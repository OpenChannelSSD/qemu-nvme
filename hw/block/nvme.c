/*
 * QEMU NVM Express Controller
 *
 * Copyright (c) 2012, Intel Corporation
 *
 * Written by Keith Busch <keith.busch@intel.com>
 *
 * This code is licensed under the GNU GPL v2 or later.
 */

/**
 * Reference Specs: http://www.nvmexpress.org, 1.1, 1.0e
 *
 *  http://www.nvmexpress.org/resources/
 */

/**
 * Usage: add options:
 *      -drive file=<file>,if=none,id=<drive_id>
 *      -device nvme,drive=<drive_id>,serial=<serial>,id=<id[optional]>
 *
 * The "file" option must point to a path to a real file that you will use as
 * the backing storage for your NVMe device. It must be a non-zero length, as
 * this will be the disk image that your nvme controller will use to carve up
 * namespaces for storage.
 *
 * Note the "drive" option's "id" name must match the "device nvme" drive's
 * name to link the block device used for backing storage to the nvme
 * interface.
 *
 * Advanced optional options:
 *
 *  namespaces=<int> : Namespaces to make out of the backing storage, Default:1
 *  queues=<int>     : Number of possible IO Queues, Default:64
 *  entries=<int>    : Maximum number of Queue entires possible, Default:0x7ff
 *  max_cqes=<int>   : Maximum completion queue entry size, Default:0x4
 *  max_sqes=<int>   : Maximum submission queue entry size, Default:0x6
 *  mpsmin=<int>     : Minimum page size supported, Default:0
 *  mpsmax=<int>     : Maximum page size supported, Default:0
 *  stride=<int>     : Doorbell stride, Default:0
 *  aerl=<int>       : Async event request limit, Default:3
 *  acl=<int>        : Abort command limit, Default:3
 *  elpe=<int>       : Error log page entries, Default:3
 *  mdts=<int>       : Maximum data transfer size, Default:5
 *  cqr=<int>        : Contiguous queues required, Default:1
 *  vwc=<int>        : Volatile write cache enabled, Default:0
 *  intc=<int>       : Interrupt configuration disabled, Default:0
 *  intc_thresh=<int>: Interrupt coalesce threshold, Default:0
 *  intc_ttime=<int> : Interrupt coalesce time 100's of usecs, Default:0
 *  nlbaf=<int>      : Number of logical block formats, Default:1
 *  lba_index=<int>  : Default namespace block format index, Default:0
 *  extended=<int>   : Use extended-lba for meta-data, Default:0
 *  dpc=<int>        : Data protection capabilities, Default:0
 *  dps=<int>        : Data protection settings, Default:0
 *  mc=<int>         : Meta-data capabilities, Default:0
 *  meta=<int>       : Meta-data size, Default:0
 *  oncs=<oncs>      : Optional NVMe command support, Default:DSM
 *  oacs=<oacs>      : Optional Admin command support, Default:Format
 *
 * The logical block formats all start at 512 byte blocks and double for the
 * next index. If meta-data is non-zero, half the logical block formats will
 * have 0 meta-data, the remaining will start the block size over at 512, but
 * with the meta-data size set accordingly. Multiple meta-data sizes are not
 * supported.
 *
 * Parameters will be verified against conflicting capabilities and attributes
 * and fail to load if there is a conflict or a configuration the emulated
 * device is unable to handle.
 *
 */

/**
 * Hot-plug support
 *
 * To hot add a new nvme device, startup the qemu monitor. The easiest way is
 * to add '-monitor stdio' option on your startup. At the monitor command line,
 * run:
 *
 * (qemu) drive_add "" if=none,id=<new_drive_id>,file=</path/to/backing/file>
 * (qemu) device_add nvme,drive=<new_drive_id>,serial=<serial>,id=<new_id>[,<optional options>]
 *
 * To hot remove the device, run:
 *
 * (qemu) device_del <id>
 *
 * You must have provided the "id" field for device_del to work. You may query
 * the available devices by running "info pci" from the qemu monitor.
 *
 * To query what disks are available to be used as a backing storage, run "info
 * block". You cannot assign the same block device to more than one storage
 * interface.
 */

#include <block/qapi.h>
#include <hw/block/block.h>
#include <hw/hw.h>
#include <hw/pci/msix.h>
#include <hw/pci/msi.h>
#include <hw/pci/pci.h>
#include <qemu/bitops.h>
#include <qemu/bitmap.h>

#include "nvme.h"

#define NVME_MAX_QS PCI_MSIX_FLAGS_QSIZE
#define NVME_MAX_QUEUE_ENTRIES  0xffff
#define NVME_MAX_STRIDE         12
#define NVME_MAX_NUM_NAMESPACES 256
#define NVME_MAX_QUEUE_ES       0xf
#define NVME_MIN_CQUEUE_ES      0x4
#define NVME_MIN_SQUEUE_ES      0x6
#define NVME_SPARE_THRESHOLD    20
#define NVME_TEMPERATURE        0x143
#define NVME_OP_ABORTED         0xff

static void nvme_process_sq(void *opaque);

static int nvme_check_sqid(NvmeCtrl *n, uint16_t sqid)
{
    return sqid < n->num_queues && n->sq[sqid] != NULL ? 0 : -1;
}

static int nvme_check_cqid(NvmeCtrl *n, uint16_t cqid)
{
    return cqid < n->num_queues && n->cq[cqid] != NULL ? 0 : -1;
}

static void nvme_inc_cq_tail(NvmeCQueue *cq)
{
    cq->tail++;
    if (cq->tail >= cq->size) {
        cq->tail = 0;
        cq->phase = !cq->phase;
    }
}

static int nvme_cqes_pending(NvmeCQueue *cq)
{
    return cq->tail > cq->head ?
        cq->head + (cq->size - cq->tail) :
        cq->head - cq->tail;
}

static void nvme_inc_sq_head(NvmeSQueue *sq)
{
    sq->head = (sq->head + 1) % sq->size;
}

static uint8_t nvme_cq_full(NvmeCQueue *cq)
{
    return (cq->tail + 1) % cq->size == cq->head;
}

static uint8_t nvme_sq_empty(NvmeSQueue *sq)
{
    return sq->head == sq->tail;
}

static void nvme_isr_notify(void *opaque)
{
    NvmeCQueue *cq = opaque;
    NvmeCtrl *n = cq->ctrl;

    if (cq->irq_enabled) {
        if (msix_enabled(&(n->parent_obj))) {
            msix_notify(&(n->parent_obj), cq->vector);
        } else if (msi_enabled(&(n->parent_obj))) {
            if (!(n->bar.intms & (1 << cq->vector))) {
                msi_notify(&(n->parent_obj), cq->vector);
            }
        } else {
            pci_irq_pulse(&n->parent_obj);
        }
    }
}

static uint64_t *nvme_setup_discontig(NvmeCtrl *n, uint64_t prp_addr,
    uint16_t queue_depth, uint16_t entry_size)
{
    int i;
    uint16_t prps_per_page = n->page_size >> 3;
    uint64_t prp[prps_per_page];
    uint16_t total_prps = DIV_ROUND_UP(queue_depth * entry_size, n->page_size);
    uint64_t *prp_list = g_malloc0(total_prps * sizeof(*prp_list));

    for (i = 0; i < total_prps; i++) {
        if (i % prps_per_page == 0 && i < total_prps - 1) {
            if (!prp_addr || prp_addr & (n->page_size - 1)) {
                g_free(prp_list);
                return NULL;
            }
            pci_dma_write(&n->parent_obj, prp_addr, (uint8_t *)&prp,
                sizeof(prp));
            prp_addr = le64_to_cpu(prp[prps_per_page - 1]);
        }
        prp_list[i] = le64_to_cpu(prp[i % prps_per_page]);
        if (!prp_list[i] || prp_list[i] & (n->page_size - 1)) {
            g_free(prp_list);
            return NULL;
        }
    }
    return prp_list;
}

static hwaddr nvme_discontig(uint64_t *dma_addr, uint16_t page_size,
    uint16_t queue_idx, uint16_t entry_size)
{
    uint16_t entries_per_page = page_size / entry_size;
    uint16_t prp_index = queue_idx / entries_per_page;
    uint16_t index_in_prp = queue_idx % entries_per_page;

    return dma_addr[prp_index] + index_in_prp * entry_size;
}

static uint16_t nvme_map_prp(QEMUSGList *qsg, uint64_t prp1, uint64_t prp2,
    uint32_t len, NvmeCtrl *n)
{
    hwaddr trans_len = n->page_size - (prp1 % n->page_size);
    trans_len = MIN(len, trans_len);
    int num_prps = (len >> n->page_bits) + 1;

    if (!prp1) {
        return NVME_INVALID_FIELD | NVME_DNR;
    }

    pci_dma_sglist_init(qsg, &n->parent_obj, num_prps);
    qemu_sglist_add(qsg, prp1, trans_len);
    len -= trans_len;
    if (len) {
        if (!prp2) {
            goto unmap;
        }
        if (len > n->page_size) {
            uint64_t prp_list[n->max_prp_ents];
            uint32_t nents, prp_trans;
            int i = 0;

            nents = (len + n->page_size - 1) >> n->page_bits;
            prp_trans = MIN(n->max_prp_ents, nents) * sizeof(uint64_t);
            pci_dma_read(&n->parent_obj, prp2, (void *)prp_list, prp_trans);
            while (len != 0) {
                uint64_t prp_ent = le64_to_cpu(prp_list[i]);

                if (i == n->max_prp_ents - 1 && len > n->page_size) {
                    if (!prp_ent || prp_ent & (n->page_size - 1)) {
                        goto unmap;
                    }

                    i = 0;
                    nents = (len + n->page_size - 1) >> n->page_bits;
                    prp_trans = MIN(n->max_prp_ents, nents) * sizeof(uint64_t);
                    pci_dma_read(&n->parent_obj, prp_ent, (void *)prp_list,
                        prp_trans);
                    prp_ent = le64_to_cpu(prp_list[i]);
                }

                if (!prp_ent || prp_ent & (n->page_size - 1)) {
                    goto unmap;
                }

                trans_len = MIN(len, n->page_size);
                qemu_sglist_add(qsg, prp_ent, trans_len);
                len -= trans_len;
                i++;
            }
        } else {
            if (prp2 & (n->page_size - 1)) {
                goto unmap;
            }
            qemu_sglist_add(qsg, prp2, len);
        }
    }
    return NVME_SUCCESS;

 unmap:
    qemu_sglist_destroy(qsg);
    return NVME_INVALID_FIELD | NVME_DNR;
}

static uint16_t nvme_dma_write_prp(NvmeCtrl *n, uint8_t *ptr, uint32_t len,
    uint64_t prp1, uint64_t prp2)
{
    QEMUSGList qsg;

    if (nvme_map_prp(&qsg, prp1, prp2, len, n)) {
        return NVME_INVALID_FIELD | NVME_DNR;
    }
    if (dma_buf_write(ptr, len, &qsg)) {
        qemu_sglist_destroy(&qsg);
        return NVME_INVALID_FIELD | NVME_DNR;
    }
    qemu_sglist_destroy(&qsg);
    return NVME_SUCCESS;
}

static uint16_t nvme_dma_read_prp(NvmeCtrl *n, uint8_t *ptr, uint32_t len,
    uint64_t prp1, uint64_t prp2)
{
    QEMUSGList qsg;

    if (nvme_map_prp(&qsg, prp1, prp2, len, n)) {
        return NVME_INVALID_FIELD | NVME_DNR;
    }
    if (dma_buf_read(ptr, len, &qsg)) {
        qemu_sglist_destroy(&qsg);
        return NVME_INVALID_FIELD | NVME_DNR;
    }
    return NVME_SUCCESS;
}

static void nvme_post_cqe(NvmeCQueue *cq, NvmeRequest *req)
{
    NvmeCtrl *n = cq->ctrl;
    NvmeSQueue *sq = req->sq;
    NvmeCqe *cqe = &req->cqe;
    hwaddr addr;
    
    if (cq->phys_contig) {
        addr = cq->dma_addr + cq->tail * n->cqe_size;
    } else {
        addr = nvme_discontig(cq->prp_list, cq->tail, n->page_size,
            n->cqe_size);
    }
    nvme_inc_cq_tail(cq);

    cqe->status = cpu_to_le16((req->status << 1) | cq->phase);
    cqe->sq_id = cpu_to_le16(sq->sqid);
    cqe->sq_head = cpu_to_le16(sq->head);
    pci_dma_write(&n->parent_obj, addr, (void *)cqe, sizeof(*cqe));

    QTAILQ_INSERT_TAIL(&sq->req_list, req, entry);
}

static void nvme_post_cqes(void *opaque)
{
    NvmeCQueue *cq = opaque;
    NvmeRequest *req, *next;

    QTAILQ_FOREACH_SAFE(req, &cq->req_list, entry, next) {
        if (nvme_cq_full(cq)) {
            break;
        }
        QTAILQ_REMOVE(&cq->req_list, req, entry);
        nvme_post_cqe(cq, req);
    }
    nvme_isr_notify(cq);
}

static void nvme_enqueue_req_completion(NvmeCQueue *cq, NvmeRequest *req)
{
    NvmeCtrl *n = cq->ctrl;
    uint64_t time_ns = NVME_INTC_TIME(n->features.int_coalescing) * 100 * 1000;
    uint8_t thresh = NVME_INTC_THR(n->features.int_coalescing) + 1;
    uint8_t coalesce_disabled =
        (n->features.int_vector_config[cq->vector] >> 16) & 1;
    uint8_t notify;

    assert(cq->cqid == req->sq->cqid);
    QTAILQ_REMOVE(&req->sq->out_req_list, req, entry);

    if (nvme_cq_full(cq) || !QTAILQ_EMPTY(&cq->req_list)) {
        QTAILQ_INSERT_TAIL(&cq->req_list, req, entry);
        return;
    }

    nvme_post_cqe(cq, req);
    notify = coalesce_disabled || !req->sq->sqid || !time_ns ||
        req->status != NVME_SUCCESS || nvme_cqes_pending(cq) >= thresh;
    if (!notify) {
        if (!timer_pending(cq->timer)) {
            timer_mod(cq->timer, qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL) +
                    time_ns);
        }
    } else {
        nvme_isr_notify(cq);
        if (timer_pending(cq->timer)) {
            timer_del(cq->timer);
        }
    }
}

static void nvme_set_error_page(NvmeCtrl *n, uint16_t sqid, uint16_t cid,
    uint16_t status, uint16_t location, uint64_t lba, uint32_t nsid)
{
    NvmeErrorLog *elp;

    elp = &n->elpes[n->elp_index];
    elp->error_count = n->error_count++;
    elp->sqid = sqid;
    elp->cid = cid;
    elp->status_field = status;
    elp->param_error_location = location;
    elp->lba = lba;
    elp->nsid = nsid;
    n->elp_index = (n->elp_index + 1) % n->elpe;
    ++n->num_errors;
}

static void nvme_enqueue_event(NvmeCtrl *n, uint8_t event_type,
    uint8_t event_info, uint8_t log_page)
{
    NvmeAsyncEvent *event = (NvmeAsyncEvent *)g_malloc(sizeof(*event));

    event->result.event_type = event_type;
    event->result.event_info = event_info;
    event->result.log_page   = log_page;
    QSIMPLEQ_INSERT_TAIL(&(n->aer_queue), event, entry);
    timer_mod(n->aer_timer, qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL) + 500);
}

static void nvme_aer_process_cb(void *param)
{
    NvmeCtrl *n = param;
    NvmeRequest *req;
    NvmeAerResult *result;
    NvmeAsyncEvent *event, *next;;

    QSIMPLEQ_FOREACH_SAFE(event, &n->aer_queue, entry, next) {
        if (n->outstanding_aers <= 0) {
            break;
        }
        if (n->aer_mask & (1 << event->result.event_type)) {
            continue;
        }

        QSIMPLEQ_REMOVE_HEAD(&n->aer_queue, entry);
        n->aer_mask |= 1 << event->result.event_type;
        n->outstanding_aers--;

        req = n->aer_reqs[n->outstanding_aers];
        result = (NvmeAerResult *)&req->cqe.result;
        result->event_type = event->result.event_type;
        result->event_info = event->result.event_info;
        result->log_page = event->result.log_page;
        g_free(event);

        req->status = NVME_SUCCESS;
        nvme_enqueue_req_completion(n->cq[0], req);
    }
}

static uint16_t nvme_sgl_verify_dif_interleave(NvmeCtrl *n, QEMUSGList *qsg,
    uint16_t ctrl, NvmeNamespace *ns, int slba)
{
    const uint8_t lba_index  = NVME_ID_NS_FLBAS_INDEX(ns->id_ns.flbas);
    const uint8_t data_shift = ns->id_ns.lbaf[lba_index].ds;
    const uint16_t ms = le16_to_cpu(ns->id_ns.lbaf[lba_index].ms);
    const uint8_t first = ns->id_ns.dps & DPS_FIRST_EIGHT;
    const uint32_t bs = 1 << data_shift;

    uint32_t i = 0, offset = 0, buf_offset = 0;
    uint32_t trans_len, dma_len = bs;
    uint8_t tmp[bs];
    uint32_t len = qsg->size;
    uint16_t meta_offset = first ? ms - 8 : 0;
    NvmeDifTuple dif;

    while (len) {
        trans_len = MIN(dma_len, qsg->sg[i].len - offset);
        trans_len = MIN(trans_len, len);

        pci_dma_read(&n->parent_obj, qsg->sg[i].base + offset,
            tmp + buf_offset, trans_len);

        len -= trans_len;
        dma_len -= trans_len;
        offset += trans_len;
        buf_offset += trans_len;

        if (dma_len == 0) {
            dma_addr_t tuple = qsg->sg[i].base + offset + meta_offset;

            pci_dma_read(&n->parent_obj, tuple, &dif, sizeof(dif));
            if (test_bit(slba, ns->util)) {
                if (ctrl & NVME_RW_PRINFO_PRCHK_GUARD) {
                    if (dif.guard_tag != cpu_to_be16(crc_t10dif(tmp, bs))) {
                        return NVME_E2E_GUARD_ERROR;
                    }
                }
                if (ctrl & NVME_RW_PRINFO_PRCHK_REF) {
                    if (slba != be32_to_cpu(dif.ref_tag)) {
                        return NVME_E2E_REF_ERROR;
                    }
                }
            } else {
                dif.guard_tag = dif.app_tag = 0xffff;
                dif.ref_tag = 0xffffffff;
                pci_dma_write(&n->parent_obj, tuple, &dif, sizeof(dif));
            }

            offset += ms;
            dma_len = bs;
            slba++;
            buf_offset = 0;
        }

        assert(offset <= qsg->sg[i].len);
        if (offset == qsg->sg[i].len) {
            offset = 0;
            i++;
        }
    }

    return NVME_SUCCESS;
}

static uint16_t nvme_sgl_verify_dif_separate(NvmeCtrl *n, QEMUSGList *qsg,
    uint8_t *buf, uint16_t ctrl, NvmeNamespace *ns, uint32_t slba,
    uint8_t first)
{
    const uint8_t lba_index  = NVME_ID_NS_FLBAS_INDEX(ns->id_ns.flbas);
    const uint8_t data_shift = ns->id_ns.lbaf[lba_index].ds;
    const uint16_t ms = le16_to_cpu(ns->id_ns.lbaf[lba_index].ms);
    const uint32_t bs = 1 << data_shift;

    uint32_t i = 0, offset = 0, buf_offset = 0;
    uint32_t trans_len, dma_len = bs;
    uint8_t tmp[bs];
    uint32_t len = qsg->size;
    uint16_t meta_offset = first ? ms - 8 : 0;
    NvmeDifTuple *dif;

    while (len) {
        trans_len = MIN(dma_len, qsg->sg[i].len - offset);
        trans_len = MIN(trans_len, len);

        pci_dma_read(&n->parent_obj, qsg->sg[i].base + offset,
            tmp + buf_offset, trans_len);

        len -= trans_len;
        dma_len -= trans_len;
        offset += trans_len;
        buf_offset += trans_len;

        if (dma_len == 0) {
            dif = (NvmeDifTuple *)(buf + meta_offset);
            if (test_bit(slba, ns->util)) {
                if (ctrl & NVME_RW_PRINFO_PRCHK_GUARD) {
                    if (dif->guard_tag != cpu_to_be16(crc_t10dif(tmp, bs))) {
                        return NVME_E2E_GUARD_ERROR;
                    }
                }
                if (ctrl & NVME_RW_PRINFO_PRCHK_REF) {
                    if (slba != be32_to_cpu(dif->ref_tag)) {
                        return NVME_E2E_REF_ERROR;
                    }
                }
            } else {
                dif->guard_tag = dif->app_tag = 0xffff;
                dif->ref_tag = 0xffffffff;
            }

            dma_len = bs;
            buf += ms;
            slba++;
            buf_offset = 0;
        }
        if (offset == qsg->sg[i].len) {
            offset = 0;
            i++;
        }
    }

    return NVME_SUCCESS;
}

static uint16_t nvme_pract_verify_dif(uint8_t *buf, const uint32_t bs,
    const uint16_t ms, uint16_t ctrl, uint32_t nlb, uint32_t slba,
    unsigned long *util, uint8_t first)
{
    NvmeDifTuple *dif;
    uint8_t *end = buf + ((bs + ms) * nlb);
    uint16_t meta_offset = first ? ms - 8 : 0;

    for (; buf < end; buf += (bs + ms)) {
        dif = (NvmeDifTuple *)(buf + meta_offset);
        if (test_bit(slba, util)) {
            if (ctrl & NVME_RW_PRINFO_PRCHK_GUARD) {
                if (dif->guard_tag != cpu_to_be16(crc_t10dif(buf, bs))) {
                    return NVME_E2E_GUARD_ERROR;
                }
            }
            if (ctrl & NVME_RW_PRINFO_PRCHK_REF) {
                if (be32_to_cpu(dif->ref_tag) != slba) {
                    return NVME_E2E_REF_ERROR;
                }
            }
            slba++;
        }
    }

    return NVME_SUCCESS;
}

static void nvme_pract_generate_dif(NvmeNamespace *ns, uint8_t *buf,
    const uint32_t bs, const uint16_t ms, uint16_t ctrl, uint32_t nlb,
    int32_t slba, uint8_t first)
{
    NvmeDifTuple *dif;
    uint8_t *end = buf + ((bs + ms) * nlb);
    uint16_t meta_offset = first ? ms - 8 : 0;

    for (; buf < end; buf += (bs + ms), slba++) {
        dif = (NvmeDifTuple *)(buf + meta_offset);
        dif->guard_tag = cpu_to_be16(crc_t10dif(buf, bs));
        dif->ref_tag = cpu_to_be32(slba);
        dif->app_tag = 0;
    }
}

static void nvme_interleave_sgl(NvmeCtrl *n, QEMUSGList *qsg, uint8_t *buf,
    uint8_t len, const uint32_t bs, const uint16_t ms, int is_write)
{
    uint32_t i = 0, sg_offset = 0;
    uint32_t trans_len, dma_len = bs;

    while (len) {
        trans_len = MIN(MIN(len, dma_len), qsg->sg[i].len - sg_offset);
        if (is_write) {
            pci_dma_read(&n->parent_obj, qsg->sg[i].base + sg_offset, buf,
                trans_len);
        } else {
            pci_dma_write(&n->parent_obj, qsg->sg[i].base + sg_offset, buf,
                trans_len);
        }

        buf += trans_len;
        len -= trans_len;
        dma_len -= trans_len;
        sg_offset += trans_len;
        if (dma_len == 0) {
            dma_len = bs;
            buf += ms;
            len -= ms;
        }
        if (sg_offset == qsg->sg[i].len) {
            sg_offset = 0;
            i++;
        }
    }
}

static void nvme_rw_cb(void *opaque, int ret)
{
    NvmeRequest *req = opaque;
    NvmeSQueue *sq = req->sq;
    NvmeCtrl *n = sq->ctrl;
    NvmeCQueue *cq = n->cq[sq->cqid];
    NvmeNamespace *ns = req->ns;

    const uint8_t pi = ns->id_ns.dps & DPS_TYPE_MASK;
    const uint8_t first = ns->id_ns.dps & DPS_FIRST_EIGHT;
    const uint8_t lba_index  = NVME_ID_NS_FLBAS_INDEX(ns->id_ns.flbas);
    const uint8_t separate = !NVME_ID_NS_FLBAS_EXTENDED(ns->id_ns.flbas);
    const uint16_t ms = le16_to_cpu(ns->id_ns.lbaf[lba_index].ms);

    bdrv_acct_done(n->conf.bs, &req->acct);
    if (!ret) {
        req->status = NVME_SUCCESS;
        if (req->meta_size) {
            if (separate) {
                if (pi) {
                    req->status = nvme_sgl_verify_dif_separate(n, &req->qsg,
                        req->meta_buf, req->ctrl, ns, req->slba, first);
                }
                pci_dma_write(&n->parent_obj, req->mptr, req->meta_buf,
                    req->meta_size);
            }
            g_free(req->meta_buf);
        }
        if (req->status == NVME_SUCCESS && ms && !separate && pi) {
            req->status = nvme_sgl_verify_dif_interleave(n, &req->qsg,
                req->ctrl, ns, req->slba);
        }
    } else {
        req->status = NVME_INTERNAL_DEV_ERROR;
    }
    if (req->status != NVME_SUCCESS) {
        nvme_set_error_page(n, sq->sqid, req->cqe.cid, req->status,
            offsetof(NvmeRwCmd, slba), req->slba, ns->id);
        if (req->is_write) {
            bitmap_clear(ns->util, req->slba, req->nlb);
        }
    }

    qemu_sglist_destroy(&req->qsg);
    nvme_enqueue_req_completion(cq, req);
}

static uint16_t nvme_rw(NvmeCtrl *n, NvmeNamespace *ns, NvmeCmd *cmd,
    NvmeRequest *req)
{
    NvmeRwCmd *rw = (NvmeRwCmd *)cmd;
    uint16_t ctrl = le16_to_cpu(rw->control);
    uint32_t nlb  = le16_to_cpu(rw->nlb) + 1;
    uint64_t slba = le64_to_cpu(rw->slba);
    uint64_t prp1 = le64_to_cpu(rw->prp1);
    uint64_t prp2 = le64_to_cpu(rw->prp2);
    uint64_t mptr = le64_to_cpu(rw->mptr);

    uint64_t offset;
    const uint64_t elba = slba + nlb;
    const uint8_t lba_index = NVME_ID_NS_FLBAS_INDEX(ns->id_ns.flbas);
    const uint8_t separate = !NVME_ID_NS_FLBAS_EXTENDED(ns->id_ns.flbas);
    const uint8_t data_shift = ns->id_ns.lbaf[lba_index].ds;
    const uint32_t bs = 1 << data_shift;
    const uint16_t ms = le16_to_cpu(ns->id_ns.lbaf[lba_index].ms);
    const uint8_t pi = ns->id_ns.dps & DPS_TYPE_MASK;
    const uint8_t first = ns->id_ns.dps & DPS_FIRST_EIGHT;
    uint64_t data_size = nlb << data_shift;
    uint64_t meta_size = nlb * ms;
    uint64_t aio_slba =
            ns->start_block + (slba << (data_shift - BDRV_SECTOR_BITS));

    req->is_write = rw->opcode == NVME_CMD_WRITE;
    if (elba > le64_to_cpu(ns->id_ns.nsze)) {
        nvme_set_error_page(n, req->sq->sqid, cmd->cid, NVME_LBA_RANGE,
            offsetof(NvmeRwCmd, nlb), elba, ns->id);
        return NVME_LBA_RANGE | NVME_DNR;
    }
    if (n->id_ctrl.mdts && data_size > n->page_size * (1 << n->id_ctrl.mdts)) {
        nvme_set_error_page(n, req->sq->sqid, cmd->cid, NVME_INVALID_FIELD,
            offsetof(NvmeRwCmd, nlb), nlb, ns->id);
        return NVME_INVALID_FIELD | NVME_DNR;
    }
    if (meta_size && !mptr && separate && !(ctrl & NVME_RW_PRINFO_PRACT)) {
        nvme_set_error_page(n, req->sq->sqid, cmd->cid, NVME_INVALID_FIELD,
            offsetof(NvmeRwCmd, control), ctrl, ns->id);
        return NVME_INVALID_FIELD | NVME_DNR;
    }
    if ((ctrl & NVME_RW_PRINFO_PRACT) && !(ns->id_ns.dps & DPS_TYPE_MASK)) {
        nvme_set_error_page(n, req->sq->sqid, cmd->cid, NVME_INVALID_FIELD,
            offsetof(NvmeRwCmd, control), ctrl, ns->id);
        return NVME_INVALID_FIELD | NVME_DNR;
    }
    if (!req->is_write && find_next_bit(ns->uncorrectable, elba, slba) < elba) {
        nvme_set_error_page(n, req->sq->sqid, cmd->cid, NVME_UNRECOVERED_READ,
            offsetof(NvmeRwCmd, slba), elba, ns->id);
        return NVME_UNRECOVERED_READ;
    }

    if (separate && meta_size && !mptr) {
        /* separate meta-buffer, controller gen/strip; do nothing */
        return NVME_INVALID_FIELD | NVME_DNR;
        meta_size = 0;
    } else if (!separate && (!(ctrl & NVME_RW_PRINFO_PRACT) ||
            ms != sizeof(NvmeDifTuple))) {
        data_size += meta_size;
        assert(data_size == (nlb * ((1 << data_shift) + ms)));
    }

    if (nvme_map_prp(&req->qsg, prp1, prp2, data_size, n)) {
        nvme_set_error_page(n, req->sq->sqid, cmd->cid, NVME_INVALID_FIELD,
            offsetof(NvmeRwCmd, prp1), 0, ns->id);
        return NVME_INVALID_FIELD | NVME_DNR;
    }
    if (!separate && (ctrl & NVME_RW_PRINFO_PRACT)) {
        data_size += meta_size;
        assert(data_size == (nlb * ((1 << data_shift) + ms)));
    }

    req->slba = slba;
    req->meta_size = 0;
    req->status = NVME_SUCCESS;
    offset = ns->meta_start_offset + (req->slba * ms);
    if (req->is_write) {
        bitmap_set(ns->util, slba, nlb);
        bitmap_clear(ns->uncorrectable, slba, nlb);
    }
    if (!separate && (!(ctrl & NVME_RW_PRINFO_PRACT) ||
            ms != sizeof(NvmeDifTuple))) {
        meta_size = req->qsg.size % BDRV_SECTOR_SIZE;
        offset = aio_slba * BDRV_SECTOR_SIZE + (req->qsg.size - meta_size);
        mptr = req->qsg.sg[req->qsg.nsg - 1].base +
            (req->qsg.sg[req->qsg.nsg - 1].len - meta_size);
    }
    if (meta_size) {
        void *buf = g_malloc(meta_size);
        if (req->is_write) {
            pci_dma_read(&n->parent_obj, mptr, buf, meta_size);
            if (separate && pi) {
                req->status = nvme_sgl_verify_dif_separate(n, &req->qsg,
                    buf, ctrl, ns, req->slba, first);
            }
            if (req->status == NVME_SUCCESS) {
                if (bdrv_pwrite_sync(n->conf.bs, offset, buf, meta_size)) {
                    req->status = NVME_INTERNAL_DEV_ERROR;
                }
            }
            free(buf);
        } else {
            if (bdrv_pread(n->conf.bs, offset, buf, meta_size) != meta_size) {
                free(buf);
                return NVME_INTERNAL_DEV_ERROR;
            }
            if (separate && pi) {
                req->mptr = mptr;
                req->meta_size = meta_size;
                req->meta_buf = buf;
                req->ctrl = ctrl;
            } else {
                pci_dma_write(&n->parent_obj, mptr, buf, meta_size);
                free(buf);
            }
        }
        if (req->status) {
            return req->status;
        }
    } else if (ctrl & NVME_RW_PRINFO_PRACT && ms == sizeof(NvmeDifTuple)) {
        /* the mete-data is interleaved; strip/insert meta-data */
        void *buf = g_malloc(data_size);
        offset = aio_slba * BDRV_SECTOR_SIZE + slba * ms;

        if (!req->is_write) {
            if (bdrv_pread(n->conf.bs, offset, buf, data_size) != data_size) {
                qemu_sglist_destroy(&req->qsg);
                g_free(buf);

                nvme_set_error_page(n, req->sq->sqid, req->cqe.cid,
                    NVME_INTERNAL_DEV_ERROR, offsetof(NvmeRwCmd, slba),
                    req->slba, ns->id);

                return NVME_INTERNAL_DEV_ERROR;
            }
            req->status = nvme_pract_verify_dif(buf, bs, ms, ctrl, nlb, slba,
                ns->util, first);
        }

        nvme_interleave_sgl(n, &req->qsg, buf, data_size, bs, ms, req->is_write);
        if (req->is_write) {
            nvme_pract_generate_dif(ns, buf, bs, ms, ctrl, nlb, slba, first);
            if (bdrv_pwrite(n->conf.bs, offset, buf, data_size) != data_size) {
                qemu_sglist_destroy(&req->qsg);
                g_free(buf);

                nvme_set_error_page(n, req->sq->sqid, req->cqe.cid,
                    NVME_INTERNAL_DEV_ERROR, offsetof(NvmeRwCmd, slba),
                    req->slba, ns->id);

                return NVME_INTERNAL_DEV_ERROR;
            }
        }

        qemu_sglist_destroy(&req->qsg);
        g_free(buf);
        return NVME_SUCCESS;
    }

    req->nlb = nlb;
    req->ns = ns;
    dma_acct_start(n->conf.bs, &req->acct, &req->qsg, req->is_write ?
        BDRV_ACCT_WRITE : BDRV_ACCT_READ);
    req->aiocb = req->is_write ?
        dma_bdrv_write(n->conf.bs, &req->qsg, aio_slba, nvme_rw_cb, req) :
        dma_bdrv_read(n->conf.bs, &req->qsg, aio_slba, nvme_rw_cb, req);

    return NVME_NO_COMPLETE;
}

static uint16_t nvme_dsm(NvmeCtrl *n, NvmeNamespace *ns, NvmeCmd *cmd,
    NvmeRequest *req)
{
    uint32_t dw10 = le32_to_cpu(cmd->cdw10);
    uint32_t dw11 = le32_to_cpu(cmd->cdw11);
    uint64_t prp1 = le64_to_cpu(cmd->prp1);
    uint64_t prp2 = le64_to_cpu(cmd->prp2);

    if (dw11 & NVME_DSMGMT_AD) {
        uint16_t nr = (dw10 & 0xff) + 1;
        uint8_t lba_index = NVME_ID_NS_FLBAS_INDEX(ns->id_ns.flbas);
        uint8_t data_shift = ns->id_ns.lbaf[lba_index].ds - BDRV_SECTOR_BITS;

        int i;
        uint64_t slba;
        uint32_t nlb;
        NvmeDsmRange range[nr];

        if (nvme_dma_write_prp(n, (uint8_t *)range, sizeof(range), prp1, prp2)) {
            nvme_set_error_page(n, req->sq->sqid, cmd->cid, NVME_INVALID_FIELD,
                offsetof(NvmeCmd, prp1), 0, ns->id);
            return NVME_INVALID_FIELD | NVME_DNR;
        }

        for (i = 0; i < nr; i++) {
            slba = le64_to_cpu(range[i].slba);
            nlb = le32_to_cpu(range[i].nlb);
            if (slba + nlb > le64_to_cpu(ns->id_ns.nsze)) {
                nvme_set_error_page(n, req->sq->sqid, cmd->cid, NVME_LBA_RANGE,
                    offsetof(NvmeCmd, cdw10), slba + nlb, ns->id);
                return NVME_LBA_RANGE | NVME_DNR;
            }

            bitmap_clear(ns->util, slba, nlb);
            if (bdrv_discard(n->conf.bs, ns->start_block + (slba << data_shift),
                    nlb << data_shift) < 0) {
                req->status = NVME_INTERNAL_DEV_ERROR;
            }
        }
    }
    return NVME_SUCCESS;
}

static uint16_t nvme_compare(NvmeCtrl *n, NvmeNamespace *ns, NvmeCmd *cmd,
    NvmeRequest *req)
{
    NvmeRwCmd *rw = (NvmeRwCmd *)cmd;
    uint32_t nlb  = le16_to_cpu(rw->nlb) + 1;
    uint64_t slba = le64_to_cpu(rw->slba);
    uint64_t prp1 = le64_to_cpu(rw->prp1);
    uint64_t prp2 = le64_to_cpu(rw->prp2);

    uint64_t elba = slba + nlb;
    uint8_t lba_index = NVME_ID_NS_FLBAS_INDEX(ns->id_ns.flbas);
    uint8_t data_shift = ns->id_ns.lbaf[lba_index].ds;
    uint64_t data_size = nlb << data_shift;
    uint64_t offset  = ns->start_block + (slba << data_shift);
    int i;

    if ((slba + nlb) > le64_to_cpu(ns->id_ns.nsze)) {
        nvme_set_error_page(n, req->sq->sqid, cmd->cid, NVME_LBA_RANGE,
            offsetof(NvmeRwCmd, nlb), elba, ns->id);
        return NVME_LBA_RANGE | NVME_DNR;
    }
    if (n->id_ctrl.mdts && data_size > n->page_size * (1 << n->id_ctrl.mdts)) {
        nvme_set_error_page(n, req->sq->sqid, cmd->cid, NVME_INVALID_FIELD,
            offsetof(NvmeRwCmd, nlb), nlb, ns->id);
        return NVME_INVALID_FIELD | NVME_DNR;
    }
    if (nvme_map_prp(&req->qsg, prp1, prp2, data_size, n)) {
        nvme_set_error_page(n, req->sq->sqid, cmd->cid, NVME_INVALID_FIELD,
            offsetof(NvmeRwCmd, prp1), 0, ns->id);
        return NVME_INVALID_FIELD | NVME_DNR;
    }
    if (find_next_bit(ns->uncorrectable, elba, slba) < elba) {
        return NVME_UNRECOVERED_READ;
    }

    for (i = 0; i < req->qsg.nsg; i++) {
        uint32_t len = req->qsg.sg[i].len;
        uint8_t tmp[2][len];

        if (bdrv_pread(n->conf.bs, offset, tmp[0], len) != len) {
            qemu_sglist_destroy(&req->qsg);
            nvme_set_error_page(n, req->sq->sqid, req->cqe.cid,
                NVME_INTERNAL_DEV_ERROR, offsetof(NvmeRwCmd, slba),
                req->slba, ns->id);
            return NVME_INTERNAL_DEV_ERROR;
        }

        pci_dma_read(&n->parent_obj, req->qsg.sg[i].base, tmp[1], len);
        if (memcmp(tmp[0], tmp[1], len)) {
            qemu_sglist_destroy(&req->qsg);
            return NVME_CMP_FAILURE;
        }

        offset += len;
    }

    qemu_sglist_destroy(&req->qsg);
    return NVME_SUCCESS;
}

static void nvme_flush_cb(void *opaque, int ret)
{
    NvmeRequest *req = opaque;
    NvmeSQueue *sq = req->sq;
    NvmeCtrl *n = sq->ctrl;
    NvmeCQueue *cq = n->cq[sq->cqid];

    bdrv_acct_done(n->conf.bs, &req->acct);
    if (!ret) {
        req->status = NVME_SUCCESS;
    } else {
        req->status = NVME_INTERNAL_DEV_ERROR;
    }
    nvme_enqueue_req_completion(cq, req);
}

static uint16_t nvme_flush(NvmeCtrl *n, NvmeNamespace *ns, NvmeCmd *cmd,
    NvmeRequest *req)
{
    bdrv_acct_start(n->conf.bs, &req->acct, 0, BDRV_ACCT_FLUSH);
    req->aiocb = bdrv_aio_flush(n->conf.bs, nvme_flush_cb, req);
    return NVME_NO_COMPLETE;
}

static uint16_t nvme_write_uncor(NvmeCtrl *n, NvmeNamespace *ns, NvmeCmd *cmd,
    NvmeRequest *req)
{
    NvmeRwCmd *rw = (NvmeRwCmd *)cmd;
    uint64_t slba = le64_to_cpu(rw->slba);
    uint32_t nlb  = le16_to_cpu(rw->nlb) + 1;

    if ((slba + nlb) > ns->id_ns.nsze) {
        nvme_set_error_page(n, req->sq->sqid, cmd->cid, NVME_LBA_RANGE,
            offsetof(NvmeRwCmd, nlb), slba + nlb, ns->id);
        return NVME_LBA_RANGE | NVME_DNR;
    }

    bitmap_set(ns->uncorrectable, slba, nlb);
    return NVME_SUCCESS;
}

static uint16_t nvme_io_cmd(NvmeCtrl *n, NvmeCmd *cmd, NvmeRequest *req)
{
    NvmeNamespace *ns;
    uint32_t nsid = le32_to_cpu(cmd->nsid);

    if (nsid == 0 || nsid > n->num_namespaces) {
        return NVME_INVALID_NSID | NVME_DNR;
    }

    ns = &n->namespaces[nsid - 1];
    switch (cmd->opcode) {
    case NVME_CMD_WRITE:
    case NVME_CMD_READ:
        return nvme_rw(n, ns, cmd, req);

    case NVME_CMD_FLUSH:
        if (!n->id_ctrl.vwc || !n->features.volatile_wc) {
            return NVME_SUCCESS;
        }
        return nvme_flush(n, ns, cmd, req);

    case NVME_CMD_DSM:
        if (NVME_ONCS_DSM & n->oncs) {
            return nvme_dsm(n, ns, cmd, req);
        }
        return NVME_INVALID_OPCODE | NVME_DNR;

    case NVME_CMD_COMPARE:
        if (NVME_ONCS_COMPARE & n->oncs) {
            return nvme_compare(n, ns, cmd, req);
        }
        return NVME_INVALID_OPCODE | NVME_DNR;

    case NVME_CMD_WRITE_UNCOR:
        if (NVME_ONCS_WRITE_UNCORR & n->oncs) {
            return nvme_write_uncor(n, ns, cmd, req);
        }
        return NVME_INVALID_OPCODE | NVME_DNR;

    default:
        return NVME_INVALID_OPCODE | NVME_DNR;
    }
}

static void nvme_free_sq(NvmeSQueue *sq, NvmeCtrl *n)
{
    n->sq[sq->sqid] = NULL;
    timer_del(sq->timer);
    timer_free(sq->timer);
    g_free(sq->io_req);
    if (sq->prp_list) {
        g_free(sq->prp_list);
    }
    if (sq->sqid) {
        g_free(sq);
    }
}

static uint16_t nvme_del_sq(NvmeCtrl *n, NvmeCmd *cmd)
{
    NvmeDeleteQ *c = (NvmeDeleteQ *)cmd;
    NvmeRequest *req, *next;
    NvmeSQueue *sq;
    NvmeCQueue *cq;
    uint16_t qid = le16_to_cpu(c->qid);

    if (!qid || nvme_check_sqid(n, qid)) {
        return NVME_INVALID_QID | NVME_DNR;
    }

    sq = n->sq[qid];
    QTAILQ_FOREACH_SAFE(req, &sq->out_req_list, entry, next) {
        if (req->aiocb) {
            bdrv_aio_cancel(req->aiocb);
        }
    }
    if (!nvme_check_cqid(n, sq->cqid)) {
        cq = n->cq[sq->cqid];
        QTAILQ_REMOVE(&cq->sq_list, sq, entry);

        nvme_post_cqes(cq);
        QTAILQ_FOREACH_SAFE(req, &cq->req_list, entry, next) {
            if (req->sq == sq) {
                QTAILQ_REMOVE(&cq->req_list, req, entry);
                QTAILQ_INSERT_TAIL(&sq->req_list, req, entry);
            }
        }
    }

    nvme_free_sq(sq, n);
    return NVME_SUCCESS;
}

static uint16_t nvme_init_sq(NvmeSQueue *sq, NvmeCtrl *n, uint64_t dma_addr,
    uint16_t sqid, uint16_t cqid, uint16_t size, enum NvmeQueueFlags prio,
    int contig)
{
    int i;
    NvmeCQueue *cq;

    sq->ctrl = n;
    sq->sqid = sqid;
    sq->size = size;
    sq->cqid = cqid;
    sq->head = sq->tail = 0;
    sq->phys_contig = contig;
    if (sq->phys_contig) {
        sq->dma_addr = dma_addr;
    } else {
        sq->prp_list = nvme_setup_discontig(n, dma_addr, size, n->sqe_size);
        if (!sq->prp_list) {
            return NVME_INVALID_FIELD | NVME_DNR;
        }
    }

    sq->io_req = g_malloc(sq->size * sizeof(*sq->io_req));
    QTAILQ_INIT(&sq->req_list);
    QTAILQ_INIT(&sq->out_req_list);
    for (i = 0; i < sq->size; i++) {
        sq->io_req[i].sq = sq;
        QTAILQ_INSERT_TAIL(&(sq->req_list), &sq->io_req[i], entry);
    }

    switch (prio) {
    case NVME_Q_PRIO_URGENT:
        sq->arb_burst = (1 << NVME_ARB_AB(n->features.arbitration));
        break;
    case NVME_Q_PRIO_HIGH:
        sq->arb_burst = NVME_ARB_HPW(n->features.arbitration) + 1;
        break;
    case NVME_Q_PRIO_NORMAL:
        sq->arb_burst = NVME_ARB_MPW(n->features.arbitration) + 1;
        break;
    case NVME_Q_PRIO_LOW:
    default:
        sq->arb_burst = NVME_ARB_LPW(n->features.arbitration) + 1;
        break;
    }
    sq->timer = timer_new_ns(QEMU_CLOCK_VIRTUAL, nvme_process_sq, sq);

    assert(n->cq[cqid]);
    cq = n->cq[cqid];
    QTAILQ_INSERT_TAIL(&(cq->sq_list), sq, entry);
    n->sq[sqid] = sq;

    return NVME_SUCCESS;
}

static uint16_t nvme_create_sq(NvmeCtrl *n, NvmeCmd *cmd)
{
    NvmeSQueue *sq;
    NvmeCreateSq *c = (NvmeCreateSq *)cmd;

    uint16_t cqid = le16_to_cpu(c->cqid);
    uint16_t sqid = le16_to_cpu(c->sqid);
    uint16_t qsize = le16_to_cpu(c->qsize);
    uint16_t qflags = le16_to_cpu(c->sq_flags);
    uint64_t prp1 = le64_to_cpu(c->prp1);

    if (!cqid || nvme_check_cqid(n, cqid)) {
        return NVME_INVALID_CQID | NVME_DNR;
    }
    if (!sqid || (sqid && !nvme_check_sqid(n, sqid))) {
        return NVME_INVALID_QID | NVME_DNR;
    }
    if (!qsize || qsize > NVME_CAP_MQES(n->bar.cap)) {
        return NVME_MAX_QSIZE_EXCEEDED | NVME_DNR;
    }
    if (!prp1 || prp1 & (n->page_size - 1)) {
        return NVME_INVALID_FIELD | NVME_DNR;
    }
    if (!(NVME_SQ_FLAGS_PC(qflags)) && NVME_CAP_CQR(n->bar.cap)) {
        return NVME_INVALID_FIELD | NVME_DNR;
    }

    sq = g_malloc0(sizeof(*sq));
    if (nvme_init_sq(sq, n, prp1, sqid, cqid, qsize + 1,
            NVME_SQ_FLAGS_QPRIO(qflags),
            NVME_SQ_FLAGS_PC(qflags))) {
        g_free(sq);
        return NVME_INVALID_FIELD | NVME_DNR;
    }

    return NVME_SUCCESS;
}

static void nvme_free_cq(NvmeCQueue *cq, NvmeCtrl *n)
{
    n->cq[cq->cqid] = NULL;
    timer_del(cq->timer);
    timer_free(cq->timer);
    msix_vector_unuse(&n->parent_obj, cq->vector);
    if (cq->prp_list) {
        g_free(cq->prp_list);
    }
    if (cq->cqid) {
        g_free(cq);
    }
}

static uint16_t nvme_del_cq(NvmeCtrl *n, NvmeCmd *cmd)
{
    NvmeDeleteQ *c = (NvmeDeleteQ *)cmd;
    NvmeCQueue *cq;
    uint16_t qid = le16_to_cpu(c->qid);

    if (!qid || nvme_check_cqid(n, qid)) {
        return NVME_INVALID_CQID | NVME_DNR;
    }

    cq = n->cq[qid];
    if (!QTAILQ_EMPTY(&cq->sq_list)) {
        return NVME_INVALID_QUEUE_DEL;
    }
    nvme_free_cq(cq, n);
    return NVME_SUCCESS;
}

static uint16_t nvme_init_cq(NvmeCQueue *cq, NvmeCtrl *n, uint64_t dma_addr,
    uint16_t cqid, uint16_t vector, uint16_t size, uint16_t irq_enabled,
    int contig)
{
    cq->ctrl = n;
    cq->cqid = cqid;
    cq->size = size;
    cq->phase = 1;
    cq->irq_enabled = irq_enabled;
    cq->vector = vector;
    cq->head = cq->tail = 0;
    cq->phys_contig = contig;
    if (cq->phys_contig) {
        cq->dma_addr = dma_addr;
    } else {
        cq->prp_list = nvme_setup_discontig(n, dma_addr, size,
            n->cqe_size);
        if (!cq->prp_list) {
            return NVME_INVALID_FIELD | NVME_DNR;
        }
    }

    QTAILQ_INIT(&cq->req_list);
    QTAILQ_INIT(&cq->sq_list);
    msix_vector_use(&n->parent_obj, cq->vector);
    n->cq[cqid] = cq;
    cq->timer = timer_new_ns(QEMU_CLOCK_VIRTUAL, nvme_isr_notify, cq);

    return NVME_SUCCESS;
}

static uint16_t nvme_create_cq(NvmeCtrl *n, NvmeCmd *cmd)
{
    NvmeCQueue *cq;
    NvmeCreateCq *c = (NvmeCreateCq *)cmd;
    uint16_t cqid = le16_to_cpu(c->cqid);
    uint16_t vector = le16_to_cpu(c->irq_vector);
    uint16_t qsize = le16_to_cpu(c->qsize);
    uint16_t qflags = le16_to_cpu(c->cq_flags);
    uint64_t prp1 = le64_to_cpu(c->prp1);

    if (!cqid || (cqid && !nvme_check_cqid(n, cqid))) {
        return NVME_INVALID_CQID | NVME_DNR;
    }
    if (!qsize || qsize > NVME_CAP_MQES(n->bar.cap)) {
        return NVME_MAX_QSIZE_EXCEEDED | NVME_DNR;
    }
    if (!prp1) {
        return NVME_INVALID_FIELD | NVME_DNR;
    }
    if (vector > n->num_queues) {
        return NVME_INVALID_IRQ_VECTOR | NVME_DNR;
    }
    if (!(NVME_CQ_FLAGS_PC(qflags)) && NVME_CAP_CQR(n->bar.cap)) {
        return NVME_INVALID_FIELD | NVME_DNR;
    }

    cq = g_malloc0(sizeof(*cq));
    if (nvme_init_cq(cq, n, prp1, cqid, vector, qsize + 1,
            NVME_CQ_FLAGS_IEN(qflags), NVME_CQ_FLAGS_PC(qflags))) {
        g_free(cq);
        return NVME_INVALID_FIELD | NVME_DNR;
    }
    return NVME_SUCCESS;
}

static uint16_t nvme_identify(NvmeCtrl *n, NvmeCmd *cmd)
{
    NvmeNamespace *ns;
    NvmeIdentify *c = (NvmeIdentify *)cmd;
    uint32_t cns  = le32_to_cpu(c->cns);
    uint32_t nsid = le32_to_cpu(c->nsid);
    uint64_t prp1 = le64_to_cpu(c->prp1);
    uint64_t prp2 = le64_to_cpu(c->prp2);

    if (cns) {
        return nvme_dma_read_prp(n, (uint8_t *)&n->id_ctrl, sizeof(n->id_ctrl),
            prp1, prp2);
    }
    if (nsid == 0 || nsid > n->num_namespaces) {
        return NVME_INVALID_NSID | NVME_DNR;
    }

    ns = &n->namespaces[nsid - 1];
    return nvme_dma_read_prp(n, (uint8_t *)&ns->id_ns, sizeof(ns->id_ns),
        prp1, prp2);
}

static uint16_t nvme_get_feature(NvmeCtrl *n, NvmeCmd *cmd, NvmeRequest *req)
{
    NvmeRangeType *rt;
    uint32_t dw10 = le32_to_cpu(cmd->cdw10);
    uint32_t dw11 = le32_to_cpu(cmd->cdw11);
    uint32_t nsid = le32_to_cpu(cmd->nsid);
    uint64_t prp1 = le64_to_cpu(cmd->prp1);
    uint64_t prp2 = le64_to_cpu(cmd->prp2);

    switch (dw10) {
    case NVME_ARBITRATION:
        req->cqe.result = cpu_to_le32(n->features.arbitration);
        break;
    case NVME_POWER_MANAGEMENT:
        req->cqe.result = cpu_to_le32(n->features.power_mgmt);
        break;
    case NVME_LBA_RANGE_TYPE:
        if (nsid == 0 || nsid > n->num_namespaces) {
            return NVME_INVALID_NSID | NVME_DNR;
        }
        rt = n->namespaces[nsid - 1].lba_range;
        return nvme_dma_read_prp(n, (uint8_t *)rt,
            MIN(sizeof(*rt), (dw11 & 0x3f) * sizeof(*rt)),
            prp1, prp2);
    case NVME_NUMBER_OF_QUEUES:
        req->cqe.result = cpu_to_le32(n->num_queues | (n->num_queues << 16));
        break;
    case NVME_TEMPERATURE_THRESHOLD:
        req->cqe.result = cpu_to_le32(n->features.temp_thresh);
        break;
    case NVME_ERROR_RECOVERY:
        req->cqe.result = cpu_to_le32(n->features.err_rec);
        break;
    case NVME_VOLATILE_WRITE_CACHE:
        req->cqe.result = cpu_to_le32(n->features.volatile_wc);
        break;
    case NVME_INTERRUPT_COALESCING:
        req->cqe.result = cpu_to_le32(n->features.int_coalescing);
        break;
    case NVME_INTERRUPT_VECTOR_CONF:
        if ((dw11 & 0xffff) > n->num_queues) {
            return NVME_INVALID_FIELD | NVME_DNR;
        }
        req->cqe.result = cpu_to_le32(
            n->features.int_vector_config[dw11 & 0xffff]);
        break;
    case NVME_WRITE_ATOMICITY:
        req->cqe.result = cpu_to_le32(n->features.write_atomicity);
        break;
    case NVME_ASYNCHRONOUS_EVENT_CONF:
        req->cqe.result = cpu_to_le32(n->features.async_config);
        break;
    case NVME_SOFTWARE_PROGRESS_MARKER:
        req->cqe.result = cpu_to_le32(n->features.sw_prog_marker);
        break;
    default:
        return NVME_INVALID_FIELD | NVME_DNR;
    }
    return NVME_SUCCESS;
}

static uint16_t nvme_set_feature(NvmeCtrl *n, NvmeCmd *cmd, NvmeRequest *req)
{
    NvmeRangeType *rt;
    uint32_t dw10 = le32_to_cpu(cmd->cdw10);
    uint32_t dw11 = le32_to_cpu(cmd->cdw11);
    uint32_t nsid = le32_to_cpu(cmd->nsid);
    uint64_t prp1 = le64_to_cpu(cmd->prp1);
    uint64_t prp2 = le64_to_cpu(cmd->prp2);

    switch (dw10) {
    case NVME_ARBITRATION:
        req->cqe.result = cpu_to_le32(n->features.arbitration);
        break;
    case NVME_POWER_MANAGEMENT:
        n->features.power_mgmt = dw11;
        break;
    case NVME_LBA_RANGE_TYPE:
        if (nsid == 0 || nsid > n->num_namespaces) {
            return NVME_INVALID_NSID | NVME_DNR;
        }
        rt = n->namespaces[nsid - 1].lba_range;
        return nvme_dma_write_prp(n, (uint8_t *)rt,
            MIN(sizeof(*rt), (dw11 & 0x3f) * sizeof(*rt)),
            prp1, prp2);
    case NVME_NUMBER_OF_QUEUES:
        req->cqe.result = cpu_to_le32(n->num_queues | (n->num_queues << 16));
        break;
    case NVME_TEMPERATURE_THRESHOLD:
        n->features.temp_thresh = dw11;
        if (n->features.temp_thresh <= n->temperature && !n->temp_warn_issued) {
            n->temp_warn_issued = 1;
            nvme_enqueue_event(n, NVME_AER_TYPE_SMART,
                    NVME_AER_INFO_SMART_TEMP_THRESH,
                    NVME_LOG_SMART_INFO);
        } else if (n->features.temp_thresh > n->temperature &&
                !(n->aer_mask & 1 << NVME_AER_TYPE_SMART)) {
            n->temp_warn_issued = 0;
        }
        break;
    case NVME_ERROR_RECOVERY:
        n->features.err_rec = dw11;
        break;
    case NVME_VOLATILE_WRITE_CACHE:
        n->features.volatile_wc = dw11;
        break;
    case NVME_INTERRUPT_COALESCING:
        n->features.int_coalescing = dw11;
        break;
    case NVME_INTERRUPT_VECTOR_CONF:
        if ((dw11 & 0xffff) > n->num_queues) {
            return NVME_INVALID_FIELD | NVME_DNR;
        }
        n->features.int_vector_config[dw11 & 0xffff] = dw11 & 0x1ffff;
        break;
    case NVME_WRITE_ATOMICITY:
        n->features.write_atomicity = dw11;
        break;
    case NVME_ASYNCHRONOUS_EVENT_CONF:
        n->features.async_config = dw11;
        break;
    case NVME_SOFTWARE_PROGRESS_MARKER:
        n->features.sw_prog_marker = dw11;
        break;
    default:
        return NVME_INVALID_FIELD | NVME_DNR;
    }
    return NVME_SUCCESS;
}

static uint16_t nvme_fw_log_info(NvmeCtrl *n, NvmeCmd *cmd, uint32_t buf_len)
{
    uint32_t trans_len;
    uint64_t prp1 = le64_to_cpu(cmd->prp1);
    uint64_t prp2 = le64_to_cpu(cmd->prp2);
    NvmeFwSlotInfoLog fw_log;

    trans_len = MIN(sizeof(fw_log), buf_len);
    return nvme_dma_read_prp(n, (uint8_t *)&fw_log, trans_len, prp1, prp2);
}

static uint16_t nvme_error_log_info(NvmeCtrl *n, NvmeCmd *cmd, uint32_t buf_len)
{
    uint32_t trans_len;
    uint64_t prp1 = le64_to_cpu(cmd->prp1);
    uint64_t prp2 = le64_to_cpu(cmd->prp2);

    trans_len = MIN(sizeof(*n->elpes) * n->elpe, buf_len);
    n->aer_mask &= ~(1 << NVME_AER_TYPE_ERROR);
    if (!QSIMPLEQ_EMPTY(&n->aer_queue)) {
        timer_mod(n->aer_timer, qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL) + 10000);
    }
    return nvme_dma_read_prp(n, (uint8_t *)n->elpes, trans_len, prp1, prp2);
}

static uint16_t nvme_smart_info(NvmeCtrl *n, NvmeCmd *cmd, uint32_t buf_len)
{
    uint64_t prp1 = le64_to_cpu(cmd->prp1);
    uint64_t prp2 = le64_to_cpu(cmd->prp2);

    uint32_t trans_len;
    time_t current_seconds;
    NvmeSmartLog smart;
    BlockStats *s = bdrv_query_stats(n->conf.bs);

    trans_len = MIN(sizeof(smart), buf_len);
    memset(&smart, 0x0, sizeof(smart));
    smart.data_units_read[0] = cpu_to_le64(s->stats->rd_bytes);
    smart.data_units_written[0] = cpu_to_le64(s->stats->wr_bytes);
    smart.host_read_commands[0] = cpu_to_le64(s->stats->rd_operations);
    smart.host_write_commands[0] = cpu_to_le64(s->stats->wr_operations);

    g_free(s);
    smart.number_of_error_log_entries[0] = cpu_to_le64(n->num_errors);
    smart.temperature[0] = n->temperature & 0xff;
    smart.temperature[1] = (n->temperature >> 8) & 0xff;

    current_seconds = time(NULL);
    smart.power_on_hours[0] = cpu_to_le64(
        ((current_seconds - n->start_time) / 60) / 60);

    smart.available_spare_threshold = NVME_SPARE_THRESHOLD;
    if (smart.available_spare <= NVME_SPARE_THRESHOLD) {
        smart.critical_warning |= NVME_SMART_SPARE;
    }
    if (n->features.temp_thresh <= n->temperature) {
        smart.critical_warning |= NVME_SMART_TEMPERATURE;
    }

    n->aer_mask &= ~(1 << NVME_AER_TYPE_SMART);
    if (!QSIMPLEQ_EMPTY(&n->aer_queue)) {
        timer_mod(n->aer_timer, qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL) + 500);
    }

    return nvme_dma_read_prp(n, (uint8_t *)&smart, trans_len, prp1, prp2);
}

static uint16_t nvme_get_log(NvmeCtrl *n, NvmeCmd *cmd)
{
    uint32_t dw10 = le32_to_cpu(cmd->cdw10);
    uint16_t lid = dw10 & 0xffff;
    uint32_t len = ((dw10 >> 16) & 0xff) << 2;

    switch (lid) {
    case NVME_LOG_ERROR_INFO:
        return nvme_error_log_info(n, cmd, len);
    case NVME_LOG_SMART_INFO:
        return nvme_smart_info(n, cmd, len);
    case NVME_LOG_FW_SLOT_INFO:
        return nvme_fw_log_info(n, cmd, len);
    default:
        return NVME_INVALID_LOG_ID | NVME_DNR;
    }
}

static uint16_t nvme_async_req(NvmeCtrl *n, NvmeCmd *cmd, NvmeRequest *req)
{
    if (n->outstanding_aers > n->aerl + 1) {
        return NVME_AER_LIMIT_EXCEEDED;
    }
    n->aer_reqs[n->outstanding_aers] = req;
    timer_mod(n->aer_timer, qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL) + 500);
    n->outstanding_aers++;
    return NVME_NO_COMPLETE;
}

static uint16_t nvme_abort_req(NvmeCtrl *n, NvmeCmd *cmd, uint32_t *result)
{
    uint32_t index = 0;
    uint16_t sqid = cmd->cdw10 & 0xffff;
    uint16_t cid = (cmd->cdw10 >> 16) & 0xffff;
    NvmeSQueue *sq;
    NvmeRequest *req, *next;

    *result = 1;
    if (nvme_check_sqid(n, sqid)) {
        return NVME_SUCCESS;
    }

    sq = n->sq[sqid];
    QTAILQ_FOREACH_SAFE(req, &sq->out_req_list, entry, next) {
        if (sq->sqid) {
            if (req->aiocb && req->cqe.cid == cid) {
                bdrv_aio_cancel(req->aiocb);
                *result = 0;
                return NVME_SUCCESS;
            }
        }
    }

    while ((sq->head + index) % sq->size != sq->tail) {
        NvmeCmd abort_cmd;
        hwaddr addr;

        if (sq->phys_contig) {
            addr = sq->dma_addr + ((sq->head + index) % sq->size) *
                n->sqe_size;
        } else {
            addr = nvme_discontig(sq->prp_list, (sq->head + index) % sq->size,
                n->page_size, n->sqe_size);
        }

        pci_dma_read(&n->parent_obj, addr, (void *)&abort_cmd,
            sizeof(abort_cmd));
        if (abort_cmd.cid == cid) {
            *result = 0;
            req = QTAILQ_FIRST(&sq->req_list);
            QTAILQ_REMOVE(&sq->req_list, req, entry);
            QTAILQ_INSERT_TAIL(&sq->out_req_list, req, entry);

            memset(&req->cqe, 0, sizeof(req->cqe));
            req->cqe.cid = cid;
            req->status = NVME_CMD_ABORT_REQ;

            abort_cmd.opcode = NVME_OP_ABORTED;
            pci_dma_write(&n->parent_obj, addr, (void *)&abort_cmd,
                sizeof(abort_cmd));

            nvme_enqueue_req_completion(n->cq[sq->cqid], req);
            return NVME_SUCCESS;
        }

        ++index;
    }
    return NVME_SUCCESS;
}

static uint16_t nvme_format_namespace(NvmeNamespace *ns, uint8_t lba_idx,
    uint8_t meta_loc, uint8_t pil, uint8_t pi, uint8_t sec_erase)
{
    uint64_t blks;
    uint16_t ms = le16_to_cpu(ns->id_ns.lbaf[lba_idx].ms);

    if (lba_idx > ns->id_ns.nlbaf) {
        return NVME_INVALID_FORMAT | NVME_DNR;
    }
    if (pi) {
        if (pil && !NVME_ID_NS_DPC_LAST_EIGHT(ns->id_ns.dpc)) {
            return NVME_INVALID_FORMAT | NVME_DNR;
        }
        if (!pil && !NVME_ID_NS_DPC_FIRST_EIGHT(ns->id_ns.dpc)) {
            return NVME_INVALID_FORMAT | NVME_DNR;
        }
        if (!((ns->id_ns.dpc & 0x7) & (1 << (pi - 1)))) {
            return NVME_INVALID_FORMAT | NVME_DNR;
        }
    }
    if (meta_loc && ms && !NVME_ID_NS_MC_EXTENDED(ns->id_ns.mc)) {
        return NVME_INVALID_FORMAT | NVME_DNR;
    }
    if (!meta_loc && ms && !NVME_ID_NS_MC_SEPARATE(ns->id_ns.mc)) {
        return NVME_INVALID_FORMAT | NVME_DNR;
    }

    g_free(ns->util);
    g_free(ns->uncorrectable);
    blks = ns->ctrl->ns_size / ((1 << ns->id_ns.lbaf[lba_idx].ds) +
                ns->ctrl->meta);
    ns->id_ns.flbas = lba_idx | meta_loc;
    ns->id_ns.nsze = cpu_to_le64(blks);
    ns->id_ns.ncap = ns->id_ns.nsze;
    ns->id_ns.nuse = ns->id_ns.nsze;
    ns->id_ns.dps = pil | pi;
    ns->util = bitmap_new(blks);
    ns->uncorrectable = bitmap_new(blks);

    if (sec_erase) {
        /* TODO: write zeros, complete asynchronously */;
    }

    return NVME_SUCCESS;
}

static uint16_t nvme_format(NvmeCtrl *n, NvmeCmd *cmd)
{
    NvmeNamespace *ns;
    uint32_t dw10 = le32_to_cpu(cmd->cdw10);
    uint32_t nsid = le32_to_cpu(cmd->nsid);

    uint8_t lba_idx = dw10 & 0xf;
    uint8_t meta_loc = dw10 & 0x10;
    uint8_t pil = (dw10 >> 5) & 0x8;
    uint8_t pi = (dw10 >> 5) & 0x7;
    uint8_t sec_erase = (dw10 >> 8) & 0x7;

    if (nsid == 0xffffffff) {
        uint32_t i;
        uint16_t ret = NVME_SUCCESS;

        for (i = 0; i < n->num_namespaces; ++i) {
            ns = &n->namespaces[i];
            ret = nvme_format_namespace(ns, lba_idx, meta_loc, pil, pi,
                sec_erase);
            if (ret != NVME_SUCCESS) {
                return ret;
            }
        }
        return ret;
    }

    if (nsid == 0 || nsid > n->num_namespaces) {
        return NVME_INVALID_NSID | NVME_DNR;
    }

    ns = &n->namespaces[nsid - 1];
    return nvme_format_namespace(ns, lba_idx, meta_loc, pil, pi,
        sec_erase);
}

static uint16_t nvme_admin_cmd(NvmeCtrl *n, NvmeCmd *cmd, NvmeRequest *req)
{
    switch (cmd->opcode) {
    case NVME_ADM_CMD_DELETE_SQ:
        return nvme_del_sq(n, cmd);
    case NVME_ADM_CMD_CREATE_SQ:
        return nvme_create_sq(n, cmd);
    case NVME_ADM_CMD_DELETE_CQ:
        return nvme_del_cq(n, cmd);
    case NVME_ADM_CMD_CREATE_CQ:
        return nvme_create_cq(n, cmd);
    case NVME_ADM_CMD_IDENTIFY:
        return nvme_identify(n, cmd);
    case NVME_ADM_CMD_SET_FEATURES:
        return nvme_set_feature(n, cmd, req);
    case NVME_ADM_CMD_GET_FEATURES:
        return nvme_get_feature(n, cmd, req);
    case NVME_ADM_CMD_GET_LOG_PAGE:
        return nvme_get_log(n, cmd);
    case NVME_ADM_CMD_ASYNC_EV_REQ:
        return nvme_async_req(n, cmd, req);
    case NVME_ADM_CMD_ABORT:
        return nvme_abort_req(n, cmd, &req->cqe.result);
    case NVME_ADM_CMD_FORMAT_NVM:
        if (NVME_OACS_FORMAT & n->oacs) {
            return nvme_format(n, cmd);
        }
        return NVME_INVALID_OPCODE | NVME_DNR;
    case NVME_ADM_CMD_ACTIVATE_FW:
    case NVME_ADM_CMD_DOWNLOAD_FW:
    case NVME_ADM_CMD_SECURITY_SEND:
    case NVME_ADM_CMD_SECURITY_RECV:
    default:
        return NVME_INVALID_OPCODE | NVME_DNR;
    }
}

static void nvme_process_sq(void *opaque)
{
    NvmeSQueue *sq = opaque;
    NvmeCtrl *n = sq->ctrl;
    NvmeCQueue *cq = n->cq[sq->cqid];

    uint16_t status;
    hwaddr addr;
    NvmeCmd cmd;
    NvmeRequest *req;
    int processed = 0;

    while (!(nvme_sq_empty(sq) || QTAILQ_EMPTY(&sq->req_list)) &&
            processed++ < sq->arb_burst) {
        if (sq->phys_contig) {
            addr = sq->dma_addr + sq->head * n->sqe_size;
        } else {
            addr = nvme_discontig(sq->prp_list, sq->head, n->page_size,
                n->sqe_size);
        }

        pci_dma_read(&n->parent_obj, addr, (void *)&cmd, sizeof(cmd));
        nvme_inc_sq_head(sq);
        if (cmd.opcode == NVME_OP_ABORTED) {
            continue;
        }

        req = QTAILQ_FIRST(&sq->req_list);
        QTAILQ_REMOVE(&sq->req_list, req, entry);
        QTAILQ_INSERT_TAIL(&sq->out_req_list, req, entry);
        memset(&req->cqe, 0, sizeof(req->cqe));
        req->cqe.cid = cmd.cid;
        req->aiocb = NULL;

        status = sq->sqid ? nvme_io_cmd(n, &cmd, req) :
            nvme_admin_cmd(n, &cmd, req);
        if (status != NVME_NO_COMPLETE) {
            req->status = status;
            nvme_enqueue_req_completion(cq, req);
        }
    }

    sq->completed += processed;
    if (!nvme_sq_empty(sq)) {
        timer_mod(sq->timer, qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL) + 500);
    }
}

static void nvme_clear_ctrl(NvmeCtrl *n)
{
    NvmeAsyncEvent *event;
    int i;

    for (i = 0; i < n->num_queues; i++) {
        if (n->sq[i] != NULL) {
            nvme_free_sq(n->sq[i], n);
        }
    }
    for (i = 0; i < n->num_queues; i++) {
        if (n->cq[i] != NULL) {
            nvme_free_cq(n->cq[i], n);
        }
    }
    if (n->aer_timer) {
        timer_del(n->aer_timer);
        timer_free(n->aer_timer);
        n->aer_timer = NULL;
    }
    while ((event = QSIMPLEQ_FIRST(&n->aer_queue)) != NULL) {
        QSIMPLEQ_REMOVE_HEAD(&n->aer_queue, entry);
        g_free(event);
    }

    bdrv_flush(n->conf.bs);
    n->bar.cc = 0;
    n->features.temp_thresh = 0x14d;
    n->temp_warn_issued = 0;
    n->outstanding_aers = 0;
}

static int nvme_start_ctrl(NvmeCtrl *n)
{
    uint32_t page_bits = NVME_CC_MPS(n->bar.cc) + 12;
    uint32_t page_size = 1 << page_bits;

    if (n->cq[0] || n->sq[0] || !n->bar.asq || !n->bar.acq ||
            n->bar.asq & (page_size - 1) || n->bar.acq & (page_size - 1) ||
            NVME_CC_MPS(n->bar.cc) < NVME_CAP_MPSMIN(n->bar.cap) ||
            NVME_CC_MPS(n->bar.cc) > NVME_CAP_MPSMAX(n->bar.cap) ||
            NVME_CC_IOCQES(n->bar.cc) < NVME_CTRL_CQES_MIN(n->id_ctrl.cqes) ||
            NVME_CC_IOCQES(n->bar.cc) > NVME_CTRL_CQES_MAX(n->id_ctrl.cqes) ||
            NVME_CC_IOSQES(n->bar.cc) < NVME_CTRL_SQES_MIN(n->id_ctrl.sqes) ||
            NVME_CC_IOSQES(n->bar.cc) > NVME_CTRL_SQES_MAX(n->id_ctrl.sqes) ||
            !NVME_AQA_ASQS(n->bar.aqa) || NVME_AQA_ASQS(n->bar.aqa) > 4095 ||
            !NVME_AQA_ACQS(n->bar.aqa) || NVME_AQA_ACQS(n->bar.aqa) > 4095) {
        return -1;
    }

    n->page_bits = page_bits;
    n->page_size = 1 << n->page_bits;
    n->max_prp_ents = n->page_size / sizeof(uint64_t);
    n->cqe_size = 1 << NVME_CC_IOCQES(n->bar.cc);
    n->sqe_size = 1 << NVME_CC_IOSQES(n->bar.cc);

    nvme_init_cq(&n->admin_cq, n, n->bar.acq, 0, 0,
            NVME_AQA_ACQS(n->bar.aqa) + 1, 1, 1);
    nvme_init_sq(&n->admin_sq, n, n->bar.asq, 0, 0,
            NVME_AQA_ASQS(n->bar.aqa) + 1, NVME_Q_PRIO_HIGH, 1);

    n->aer_timer = timer_new_ns(QEMU_CLOCK_VIRTUAL, nvme_aer_process_cb, n);
    QSIMPLEQ_INIT(&n->aer_queue);
    return 0;
}

static void nvme_write_bar(NvmeCtrl *n, hwaddr offset, uint64_t data,
    unsigned size)
{
    switch (offset) {
    case 0xc:
        n->bar.intms |= data & 0xffffffff;
        n->bar.intmc = n->bar.intms;
        break;
    case 0x10:
        n->bar.intms &= ~(data & 0xffffffff);
        n->bar.intmc = n->bar.intms;
        break;
    case 0x14:
        if (NVME_CC_EN(data) && !NVME_CC_EN(n->bar.cc)) {
            n->bar.cc = data;
            if (nvme_start_ctrl(n)) {
                n->bar.csts = NVME_CSTS_FAILED;
            } else {
                n->bar.csts = NVME_CSTS_READY;
            }
        } else if (!NVME_CC_EN(data) && NVME_CC_EN(n->bar.cc)) {
            nvme_clear_ctrl(n);
            n->bar.csts &= ~NVME_CSTS_READY;
        }
        if (NVME_CC_SHN(data) && !(NVME_CC_SHN(n->bar.cc))) {
                nvme_clear_ctrl(n);
                n->bar.cc = data;
                n->bar.csts |= NVME_CSTS_SHST_COMPLETE;
        } else if (!NVME_CC_SHN(data) && NVME_CC_SHN(n->bar.cc)) {
                n->bar.csts &= ~NVME_CSTS_SHST_COMPLETE;
                n->bar.cc = data;
        }
        break;
    case 0x24:
        n->bar.aqa = data & 0xffffffff;
        break;
    case 0x28:
        n->bar.asq = data;
        break;
    case 0x2c:
        n->bar.asq |= data << 32;
        break;
    case 0x30:
        n->bar.acq = data;
        break;
    case 0x34:
        n->bar.acq |= data << 32;
        break;
    default:
        break;
    }
}

static uint64_t nvme_mmio_read(void *opaque, hwaddr addr, unsigned size)
{
    NvmeCtrl *n = (NvmeCtrl *)opaque;
    uint8_t *ptr = (uint8_t *)&n->bar;
    uint64_t val = 0;

    if (addr < sizeof(n->bar)) {
        memcpy(&val, ptr + addr, size);
    }
    return val;
}

static void nvme_process_db(NvmeCtrl *n, hwaddr addr, int val)
{
    uint32_t qid;
    uint16_t new_val = val & 0xffff;
    NvmeSQueue *sq;

    if (addr & ((1 << (2 + n->db_stride)) - 1)) {
        nvme_enqueue_event(n, NVME_AER_TYPE_ERROR,
            NVME_AER_INFO_ERR_INVALID_DB, NVME_LOG_ERROR_INFO);
        return;
    }

    if (((addr - 0x1000) >> (2 + n->db_stride)) & 1) {
        NvmeCQueue *cq;
        bool start_sqs;

        qid = (addr - (0x1000 + (1 << (2 + n->db_stride)))) >>
            (3 + n->db_stride);
        if (nvme_check_cqid(n, qid)) {
            nvme_enqueue_event(n, NVME_AER_TYPE_ERROR,
                NVME_AER_INFO_ERR_INVALID_DB, NVME_LOG_ERROR_INFO);
            return;
        }

        cq = n->cq[qid];
        if (new_val >= cq->size) {
            nvme_enqueue_event(n, NVME_AER_TYPE_ERROR,
                NVME_AER_INFO_ERR_INVALID_DB, NVME_LOG_ERROR_INFO);
            return;
        }

        start_sqs = nvme_cq_full(cq) ? true : false;
        cq->head = new_val;
        if (start_sqs) {
            QTAILQ_FOREACH(sq, &cq->sq_list, entry) {
                if (!timer_pending(sq->timer)) {
                    timer_mod(sq->timer, qemu_clock_get_ns(
                                            QEMU_CLOCK_VIRTUAL) + 500);
                }
            }
            nvme_post_cqes(cq);
        } else if (cq->tail != cq->head) {
            nvme_isr_notify(cq);
        }
    } else {
        qid = (addr - 0x1000) >> (3 + n->db_stride);
        if (nvme_check_sqid(n, qid)) {
            nvme_enqueue_event(n, NVME_AER_TYPE_ERROR,
                NVME_AER_INFO_ERR_INVALID_SQ, NVME_LOG_ERROR_INFO);
            return;
        }

        sq = n->sq[qid];
        if (new_val >= sq->size) {
            nvme_enqueue_event(n, NVME_AER_TYPE_ERROR,
                NVME_AER_INFO_ERR_INVALID_DB, NVME_LOG_ERROR_INFO);
            return;
        }

        sq->tail = new_val;
        if (!timer_pending(sq->timer)) {
            timer_mod(sq->timer, qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL) + 500);
        }
    }
}

static void nvme_mmio_write(void *opaque, hwaddr addr, uint64_t data,
    unsigned size)
{
    NvmeCtrl *n = (NvmeCtrl *)opaque;
    if (addr < sizeof(n->bar)) {
        nvme_write_bar(n, addr, data, size);
    } else if (addr >= 0x1000) {
        nvme_process_db(n, addr, data);
    }
}

static const MemoryRegionOps nvme_mmio_ops = {
    .read = nvme_mmio_read,
    .write = nvme_mmio_write,
    .endianness = DEVICE_LITTLE_ENDIAN,
    .impl = {
        .min_access_size = 2,
        .max_access_size = 8,
    },
};

static int nvme_check_constraints(NvmeCtrl *n)
{
    if ((!(n->conf.bs)) || !(n->serial) ||
        (n->num_namespaces == 0 || n->num_namespaces > NVME_MAX_NUM_NAMESPACES) ||
        (n->num_queues < 1 || n->num_queues > NVME_MAX_QS) ||
        (n->db_stride > NVME_MAX_STRIDE) ||
        (n->max_q_ents < 1) ||
        (n->max_sqes > NVME_MAX_QUEUE_ES || n->max_cqes > NVME_MAX_QUEUE_ES ||
            n->max_sqes < NVME_MIN_SQUEUE_ES || n->max_cqes < NVME_MIN_CQUEUE_ES) ||
        (n->vwc > 1 || n->intc > 1 || n->cqr > 1 || n->extended > 1) ||
        (n->nlbaf > 16) ||
        (n->lba_index >= n->nlbaf) ||
        (n->meta && !n->mc) ||
        (n->extended && !(NVME_ID_NS_MC_EXTENDED(n->mc))) ||
        (!n->extended && n->meta && !(NVME_ID_NS_MC_SEPARATE(n->mc))) ||
        (n->dps && n->meta < 8) ||
        (n->dps && ((n->dps & DPS_FIRST_EIGHT) &&
            !NVME_ID_NS_DPC_FIRST_EIGHT(n->dpc))) ||
        (n->dps && !(n->dps & DPS_FIRST_EIGHT) &&
            !NVME_ID_NS_DPC_LAST_EIGHT(n->dpc)) ||
        (n->dps & DPS_TYPE_MASK && !((n->dpc & NVME_ID_NS_DPC_TYPE_MASK) &
            (1 << ((n->dps & DPS_TYPE_MASK) - 1)))) ||
        (n->mpsmax > 0xf || n->mpsmax > n->mpsmin) ||
        (n->oacs & ~(NVME_OACS_FORMAT)) ||
        (n->oncs & ~(NVME_ONCS_COMPARE | NVME_ONCS_WRITE_UNCORR |
            NVME_ONCS_DSM))) {
        return -1;
    }
    return 0;
}

static void nvme_init_namespaces(NvmeCtrl *n)
{
    int i, j, k;
    int ji = n->meta ? 2 : 1;

    for (i = 0; i < n->num_namespaces; i++) {
        uint64_t blks, bdrv_blks;
        int lba_index;
        NvmeNamespace *ns = &n->namespaces[i];
        NvmeIdNs *id_ns = &ns->id_ns;

        id_ns->nsfeat = 0;
        id_ns->nlbaf = n->nlbaf - 1;
        id_ns->flbas = n->lba_index | (n->extended << 4);
        id_ns->mc = n->mc;
        id_ns->dpc = n->dpc;
        id_ns->dps = n->dps;

        for (j = 0; j < ji; j++) {
            for (k = 0; k < n->nlbaf / ji; k++) {
                id_ns->lbaf[k + (n->nlbaf / ji) * j].ds = BDRV_SECTOR_BITS + k;
                if (j) {
                    id_ns->lbaf[k + (n->nlbaf / ji)].ms = cpu_to_le16(n->meta);
                }
            }
        }

        lba_index = NVME_ID_NS_FLBAS_INDEX(ns->id_ns.flbas);
        blks = n->ns_size / ((1 << id_ns->lbaf[lba_index].ds) + n->meta);
        id_ns->nuse = id_ns->ncap = id_ns->nsze = cpu_to_le64(blks);
        bdrv_blks = blks << (id_ns->lbaf[lba_index].ds - BDRV_SECTOR_BITS);

        ns->id = i + 1;
        ns->ctrl = n;
        ns->start_block = ((n->ns_size >> BDRV_SECTOR_BITS) +
            (n->meta * bdrv_blks)) * i;
        ns->meta_start_offset = (ns->start_block + bdrv_blks) << BDRV_SECTOR_BITS;
        ns->util = bitmap_new(blks);
        ns->uncorrectable = bitmap_new(blks);
    }
}

static void nvme_init_ctrl(NvmeCtrl *n)
{
    int i;
    NvmeIdCtrl *id = &n->id_ctrl;
    uint8_t *pci_conf = n->parent_obj.config;

    id->vid = cpu_to_le16(pci_get_word(pci_conf + PCI_VENDOR_ID));
    id->ssvid = cpu_to_le16(pci_get_word(pci_conf + PCI_SUBSYSTEM_VENDOR_ID));
    strpadcpy((char *)id->mn, sizeof(id->mn), "QEMU NVMe Ctrl", ' ');
    strpadcpy((char *)id->fr, sizeof(id->fr), "1.0", ' ');
    strpadcpy((char *)id->sn, sizeof(id->sn), n->serial, ' ');
    id->rab = 6;
    id->ieee[0] = 0x00;
    id->ieee[1] = 0x02;
    id->ieee[2] = 0xb3;
    id->cmic = 0;
    id->mdts = n->mdts;
    id->oacs = cpu_to_le16(n->oacs);
    id->acl = n->acl;
    id->aerl = n->aerl;
    id->frmw = 7 << 1 | 1;
    id->lpa = 0 << 0;
    id->elpe = n->elpe;
    id->npss = 0;
    id->sqes = (n->max_sqes << 4) | 0x6;
    id->cqes = (n->max_cqes << 4) | 0x4;
    id->nn = cpu_to_le32(n->num_namespaces);
    id->oncs = cpu_to_le16(n->oncs);
    id->fuses = cpu_to_le16(0);
    id->fna = 0;
    id->vwc = n->vwc;
    id->awun = cpu_to_le16(0);
    id->awupf = cpu_to_le16(0);
    id->psd[0].mp = cpu_to_le16(0x9c4);
    id->psd[0].enlat = cpu_to_le32(0x10);
    id->psd[0].exlat = cpu_to_le32(0x4);

    n->features.arbitration     = 0x1f0f0706;
    n->features.power_mgmt      = 0;
    n->features.temp_thresh     = 0x14d;
    n->features.err_rec         = 0;
    n->features.volatile_wc     = n->vwc;
    n->features.num_queues      = (n->num_queues - 1) |
                                 ((n->num_queues - 1) << 16);
    n->features.int_coalescing  = n->intc_thresh | (n->intc_time << 8);
    n->features.write_atomicity = 0;
    n->features.async_config    = 0x0;
    n->features.sw_prog_marker  = 0;

    for (i = 0; i < n->num_queues; i++) {
        n->features.int_vector_config[i] = i | (n->intc << 16);
    }

    n->bar.cap = 0;
    NVME_CAP_SET_MQES(n->bar.cap, n->max_q_ents);
    NVME_CAP_SET_CQR(n->bar.cap, n->cqr);
    NVME_CAP_SET_AMS(n->bar.cap, 1);
    NVME_CAP_SET_TO(n->bar.cap, 0xf);
    NVME_CAP_SET_DSTRD(n->bar.cap, n->db_stride);
    NVME_CAP_SET_NSSRS(n->bar.cap, 0);
    NVME_CAP_SET_CSS(n->bar.cap, 1);
    NVME_CAP_SET_MPSMIN(n->bar.cap, n->mpsmin);
    NVME_CAP_SET_MPSMAX(n->bar.cap, n->mpsmax);

    n->bar.vs = 0x00010001;
    n->bar.intmc = n->bar.intms = 0;
    n->temperature = NVME_TEMPERATURE;
}

static void nvme_init_pci(NvmeCtrl *n)
{
    uint8_t *pci_conf = n->parent_obj.config;

    pci_conf[PCI_INTERRUPT_PIN] = 1;
    pci_config_set_prog_interface(pci_conf, 0x2);
    pci_config_set_class(pci_conf, PCI_CLASS_STORAGE_EXPRESS);
    pcie_endpoint_cap_init(&n->parent_obj, 0x80);

    memory_region_init_io(&n->iomem, OBJECT(n), &nvme_mmio_ops, n, "nvme",
        n->reg_size);
    pci_register_bar(&n->parent_obj, 0,
        PCI_BASE_ADDRESS_SPACE_MEMORY | PCI_BASE_ADDRESS_MEM_TYPE_64,
        &n->iomem);
    msix_init_exclusive_bar(&n->parent_obj, n->num_queues, 4);
    msi_init(&n->parent_obj, 0x50, 32, true, false);
}

static int nvme_init(PCIDevice *pci_dev)
{
    NvmeCtrl *n = NVME(pci_dev);
    int64_t bs_size;

    blkconf_serial(&n->conf, &n->serial);
    if (nvme_check_constraints(n)) {
        return -1;
    }

    bs_size = bdrv_getlength(n->conf.bs);
    if (bs_size <= 0) {
        return -1;
    }

    n->start_time = time(NULL);
    n->reg_size = 1 << qemu_fls(0x1004 + 2 * (n->num_queues + 1) * 4);
    n->ns_size = bs_size / (uint64_t)n->num_namespaces;

    n->sq = g_malloc0(sizeof(*n->sq)*n->num_queues);
    n->cq = g_malloc0(sizeof(*n->cq)*n->num_queues);
    n->namespaces = g_malloc0(sizeof(*n->namespaces) * n->num_namespaces);
    n->elpes = g_malloc0((n->elpe + 1) * sizeof(*n->elpes));
    n->aer_reqs = g_malloc0((n->aerl + 1) * sizeof(*n->aer_reqs));
    n->features.int_vector_config = g_malloc(n->num_queues *
        sizeof(*n->features.int_vector_config));

    nvme_init_pci(n);
    nvme_init_ctrl(n);
    nvme_init_namespaces(n);

    return 0;
}

static void nvme_exit(PCIDevice *pci_dev)
{
    NvmeCtrl *n = NVME(pci_dev);

    nvme_clear_ctrl(n);
    g_free(n->namespaces);
    g_free(n->features.int_vector_config);
    g_free(n->aer_reqs);
    g_free(n->elpes);
    g_free(n->cq);
    g_free(n->sq);
    msix_uninit_exclusive_bar(pci_dev);
    memory_region_destroy(&n->iomem);
}

static Property nvme_props[] = {
    DEFINE_BLOCK_PROPERTIES(NvmeCtrl, conf),
    DEFINE_PROP_STRING("serial", NvmeCtrl, serial),
    DEFINE_PROP_UINT32("namespaces", NvmeCtrl, num_namespaces, 1),
    DEFINE_PROP_UINT32("queues", NvmeCtrl, num_queues, 64),
    DEFINE_PROP_UINT32("entries", NvmeCtrl, max_q_ents, 0x7ff),
    DEFINE_PROP_UINT8("max_cqes", NvmeCtrl, max_cqes, 0x4),
    DEFINE_PROP_UINT8("max_sqes", NvmeCtrl, max_sqes, 0x6),
    DEFINE_PROP_UINT8("stride", NvmeCtrl, db_stride, 0),
    DEFINE_PROP_UINT8("aerl", NvmeCtrl, aerl, 3),
    DEFINE_PROP_UINT8("acl", NvmeCtrl, acl, 3),
    DEFINE_PROP_UINT8("elpe", NvmeCtrl, elpe, 3),
    DEFINE_PROP_UINT8("mdts", NvmeCtrl, mdts, 5),
    DEFINE_PROP_UINT8("cqr", NvmeCtrl, cqr, 1),
    DEFINE_PROP_UINT8("vwc", NvmeCtrl, vwc, 0),
    DEFINE_PROP_UINT8("intc", NvmeCtrl, intc, 0),
    DEFINE_PROP_UINT8("intc_thresh", NvmeCtrl, intc_thresh, 0),
    DEFINE_PROP_UINT8("intc_time", NvmeCtrl, intc_time, 0),
    DEFINE_PROP_UINT8("mpsmin", NvmeCtrl, mpsmin, 0),
    DEFINE_PROP_UINT8("mpsmax", NvmeCtrl, mpsmax, 0),
    DEFINE_PROP_UINT8("nlbaf", NvmeCtrl, nlbaf, 1),
    DEFINE_PROP_UINT8("lba_index", NvmeCtrl, lba_index, 0),
    DEFINE_PROP_UINT8("extended", NvmeCtrl, extended, 0),
    DEFINE_PROP_UINT8("dpc", NvmeCtrl, dpc, 0),
    DEFINE_PROP_UINT8("dps", NvmeCtrl, dps, 0),
    DEFINE_PROP_UINT8("mc", NvmeCtrl, mc, 0),
    DEFINE_PROP_UINT8("meta", NvmeCtrl, meta, 0),
    DEFINE_PROP_UINT16("oacs", NvmeCtrl, oacs, NVME_OACS_FORMAT),
    DEFINE_PROP_UINT16("oncs", NvmeCtrl, oncs, NVME_ONCS_DSM),
    DEFINE_PROP_END_OF_LIST(),
};

static const VMStateDescription nvme_vmstate = {
    .name = "nvme",
    .unmigratable = 1,
};

static void nvme_class_init(ObjectClass *oc, void *data)
{
    DeviceClass *dc = DEVICE_CLASS(oc);
    PCIDeviceClass *pc = PCI_DEVICE_CLASS(oc);

    pc->init = nvme_init;
    pc->exit = nvme_exit;
    pc->class_id = PCI_CLASS_STORAGE_EXPRESS;
    pc->vendor_id = PCI_VENDOR_ID_INTEL;
    pc->device_id = 0x5845;
    pc->revision = 1;
    pc->is_express = 1;

    set_bit(DEVICE_CATEGORY_STORAGE, dc->categories);
    dc->desc = "Non-Volatile Memory Express";
    dc->props = nvme_props;
    dc->vmsd = &nvme_vmstate;
}

static const TypeInfo nvme_info = {
    .name          = "nvme",
    .parent        = TYPE_PCI_DEVICE,
    .instance_size = sizeof(NvmeCtrl),
    .class_init    = nvme_class_init,
};

static void nvme_register_types(void)
{
    type_register_static(&nvme_info);
}

type_init(nvme_register_types)
