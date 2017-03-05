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
 * Reference Specs: http://www.nvmexpress.org, 1.2, 1.1, 1.0e
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
 *  cmbsz=<cmbsz>    : Controller Memory Buffer CMBSZ register, Default:0
 *  cmbloc=<cmbloc>  : Controller Memory Buffer CMBLOC register, Default:0
 *  lver=<int>         : version of the LightNVM standard to use, Default:1
 *  ll2pmode=<int>     : LightNVM op. mode. 1: hybrid, 0: full host-based. Default: 1
 *  lsec_size=<int>    : Controller Sector Size. Default: 4096
 *  lsecs_per_pg=<int> : Number of sectors in a flash page. Default: 1
 *  lpgs_per_blk=<int> : Number of pages per flash block. Default: 256
 *  lmax_sec_per_rq=<int> : Maximum number of sectors per I/O request. Default: 64
 *  lmtype=<int>       : Media type. Default: 0 (NAND Flash Memory)
 *  lfmtype=<int>      : Flash media type. Default: 0 (SLC)
 *  lnum_ch=<int>      : Number of controller channels. Default: 1
 *  lnum_lun=<int>     : Number of LUNs per channel, Default:1
 *  lnum_pln=<int>     : Number of flash planes per LUN. Supported single (1),
 *  dual (2) and quad (4) plane modes. Defult: 1
 *  lreadl2ptbl=<int>  : Load logical to physical table. 1: yes, 0: no. Default: 1
 *  lbbtable=<file>    : Load bad block table from file destination (Provide path
 *  to file. If no file is provided a bad block table will be generated. Look
 *  at lbbfrequency. Default: Null (no file).
 *  lbbfrequency:<int> : Bad block frequency for generating bad block table. If
 *  no frequency is provided LNVM_DEFAULT_BB_FREQ will be used.
 *  lmetadata=<file>   : Load metadata from file destination
 *  lmetasize=<int>    : LightNVM metadata (OOB) size. Default: 16
 *  lb_err_write       : First ppa to inject write error. Default: 0 (disabled)
 *  ln_err_write       : Number of ppas affected by write error injection
 *  ldebug             : Enable LightNVM debugging. Default: 0 (disabled)
 *  lstrict            : Enable strict checks. Necessary for pblk (disabled)
 *
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
 * Note that when a CMB is requested the NVMe version is set to 1.2,
 * for all other cases it is set to 1.1.
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

/**
 * Controller Memory Buffer: For now, you can only turn it on or off, but can't
 * tune the exact settings.
 */

#include <block/block_int.h>
#include <block/qapi.h>
#include <exec/memory.h>
#include <hw/block/block.h>
#include <hw/hw.h>
#include <hw/pci/msix.h>
#include <hw/pci/msi.h>
#include <hw/pci/pci.h>
#include <qapi/visitor.h>
#include <qemu/bitops.h>
#include <qemu/bitmap.h>
#include <sysemu/sysemu.h>
#include <sysemu/block-backend.h>
#include <qemu/main-loop.h>

#include "nvme.h"
#include "trace.h"

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

#define LNVM_MAX_GRPS_PR_IDENT (20)
#define LNVM_FEAT_EXT_START 64
#define LNVM_FEAT_EXT_END 127
#define LNVM_PBA_UNMAPPED UINT64_MAX
#define LNVM_LBA_UNMAPPED UINT64_MAX

static void nvme_process_sq(void *opaque);

static void nvme_addr_read(NvmeCtrl *n, hwaddr addr, void *buf, int size)
{
    if (n->cmbsz && addr >= n->ctrl_mem.addr &&
                addr < (n->ctrl_mem.addr + int128_get64(n->ctrl_mem.size))) {
        memcpy(buf, (void *)&n->cmbuf[addr - n->ctrl_mem.addr], size);
    } else {
        pci_dma_read(&n->parent_obj, addr, buf, size);
    }
}

static void nvme_addr_write(NvmeCtrl *n, hwaddr addr, void *buf, int size)
{
    if (n->cmbsz && addr >= n->ctrl_mem.addr &&
                addr < (n->ctrl_mem.addr + int128_get64(n->ctrl_mem.size))) {
        memcpy((void *)&n->cmbuf[addr - n->ctrl_mem.addr], buf, size);
        return;
    } else {
        pci_dma_write(&n->parent_obj, addr, buf, size);
    }
}

static uint8_t lightnvm_dev(NvmeCtrl *n)
{
    return (n->lightnvm_ctrl.id_ctrl.ver_id != 0);
}

static uint8_t lightnvm_hybrid_dev(NvmeCtrl *n)
{
    return (n->lightnvm_ctrl.id_ctrl.dom == 1);
}

static void lightnvm_tbl_initialize(NvmeNamespace *ns)
{
    uint32_t len = ns->tbl_entries;
    uint32_t i;

    for (i = 0; i < len; i++)
        ns->tbl[i] = LNVM_LBA_UNMAPPED;
}

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

static void nvme_update_cq_head(NvmeCQueue *cq)
{
    if (cq->db_addr) {
        nvme_addr_read(cq->ctrl, cq->db_addr, &cq->head, sizeof(cq->head));
    }
}

static uint8_t nvme_cq_full(NvmeCQueue *cq)
{
    nvme_update_cq_head(cq);
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
            nvme_addr_write(n, prp_addr, (uint8_t *)&prp, sizeof(prp));
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

static uint16_t nvme_map_prp(QEMUSGList *qsg, QEMUIOVector *iov,
                             uint64_t prp1, uint64_t prp2, uint32_t len, NvmeCtrl *n)
{
    hwaddr trans_len = n->page_size - (prp1 % n->page_size);
    trans_len = MIN(len, trans_len);
    int num_prps = (len >> n->page_bits) + 1;
    bool cmb = false;

    if (!prp1) {
        return NVME_INVALID_FIELD | NVME_DNR;
    } else if (n->cmbsz && prp1 >= n->ctrl_mem.addr &&
               prp1 < n->ctrl_mem.addr + int128_get64(n->ctrl_mem.size)) {
        cmb = true;
        qsg->nsg = 0;
        qemu_iovec_init(iov, num_prps);
        qemu_iovec_add(iov, (void *)&n->cmbuf[prp1 - n->ctrl_mem.addr], trans_len);
    } else {
        pci_dma_sglist_init(qsg, &n->parent_obj, num_prps);
        qemu_sglist_add(qsg, prp1, trans_len);
    }

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
            nvme_addr_read(n, prp2, (void *)prp_list, prp_trans);
            while (len != 0) {
                uint64_t prp_ent = le64_to_cpu(prp_list[i]);

                if (i == n->max_prp_ents - 1 && len > n->page_size) {
                    if (!prp_ent || prp_ent & (n->page_size - 1)) {
                        goto unmap;
                    }

                    i = 0;
                    nents = (len + n->page_size - 1) >> n->page_bits;
                    prp_trans = MIN(n->max_prp_ents, nents) * sizeof(uint64_t);
                    nvme_addr_read(n, prp_ent, (void *)prp_list,
                        prp_trans);
                    prp_ent = le64_to_cpu(prp_list[i]);
                }

                if (!prp_ent || prp_ent & (n->page_size - 1)) {
                    goto unmap;
                }

                trans_len = MIN(len, n->page_size);
                if (!cmb){
                    qemu_sglist_add(qsg, prp_ent, trans_len);
                } else {
                    qemu_iovec_add(iov, (void *)&n->cmbuf[prp_ent - n->ctrl_mem.addr], trans_len);
                }
                len -= trans_len;
                i++;
            }
        } else {
            if (prp2 & (n->page_size - 1)) {
                goto unmap;
            }
            if (!cmb) {
                qemu_sglist_add(qsg, prp2, len);
            } else {
                qemu_iovec_add(iov, (void *)&n->cmbuf[prp2 - n->ctrl_mem.addr], trans_len);
            }
        }
    }
    return NVME_SUCCESS;

 unmap:
    if (!cmb){
        qemu_sglist_destroy(qsg);
    } else {
        qemu_iovec_destroy(iov);
    }
    return NVME_INVALID_FIELD | NVME_DNR;
}

static uint16_t nvme_dma_write_prp(NvmeCtrl *n, uint8_t *ptr, uint32_t len,
    uint64_t prp1, uint64_t prp2)
{
    QEMUSGList qsg;
    QEMUIOVector iov;
    uint16_t status = NVME_SUCCESS;

    if (nvme_map_prp(&qsg, &iov, prp1, prp2, len, n)) {
        return NVME_INVALID_FIELD | NVME_DNR;
    }
    if (qsg.nsg > 0) {
        if (dma_buf_write(ptr, len, &qsg)) {
            status = NVME_INVALID_FIELD | NVME_DNR;
        }
        qemu_sglist_destroy(&qsg);
    } else {
        if (qemu_iovec_from_buf(&iov, 0, ptr, len) != len) {
            status = NVME_INVALID_FIELD | NVME_DNR;
        }
        qemu_iovec_destroy(&iov);
    }
    return status;
}

static uint16_t nvme_dma_read_prp(NvmeCtrl *n, uint8_t *ptr, uint32_t len,
    uint64_t prp1, uint64_t prp2)
{
    QEMUSGList qsg;
    QEMUIOVector iov;
    uint16_t status = NVME_SUCCESS;

    if (nvme_map_prp(&qsg, &iov, prp1, prp2, len, n)) {
        return NVME_INVALID_FIELD | NVME_DNR;
    }
    if (qsg.nsg > 0) {
        if (dma_buf_read(ptr, len, &qsg)) {
            status = NVME_INVALID_FIELD | NVME_DNR;
        }
        qemu_sglist_destroy(&qsg);
    } else {
        if (qemu_iovec_to_buf(&iov, 0, ptr, len) != len) {
            status = NVME_INVALID_FIELD | NVME_DNR;
        }
        qemu_iovec_destroy(&iov);
    }
    return status;
}

static void lnvm_inject_w_err(LnvmCtrl *ln, NvmeRequest *req, NvmeCqe *cqe)
{
   if (ln->err_write && req->is_write) {
        if (ln->debug)
            printf("nvme:err_stat:err_write_cnt:%d,nppas:%d,err_write:%d, n_err_write:%d\n",
                    ln->err_write_cnt, req->nlb, ln->err_write, ln->n_err_write);
        if ((ln->err_write_cnt + req->nlb) > ln->err_write) {
            int i;
            int bit;

            /* kill n_err_write sectors in ppa list */
            for (i = 0; i < req->nlb; i++) {
                if (ln->err_write_cnt + i < ln->err_write)
                    continue;

                bit = i;
                bitmap_set(&cqe->res64, bit, ln->n_err_write);
                break;
            }

            if (ln->debug)
                printf("nvme: injected error:%u, n:%u, bitmap:%lu\n",
                                             bit, ln->n_err_write, cqe->res64);
            req->status = 0x40ff; /* FAIL WRITE status code */
            ln->err_write_cnt = 0;
        }
        ln->err_write_cnt += req->nlb;
    }
}

static void lnvm_post_cqe(NvmeCtrl *n, NvmeRequest *req)
{
    LnvmCtrl *ln = &n->lightnvm_ctrl;
    NvmeCqe *cqe = &req->cqe;

   /* Do post-completion processing depending on the type of command. This is
     * used primarily to inject different types of errors.
     */
    switch (req->cmd_opcode) {
    case LNVM_CMD_HYBRID_WRITE:
    case LNVM_CMD_PHYS_WRITE:
         lnvm_inject_w_err(ln, req, cqe);
    }
}

static void nvme_post_cqe(NvmeCQueue *cq, NvmeRequest *req)
{
    NvmeCtrl *n = cq->ctrl;
    NvmeSQueue *sq = req->sq;
    NvmeCqe *cqe = &req->cqe;
    uint8_t phase = cq->phase;
    hwaddr addr;

    if (cq->phys_contig) {
        addr = cq->dma_addr + cq->tail * n->cqe_size;
    } else {
        addr = nvme_discontig(cq->prp_list, cq->tail, n->page_size,
            n->cqe_size);
    }

    lnvm_post_cqe(n, req);

    cqe->status = cpu_to_le16((req->status << 1) | phase);
    cqe->sq_id = cpu_to_le16(sq->sqid);
    cqe->sq_head = cpu_to_le16(sq->head);
    nvme_addr_write(n, addr, (void *)cqe, sizeof(*cqe));
    nvme_inc_cq_tail(cq);

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
    NvmeAsyncEvent *event;

    if (!(n->bar.csts & NVME_CSTS_READY))
	return;

    event = (NvmeAsyncEvent *)g_malloc0(sizeof(*event));
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
        result = (NvmeAerResult *)&req->cqe.n.result;
        result->event_type = event->result.event_type;
        result->event_info = event->result.event_info;
        result->log_page = event->result.log_page;
        g_free(event);

        req->status = NVME_SUCCESS;
        nvme_enqueue_req_completion(n->cq[0], req);
    }
}

static void nvme_rw_cb(void *opaque, int ret)
{
    NvmeRequest *req = opaque;
    NvmeSQueue *sq = req->sq;
    NvmeCtrl *n = sq->ctrl;
    NvmeCQueue *cq = n->cq[sq->cqid];
    NvmeNamespace *ns = req->ns;

    block_acct_done(blk_get_stats(n->conf.blk), &req->acct);
    if (!ret) {
        req->status = NVME_SUCCESS;
    } else {
        req->status = NVME_INTERNAL_DEV_ERROR;
    }
    if (req->status != NVME_SUCCESS) {
        nvme_set_error_page(n, sq->sqid, req->cqe.cid, req->status,
            offsetof(NvmeRwCmd, slba), req->slba, ns->id);
        if (req->is_write) {
            bitmap_clear(ns->util, req->slba, req->nlb);
        }
    } else {
        if (lightnvm_dev(n)) {
            if (lightnvm_hybrid_dev(n) && req->is_write) {
                if (req->nlb > 1) {
                    int i;
                    for (i = 0; i < req->nlb; i++)
                        ns->tbl[req->lightnvm_slba + i] =
                                                    req->lightnvm_ppa_list[i];
                } else {
                    ns->tbl[req->lightnvm_slba] = req->slba;
                }
            }

            if (!lightnvm_hybrid_dev(n))
                g_free(req->lightnvm_ppa_list);
        }
    }

    if (req->qsg.nsg) {
        qemu_sglist_destroy(&req->qsg);
    } else {
        qemu_iovec_destroy(&req->iov);
    }
    nvme_enqueue_req_completion(cq, req);
}

static uint16_t nvme_rw_check_req(NvmeCtrl *n, NvmeNamespace *ns, NvmeCmd *cmd,
    NvmeRequest *req, uint64_t slba, uint64_t elba, uint32_t nlb, uint16_t ctrl,
    uint64_t data_size, uint64_t meta_size)
{
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
    if (meta_size) {
        nvme_set_error_page(n, req->sq->sqid, cmd->cid, NVME_INVALID_FIELD,
            offsetof(NvmeRwCmd, control), ctrl, ns->id);
        return NVME_INVALID_FIELD | NVME_DNR;
    }
    if ((ctrl & NVME_RW_PRINFO_PRACT) && !(ns->id_ns.dps & DPS_TYPE_MASK)) {
        nvme_set_error_page(n, req->sq->sqid, cmd->cid, NVME_INVALID_FIELD,
            offsetof(NvmeRwCmd, control), ctrl, ns->id);
        /* Not contemplated in LightNVM for now */
        if (lightnvm_dev(n))
            return 0;
        return NVME_INVALID_FIELD | NVME_DNR;
    }
    if (!req->is_write && find_next_bit(ns->uncorrectable, elba, slba) < elba) {
        nvme_set_error_page(n, req->sq->sqid, cmd->cid, NVME_UNRECOVERED_READ,
            offsetof(NvmeRwCmd, slba), elba, ns->id);
        return NVME_UNRECOVERED_READ;
    }

    return 0;
}

static void print_ppa(LnvmCtrl *ln, uint64_t ppa)
{
    uint64_t ch = (ppa & ln->ppaf.ch_mask) >> ln->ppaf.ch_offset;
    uint64_t lun = (ppa & ln->ppaf.lun_mask) >> ln->ppaf.lun_offset;
    uint64_t blk = (ppa & ln->ppaf.blk_mask) >> ln->ppaf.blk_offset;
    uint64_t pg = (ppa & ln->ppaf.pg_mask) >> ln->ppaf.pg_offset;
    uint64_t pln = (ppa & ln->ppaf.pln_mask) >> ln->ppaf.pln_offset;
    uint64_t sec = (ppa & ln->ppaf.sec_mask) >> ln->ppaf.sec_offset;

    printf("ppa:ch:%lu,lun:%lu,blk:%lu,pg:%lu,pl:%lu,sec:%lu\n",
                                            ch, lun, blk, pg, pln, sec);
}

struct lnvm_metadata_format {
    uint32_t state;
    uint64_t rsv[2];
} __attribute__((__packed__));

struct lnvm_tgt_meta {
    uint64_t lba;
    uint64_t rsvd;
} __attribute__((__packed__));

/* Must be used after nvme_set_write_state to have the right file offset */
static inline int nvme_write_meta(LnvmCtrl *ln, void *meta, uint64_t ppa)
{
    FILE *fp = ln->metadata;
    size_t tgt_oob_len = ln->params.sos;
    size_t ret;

    ret = fwrite(meta, tgt_oob_len, 1, fp);
    if (ret != 1) {
        printf("Could not write to metadata file\n");
        return -1;
    }

    if (fflush(fp))
        printf("Could not write to metadata file:%d\n", errno);

    return 0;
}

/* Must be used after nvme_check_state to have the right file offset */
static inline int nvme_read_meta(LnvmCtrl *ln, void *meta, uint64_t ppa)
{
    FILE *fp = ln->metadata;
    size_t tgt_oob_len = ln->params.sos;
    size_t ret;

    ret = fread(meta, tgt_oob_len, 1, fp);
    if (ret != 1) {
        if (errno == EAGAIN)
            return 0;
        printf("Could not read metadata file - ppa:%lu (ret:%lu)\n", ppa, ret);
        perror("read");
        return -1;
    }

    return 0;
}

static inline int64_t nvme_get_bb_pos(LnvmCtrl *ln, uint64_t r)
{
    LnvmIdGroup *c = &ln->id_ctrl.groups[0];
    uint64_t lun = (r & ln->ppaf.lun_mask) >> ln->ppaf.lun_offset;
    uint64_t blk = (r & ln->ppaf.blk_mask) >> ln->ppaf.blk_offset;
    uint64_t pln = (r & ln->ppaf.pln_mask) >> ln->ppaf.pln_offset;
    uint64_t lun_off = lun * c->num_blk * c->num_pln;
    uint64_t blk_off = blk * c->num_pln;

    return pln + blk_off + lun_off;
}

static inline int nvme_erase_meta(NvmeNamespace *ns, LnvmCtrl *ln,
                                  uint64_t *psl, int nr_ppas)
{
    LnvmIdGroup *c = &ln->id_ctrl.groups[0];
    FILE *fp = ln->metadata;
    struct lnvm_metadata_format meta;
    size_t tgt_oob_len = ln->params.sos;
    size_t int_oob_len = ln->int_meta_size;
    size_t meta_len = tgt_oob_len + int_oob_len;
    uint8_t nr_blks = nr_ppas / c->num_pln;
    int ret;
    int blk, i, j;

    meta.state = LNVM_SEC_ERASED;

    if (ln->strict && nr_ppas != c->num_pln) {
        printf("lnvm: Strict erase not performed to all planes (%d)\n", nr_ppas);
        return NVME_INVALID_FIELD | NVME_DNR;
    }

    if (nr_ppas % c->num_pln) {
        printf("lnvm: Erase not performed to all planes (%d)\n", nr_ppas);
        return NVME_INVALID_FIELD | NVME_DNR;
    }

    for (blk = 0; blk < nr_blks; blk++) {
        uint8_t blk_pos = blk * c->num_pln;
        uint64_t r = psl[blk_pos];
        uint64_t ch = (r & ln->ppaf.ch_mask) >> ln->ppaf.ch_offset;
        uint64_t lun = (r & ln->ppaf.lun_mask) >> ln->ppaf.lun_offset;
        uint64_t blk = (r & ln->ppaf.blk_mask) >> ln->ppaf.blk_offset;
        uint64_t lun_off = lun * ln->params.sec_per_lun;
        uint64_t blk_off = blk * ln->params.sec_per_blk;
        uint64_t ppa = blk_off + lun_off;
        uint64_t bb_pos;

        for (i = 0; i < c->num_pln; i++) {
            /* Fail erase if the block is marked as bad */
            bb_pos = nvme_get_bb_pos(ln, psl[blk_pos + i]);
            if (ns->bbtbl[bb_pos])
                return -1;

            if (fseek(fp, ppa * meta_len , SEEK_SET)) {
                printf("Could not write OOB to metadata file\n");
                return -1;
            }

            for (j = 0; j < ln->params.sec_per_blk; j++) {
                ret = fwrite(&meta, meta_len, 1, fp);
                if (ret != 1) {
                    printf("Failed to erase ch:%lu,lun:%lu,blk:%lu - ret:%d/%d\n",
                                    ch, lun, blk, ret, ln->params.sec_per_blk);
                    return -1;
                }
            }
        }
    }

    if (fflush(fp))
        printf("Could not write to metadata file:%d\n", errno);

    return 0;
}

static inline int nvme_set_written_state(LnvmCtrl *ln, uint64_t ppa)
{
    FILE *fp = ln->metadata;
    size_t tgt_oob_len = ln->params.sos;
    size_t int_oob_len = ln->int_meta_size;
    size_t meta_len = tgt_oob_len + int_oob_len;
    uint32_t state;
    uint32_t seek = ppa * meta_len;
    size_t ret;

    if (fseek(fp, seek, SEEK_SET)) {
        printf("Could not write OOB to metadata file\n");
        return -1;
    }

    ret = fread(&state, int_oob_len, 1, fp);
    if (ret != 1) {
        if (errno == EAGAIN)
            return 0;
        printf("Could not read metadata file - ppa:%lu (ret:%lu)\n", ppa, ret);
        perror("read");
        return -1;
    }

    if (state != LNVM_SEC_ERASED) {
        printf("Attempting to write to non erased block (%d)\n", state);
        return -1;
    }

    if (fseek(fp, seek, SEEK_SET)) {
        printf("Could not write OOB to metadata file\n");
        return -1;
    }

    state = LNVM_SEC_WRITTEN;
    ret = fwrite(&state, int_oob_len, 1, fp);
    if (ret != 1) {
        printf("Could not write state to metadata file\n");
        return -1;
    }

    if (fflush(fp))
        printf("Could not write to metadata file:%d\n", errno);

    return 0;
}

static inline int nvme_check_state(LnvmCtrl *ln, uint64_t ppa, uint32_t *state)
{
    FILE *fp = ln->metadata;
    size_t tgt_oob_len = ln->params.sos;
    size_t int_oob_len = ln->int_meta_size;
    size_t meta_len = tgt_oob_len + int_oob_len;
    size_t ret;

    if (fseek(fp, ppa * meta_len , SEEK_SET)) {
        printf("Could not write OOB to metadata file\n");
        return -1;
    }

    ret = fread(state, int_oob_len, 1, fp);
    if (ret != 1) {
        if (errno == EAGAIN)
            return 0;
        printf("Could not read metadata file - ppa:%lu (ret:%lu)\n", ppa, ret);
        perror("read");
        return -1;
    }

    return 0;
}

static inline void *nvme_index_meta(LnvmCtrl *ln, void *meta, uint32_t index)
{
    return meta + (index * ln->params.sos);
}

static inline int64_t nvme_gen_to_dev_addr(LnvmCtrl *ln, uint64_t r)
{
    uint64_t ch = (r & ln->ppaf.ch_mask) >> ln->ppaf.ch_offset;
    uint64_t lun = (r & ln->ppaf.lun_mask) >> ln->ppaf.lun_offset;
    uint64_t pln = (r & ln->ppaf.pln_mask) >> ln->ppaf.pln_offset;
    uint64_t blk = (r & ln->ppaf.blk_mask) >> ln->ppaf.blk_offset;
    uint64_t pg = (r & ln->ppaf.pg_mask) >> ln->ppaf.pg_offset;
    uint64_t sec = (r & ln->ppaf.sec_mask) >> ln->ppaf.sec_offset;
    uint64_t lun_off = lun * ln->params.sec_per_lun;
    uint64_t blk_off = blk * ln->params.sec_per_blk;
    uint64_t pg_off = pg * ln->params.sec_per_pl;
    uint64_t pln_off = pln * ln->params.sec_per_pg;
    uint32_t ret;

    ret = sec + pg_off + blk_off + lun_off + pln_off;
    if (ret > ln->params.total_secs) {
        printf("Lnvm: ppa OOB:ch:%lu,lun:%lu,blk:%lu,pg:%lu,pl:%lu,sec:%lu\n",
                ch, lun, blk, pg, pln, sec);
        return -1;
    }

    return ret;
}

static uint16_t nvme_lnvm_rw(NvmeCtrl *n, NvmeNamespace *ns, NvmeCmd *cmd,
    NvmeRequest *req)
{
    /* In the case of a LightNVM device. The slba is the logical address, while the actual
     * physical block address is stored in Command Dword 11-10. */
    LnvmCtrl *ln = &n->lightnvm_ctrl;
    LnvmRwCmd *lrw = (LnvmRwCmd *)cmd;
    NvmeCqe *cqe = &req->cqe;
    uint64_t psl[ln->params.max_sec_per_rq];
    void *msl;
    uint64_t sppa;
    uint64_t eppa;
    uint64_t ppa;
    uint64_t *sector_list;
    uint64_t *aio_sector_list;
    uint32_t nlb  = le16_to_cpu(lrw->nlb) + 1;
    uint64_t prp1 = le64_to_cpu(lrw->prp1);
    uint64_t prp2 = le64_to_cpu(lrw->prp2);
    uint64_t spba = le64_to_cpu(lrw->spba);
    uint64_t meta = le64_to_cpu(lrw->metadata);
    const uint8_t lba_index = NVME_ID_NS_FLBAS_INDEX(ns->id_ns.flbas);
    const uint8_t data_shift = ns->id_ns.lbaf[lba_index].ds;
    const uint16_t ms = le16_to_cpu(ns->id_ns.lbaf[lba_index].ms);
    uint64_t data_size = nlb << data_shift;
    uint64_t meta_size = nlb * ms;
    uint32_t n_pages = data_size / ln->params.sec_size;
    uint16_t is_write = (lrw->opcode == LNVM_CMD_PHYS_WRITE ||
                                          lrw->opcode == LNVM_CMD_HYBRID_WRITE);
    uint16_t ctrl = 0;
    uint16_t err;
    uint8_t i;

    sector_list = g_malloc0(sizeof(uint64_t) * ln->params.max_sec_per_rq);
    if (!sector_list)
        return -ENOMEM;

    aio_sector_list = g_malloc0(sizeof(uint64_t) * ln->params.max_sec_per_rq);
    if (!aio_sector_list) {
        err = -ENOMEM;
        goto fail_free_sector_list;
    }

    msl = g_malloc0(ln->params.sos * ln->params.max_sec_per_rq);
    if (!msl) {
        err = -ENOMEM;
        goto fail_free_aio_sector_list;
    }

    if (n_pages > ln->params.max_sec_per_rq) {
        printf("npages too large (%u). Max:%u supported\n",
                                        n_pages, ln->params.max_sec_per_rq);
        nvme_set_error_page(n, req->sq->sqid, cmd->cid, NVME_LBA_RANGE,
                offsetof(LnvmRwCmd, spba), lrw->slba + nlb, ns->id);
        err = NVME_INVALID_FIELD | NVME_DNR;
        goto fail_free_msl;
    } else if ((is_write) && (!ln->id_ctrl.dom)
                                && (n_pages < ln->params.sec_per_pl)) {
        printf("lnvm: I/O does not respect device write constrains."
                "Sectors send: (%u). Min:%u sectors required\n",
                                        n_pages, ln->params.sec_per_pl);
        nvme_set_error_page(n, req->sq->sqid, cmd->cid, NVME_LBA_RANGE,
                offsetof(LnvmRwCmd, spba), lrw->slba + nlb, ns->id);
        err = NVME_INVALID_FIELD | NVME_DNR;
        goto fail_free_msl;
    } else if (n_pages > 1) {
            nvme_addr_read(n, spba, (void *)psl, n_pages * sizeof(void *));
    } else {
            psl[0] = spba;
    }

    if (spba == LNVM_PBA_UNMAPPED) {
        printf("lnvm: unmapped PBA\n");
        nvme_set_error_page(n, req->sq->sqid, cmd->cid, NVME_LBA_RANGE,
                offsetof(LnvmRwCmd, spba), lrw->slba + nlb, ns->id);
        err = NVME_INVALID_FIELD | NVME_DNR;
        goto fail_free_msl;
    }

    ctrl = le16_to_cpu(lrw->control);
    req->lightnvm_ppa_list = sector_list;
    req->lightnvm_slba = le64_to_cpu(lrw->slba);
    req->is_write = is_write;

    /* Reuse check logic from nvme_rw */
    sppa = nvme_gen_to_dev_addr(ln, psl[0]);
    eppa = nvme_gen_to_dev_addr(ln, psl[n_pages - 1]);
    if (sppa == -1 || eppa == -1) {
        err = -EINVAL;
        goto fail_free_msl;
    }

    err = nvme_rw_check_req(n, ns, cmd, req, sppa, eppa, nlb, ctrl,
                                                        data_size, meta_size);
    if (err)
        goto fail_free_msl;

    if (meta && is_write)
        nvme_addr_read(n, meta, (void *)msl, n_pages * ln->params.sos);

    /* If several LUNs are set up, the ppa list sent by the host will not be
     * sequential. In this case, we need to pass on the list of ppas to the dma
     * handlers to write/read data to/from the right physical sector
     */
    for (i = 0; i < n_pages; i++) {
        ppa = nvme_gen_to_dev_addr(ln, psl[i]);
        sector_list[i] = ppa;
        aio_sector_list[i] =
                    ns->start_block + (ppa << (data_shift - BDRV_SECTOR_BITS));

        if (is_write) {
            if (!lightnvm_hybrid_dev(n) && nvme_set_written_state(ln, ppa)) {
                printf("lnvm: set written status failed\n");
                print_ppa(ln, psl[i]);
                err = NVME_INVALID_FIELD | NVME_DNR;
                goto fail_free_msl;
            }

            if (meta) {
                if (nvme_write_meta(ln, nvme_index_meta(ln, msl, i), ppa)) {
                    printf("lnvm: write metadata failed\n");
                    print_ppa(ln, psl[i]);
                    err = NVME_INVALID_FIELD | NVME_DNR;
                    goto fail_free_msl;
                }
            }
        } else if (!is_write){
            uint32_t state;

            if (!lightnvm_hybrid_dev(n) && nvme_check_state(ln, ppa, &state)) {
                printf("lnvm: read status failed\n");
                print_ppa(ln, psl[i]);
                err = NVME_INVALID_FIELD | NVME_DNR;
                goto fail_free_msl;
            }

            if (state != LNVM_SEC_WRITTEN) {
                bitmap_set(&cqe->res64, i, n_pages - i);
                req->status = 0x42ff;

                /* Copy what has been read from the OOB area */
                if (meta)
                    nvme_addr_write(n, meta, (void *)msl,
                                                    n_pages * ln->params.sos);
                err = 0x42ff;
                goto fail_free_msl;
            }

            if (meta) {
                if (nvme_read_meta(ln, nvme_index_meta(ln, msl, i), ppa)) {
                    printf("lnvm: read metadata failed\n");
                    print_ppa(ln, psl[i]);
                    err = NVME_INVALID_FIELD | NVME_DNR;
                    goto fail_free_msl;
                }
            }
         }
    }

    if (meta && !is_write)
        nvme_addr_write(n, meta, (void *)msl, n_pages * ln->params.sos);

    g_free(msl);

    if (nvme_map_prp(&req->qsg, &req->iov, prp1, prp2, data_size, n)) {
        printf("lnvm: malformed prp (size:%lu), w:%d\n", data_size, is_write);
        for (i = 0; i < n_pages; i++)
            print_ppa(ln, psl[i]);

        nvme_set_error_page(n, req->sq->sqid, cmd->cid, NVME_INVALID_FIELD,
            offsetof(NvmeRwCmd, prp1), 0, ns->id);
        err = NVME_INVALID_FIELD | NVME_DNR;
        goto fail_free_msl;
    }
    req->slba = sppa;
    req->meta_size = 0;
    req->status = NVME_SUCCESS;
    req->nlb = nlb;
    req->ns = ns;

    dma_acct_start(n->conf.blk, &req->acct, &req->qsg, req->is_write ?
        BLOCK_ACCT_WRITE : BLOCK_ACCT_READ);
    if (req->qsg.nsg > 0) {
        req->aiocb = req->is_write ?
            dma_blk_write_list(n->conf.blk, &req->qsg, aio_sector_list,
                                                            nvme_rw_cb, req) :
            dma_blk_read_list(n->conf.blk, &req->qsg, aio_sector_list,
                                                            nvme_rw_cb, req);
    } else {
        uint64_t aio_sector = aio_sector_list[0];

        req->aiocb = req->is_write ?
            blk_aio_writev(n->conf.blk, aio_sector, &req->iov,
                                            data_size >> 9, nvme_rw_cb, req) :
            blk_aio_readv(n->conf.blk, aio_sector, &req->iov,
                                            data_size >> 9, nvme_rw_cb, req);

        g_free(aio_sector_list);
    }

    return NVME_NO_COMPLETE;

fail_free_msl:
        g_free(msl);
fail_free_aio_sector_list:
        g_free(aio_sector_list);
fail_free_sector_list:
        g_free(sector_list);
    return err;
}

static uint16_t nvme_rw(NvmeCtrl *n, NvmeNamespace *ns, NvmeCmd *cmd,
    NvmeRequest *req)
{
    NvmeRwCmd *rw = (NvmeRwCmd *)cmd;
    uint16_t ctrl = 0;
    uint32_t nlb  = le16_to_cpu(rw->nlb) + 1;
    uint64_t prp1 = le64_to_cpu(rw->prp1);
    uint64_t prp2 = le64_to_cpu(rw->prp2);
    uint64_t slba;
    uint64_t elba;
    const uint8_t lba_index = NVME_ID_NS_FLBAS_INDEX(ns->id_ns.flbas);
    const uint8_t data_shift = ns->id_ns.lbaf[lba_index].ds;
    const uint16_t ms = le16_to_cpu(ns->id_ns.lbaf[lba_index].ms);
    uint64_t data_size = nlb << data_shift;
    uint64_t meta_size = nlb * ms;
    uint64_t aio_slba;
    uint16_t err;

    slba = le64_to_cpu(rw->slba);
    elba = slba + nlb;
    req->is_write = rw->opcode == NVME_CMD_WRITE;
    aio_slba = ns->start_block + (slba << (data_shift - BDRV_SECTOR_BITS));
    ctrl = le16_to_cpu(rw->control);

    err = nvme_rw_check_req(n, ns, cmd, req, slba, elba, nlb, ctrl,
                                                        data_size, meta_size);
    if (err)
        return err;

    if (nvme_map_prp(&req->qsg, &req->iov, prp1, prp2, data_size, n)) {
        nvme_set_error_page(n, req->sq->sqid, cmd->cid, NVME_INVALID_FIELD,
            offsetof(NvmeRwCmd, prp1), 0, ns->id);
        return NVME_INVALID_FIELD | NVME_DNR;
    }
    req->slba = slba;
    req->meta_size = 0;
    req->status = NVME_SUCCESS;
    req->nlb = nlb;
    req->ns = ns;

    dma_acct_start(n->conf.blk, &req->acct, &req->qsg, req->is_write ?
        BLOCK_ACCT_WRITE : BLOCK_ACCT_READ);
    if (req->qsg.nsg > 0) {
        req->aiocb = req->is_write ?
            dma_blk_write(n->conf.blk, &req->qsg, aio_slba, nvme_rw_cb, req) :
            dma_blk_read(n->conf.blk, &req->qsg, aio_slba, nvme_rw_cb, req);
    } else {
        req->aiocb = req->is_write ?
            blk_aio_writev(n->conf.blk, aio_slba, &req->iov, data_size >> 9, nvme_rw_cb, req) :
            blk_aio_readv(n->conf.blk, aio_slba, &req->iov, data_size >> 9, nvme_rw_cb, req);
    }

    return NVME_NO_COMPLETE;
}

static void nvme_discard_cb(void *opaque, int ret)
{
    NvmeRequest *req = opaque;

    if (!ret) {
        req->status = NVME_SUCCESS;
    } else {
        req->status = NVME_INTERNAL_DEV_ERROR;
    }
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

        req->status = NVME_SUCCESS;
        for (i = 0; i < nr; i++) {
            slba = le64_to_cpu(range[i].slba);
            nlb = le32_to_cpu(range[i].nlb);
            if (slba + nlb > le64_to_cpu(ns->id_ns.nsze)) {
                nvme_set_error_page(n, req->sq->sqid, cmd->cid, NVME_LBA_RANGE,
                    offsetof(NvmeCmd, cdw10), slba + nlb, ns->id);
                return NVME_LBA_RANGE | NVME_DNR;
            }

            req->aiocb = blk_aio_discard(n->conf.blk,
                    ns->start_block + (slba << data_shift),
                    nlb << data_shift, nvme_discard_cb, req);
            aio_poll(blk_get_aio_context(n->conf.blk), true);

            if (req->status != NVME_SUCCESS)
                return req->status;
            bitmap_clear(ns->util, slba, nlb);
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
    if (nvme_map_prp(&req->qsg, &req->iov, prp1, prp2, data_size, n)) {
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

        if (blk_pread(n->conf.blk, offset, tmp[0], len) != len) {
            qemu_sglist_destroy(&req->qsg);
            nvme_set_error_page(n, req->sq->sqid, req->cqe.cid,
                NVME_INTERNAL_DEV_ERROR, offsetof(NvmeRwCmd, slba),
                req->slba, ns->id);
            return NVME_INTERNAL_DEV_ERROR;
        }

        nvme_addr_read(n, req->qsg.sg[i].base, tmp[1], len);
        if (memcmp(tmp[0], tmp[1], len)) {
            qemu_sglist_destroy(&req->qsg);
            return NVME_CMP_FAILURE;
        }
        offset += len;
    }

    qemu_sglist_destroy(&req->qsg);
    return NVME_SUCCESS;
}

static void nvme_misc_cb(void *opaque, int ret)
{
    NvmeRequest *req = opaque;
    NvmeSQueue *sq = req->sq;
    NvmeCtrl *n = sq->ctrl;
    NvmeCQueue *cq = n->cq[sq->cqid];

    block_acct_done(blk_get_stats(n->conf.blk), &req->acct);
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
    block_acct_start(blk_get_stats(n->conf.blk), &req->acct, 0, BLOCK_ACCT_FLUSH);
    req->aiocb = blk_aio_flush(n->conf.blk, nvme_misc_cb, req);
    return NVME_NO_COMPLETE;
}

static uint16_t nvme_write_zeros(NvmeCtrl *n, NvmeNamespace *ns, NvmeCmd *cmd,
    NvmeRequest *req)
{
    NvmeRwCmd *rw = (NvmeRwCmd *)cmd;
    const uint8_t lba_index = NVME_ID_NS_FLBAS_INDEX(ns->id_ns.flbas);
    const uint8_t data_shift = ns->id_ns.lbaf[lba_index].ds;
    uint64_t slba = le64_to_cpu(rw->slba);
    uint32_t nlb  = le16_to_cpu(rw->nlb) + 1;
    uint64_t aio_slba = ns->start_block + (slba << (data_shift - BDRV_SECTOR_BITS));
    uint32_t aio_nlb = nlb << (data_shift - BDRV_SECTOR_BITS);

    if ((slba + nlb) > ns->id_ns.nsze) {
        nvme_set_error_page(n, req->sq->sqid, cmd->cid, NVME_LBA_RANGE,
            offsetof(NvmeRwCmd, nlb), slba + nlb, ns->id);
        return NVME_LBA_RANGE | NVME_DNR;
    }

    block_acct_start(blk_get_stats(n->conf.blk), &req->acct, 0, BLOCK_ACCT_WRITE);
    req->aiocb = blk_aio_write_zeroes(n->conf.blk, aio_slba, aio_nlb, 0,
                                        nvme_misc_cb, req);
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

static uint32_t lightnvm_tbl_size(NvmeNamespace *ns)
{
    return ns->tbl_entries * sizeof(*(ns->tbl));
}

static uint16_t lightnvm_identity(NvmeCtrl *n, NvmeCmd *cmd)
{
    NvmeIdentify *c = (NvmeIdentify *)cmd;
    uint32_t nsid = le32_to_cpu(c->nsid);
    uint64_t prp1 = le64_to_cpu(c->prp1);
    uint64_t prp2 = le64_to_cpu(c->prp2);

    if (nsid == 0 || nsid > n->num_namespaces) {
        return NVME_INVALID_NSID | NVME_DNR;
    }

    return nvme_dma_read_prp(n, (uint8_t *)&n->lightnvm_ctrl.id_ctrl,
                                    sizeof(LnvmIdCtrl), prp1, prp2);
}

static uint16_t lightnvm_get_l2p_tbl(NvmeCtrl *n, NvmeCmd *cmd, NvmeRequest *req)
{
    NvmeNamespace *ns;
    LnvmGetL2PTbl *gtbl = (LnvmGetL2PTbl*)cmd;
    uint64_t slba = le64_to_cpu(gtbl->slba);
    uint32_t nlb = le32_to_cpu(gtbl->nlb);
    uint64_t prp1 = le64_to_cpu(gtbl->prp1);
    uint64_t prp2 = le64_to_cpu(gtbl->prp2);
    uint32_t nsid = le32_to_cpu(gtbl->nsid);
    uint64_t xfer_len = nlb * sizeof(*(ns->tbl));

    if (nsid == 0 || nsid > n->num_namespaces) {
        return NVME_INVALID_NSID | NVME_DNR;
    }
    ns = &n->namespaces[nsid - 1];

    if (slba >= ns->tbl_entries) {
        nvme_set_error_page(n, req->sq->sqid, cmd->cid, NVME_INVALID_FIELD,
            offsetof(LnvmGetL2PTbl, slba), 0, ns->id);
        return NVME_INVALID_FIELD | NVME_DNR;
    }
    if ((slba + nlb) > ns->tbl_entries) {
        nvme_set_error_page(n, req->sq->sqid, cmd->cid, NVME_INVALID_FIELD,
            offsetof(LnvmGetL2PTbl, nlb), 0, ns->id);
        return NVME_INVALID_FIELD | NVME_DNR;
    }

    if (nvme_dma_read_prp(n, (uint8_t *)&ns->tbl[slba], xfer_len,
                          prp1, prp2)) {
        nvme_set_error_page(n, req->sq->sqid, cmd->cid, NVME_INVALID_FIELD,
                            offsetof(LnvmGetL2PTbl, prp1), 0, ns->id);
        return NVME_INVALID_FIELD | NVME_DNR;
    }
    return NVME_SUCCESS;
}

/* TODO: Implement for different bad block table formats. It depends on flash
 * vendors.
 */
static int lightnvm_read_bbtbl(NvmeNamespace *ns, uint32_t nr_blocks,
                                             uint32_t offset, uint8_t *blks)
{
    struct LnvmCtrl *ln = &ns->ctrl->lightnvm_ctrl;
    FILE *fp;
    size_t ret;

    fp = fopen(ln->bb_tbl_name, "r");
    if (!fp) {
        memcpy(blks, ns->bbtbl, nr_blocks);
        return 0;
    }

    if (fseek(fp, offset, SEEK_SET)) {
        printf("Could not read bb file\n");
        return -1;
    }

    ret = fread(blks, 1, nr_blocks, fp);
    if (ret != nr_blocks) {
        printf("Could not read bb file\n");
        return -1;
    }

    fclose(fp);
    return 0;
}

/*static int lightnvm_gen_bbtbl(LnvmCtrl *ln, uint32_t nr_blocks, uint8_t *blks)
{
    uint32_t i;

    if (!ln->bb_gen_freq)
        return 0;

    for (i = 0; i < nr_blocks; i++) {
        if ((i % ln->bb_gen_freq) == 0) {
            blks[i] = 0x1;
        }
    }

    return 0;
}*/

static uint16_t lightnvm_get_bb_tbl(NvmeCtrl *n, NvmeCmd *cmd, NvmeRequest *req)
{
    NvmeNamespace *ns;
    LnvmCtrl *ln;
    LnvmIdGroup *c;
    LnvmGetBBTbl *bbtbl = (LnvmGetBBTbl*)cmd;

    uint32_t nsid = le32_to_cpu(bbtbl->nsid);
    uint64_t prp1 = le64_to_cpu(bbtbl->prp1);
    uint64_t prp2 = le64_to_cpu(bbtbl->prp2);
    uint64_t ppa, lun;
    uint64_t offset;
    uint32_t nr_blocks;
    LnvmBBTbl *bb_tbl;
    int ret = NVME_SUCCESS;

    if (nsid == 0 || nsid > n->num_namespaces) {
        return NVME_INVALID_NSID | NVME_DNR;
    }

    ns = &n->namespaces[nsid - 1];
    ln = &n->lightnvm_ctrl;
    c = &ln->id_ctrl.groups[0];
    nr_blocks = c->num_blk * c->num_pln;

    ppa = le64_to_cpu(bbtbl->spba);
    lun = (ppa & ln->ppaf.lun_mask) >> ln->ppaf.lun_offset;

    bb_tbl = calloc(sizeof(LnvmBBTbl) + nr_blocks, 1);
    if (!bb_tbl) {
        error_report("lightnvm: cannot allocate bitmap for bad block table\n");
        ret = -ENOMEM;
        goto out;
    }

    bb_tbl->tblid[0] = 'B';
    bb_tbl->tblid[1] = 'B';
    bb_tbl->tblid[2] = 'L';
    bb_tbl->tblid[3] = 'T';
    bb_tbl->verid = cpu_to_le16(1);
    bb_tbl->tblks = cpu_to_le32(nr_blocks);

    offset = lun * (c->num_blk * c->num_pln);
    ret = lightnvm_read_bbtbl(ns, nr_blocks, offset, bb_tbl->blk);
    if (ret)
        goto clean;

    if (nvme_dma_read_prp(n, (uint8_t*)bb_tbl, sizeof(LnvmBBTbl) + nr_blocks, prp1, prp2)) {
        nvme_set_error_page(n, req->sq->sqid, cmd->cid,
            NVME_INVALID_FIELD, (uint16_t)1234, 0, ns->id);
        free(bb_tbl);
        return NVME_INVALID_FIELD | NVME_DNR;
    }

clean:
    free(bb_tbl);
out:
    return ret; /*TODO: STUB*/
}

static uint16_t lightnvm_set_bb_tbl(NvmeCtrl *n, NvmeCmd *cmd, NvmeRequest *req)
{
    NvmeNamespace *ns;
    LnvmCtrl *ln;
    LnvmIdGroup *c;
    LnvmSetBBTbl *bbtbl = (LnvmSetBBTbl*)cmd;

    uint32_t nsid = le32_to_cpu(bbtbl->nsid);
    uint64_t prp2 = le64_to_cpu(bbtbl->prp2);
    uint32_t nlb  = le16_to_cpu(bbtbl->nlb) + 1;
    uint64_t spba = le64_to_cpu(bbtbl->spba);
    uint8_t value = bbtbl->value;
    uint32_t nr_blocks;
    uint64_t pos;
    int i;
    FILE *fp;
    size_t ret;

    if (nsid == 0 || nsid > n->num_namespaces) {
        return NVME_INVALID_NSID | NVME_DNR;
    }

    ns = &n->namespaces[nsid - 1];
    ln = &n->lightnvm_ctrl;
    c = &ln->id_ctrl.groups[0];
    nr_blocks = c->num_blk * c->num_pln * c->num_lun;

    uint64_t ppas[ln->params.max_sec_per_rq];

    if (nlb == 1) {
        ppas[0] = spba;
        pos = nvme_get_bb_pos(ln, spba);
        ns->bbtbl[pos] = value;
    } else {
        if (nvme_dma_write_prp(n, (uint8_t *)ppas, nlb * 8, spba, prp2)) {
            nvme_set_error_page(n, req->sq->sqid, cmd->cid, NVME_INVALID_FIELD,
                offsetof(LnvmSetBBTbl, spba), 0, ns->id);
            return NVME_INVALID_FIELD | NVME_DNR;
        }

        for (i = 0; i < nlb; i++) {
            pos = nvme_get_bb_pos(ln, ppas[i]);
            ns->bbtbl[pos] = value;
        }
    }

    fp = fopen(ln->bb_tbl_name, "w+");
    if (!fp) {
        error_report("nvme: could not save bad block table file: %s\n",
                                                         ln->bb_tbl_name);
        return -EEXIST;
    }

    ret = fwrite(ns->bbtbl, 1, nr_blocks, fp);
    if (ret != nr_blocks)
        printf("Could not read file\n");

    fclose(fp);

    return NVME_SUCCESS;
}

static int lightnvm_flush_tbls(NvmeCtrl *n)
{
    uint32_t i;
    for (i = 0; i < n->num_namespaces; i++) {
        NvmeNamespace *ns = &n->namespaces[i];
        if (bdrv_pwrite_sync(blk_bs(n->conf.blk), ns->tbl_dsk_start_offset,
                             ns->tbl, lightnvm_tbl_size(ns))) {
            return -1;
        }
    }
    return 0;
}

static int lightnvm_read_tbls(NvmeCtrl *n)
{
    uint32_t i;

    for (i = 0; i < n->num_namespaces; i++) {
        NvmeNamespace *ns = &n->namespaces[i];
        uint32_t tbl_size = lightnvm_tbl_size(ns);
        if (blk_pread(n->conf.blk, ns->tbl_dsk_start_offset,
                       ns->tbl, tbl_size) != tbl_size) {
            return -1;
        }
    }

    return 0;
}

static void erase_io_complete_cb(void *opaque, int ret)
{
    NvmeRequest *req = opaque;
    NvmeSQueue *sq = req->sq;
    NvmeCtrl *n = sq->ctrl;
    NvmeCQueue *cq = n->cq[sq->cqid];

    block_acct_done(blk_get_stats(n->conf.blk), &req->acct);
    if (!ret) {
        req->status = NVME_SUCCESS;
    } else {
        req->status = 0x40ff;
    }

    nvme_enqueue_req_completion(cq, req);
}

static uint16_t lightnvm_erase_async(NvmeCtrl *n, NvmeNamespace *ns, NvmeCmd *cmd,
    NvmeRequest *req)
{
    LnvmCtrl *ln = &n->lightnvm_ctrl;
    LnvmRwCmd *dm = (LnvmRwCmd *)cmd;
    uint64_t spba = le64_to_cpu(dm->spba);
    uint64_t psl[ln->params.max_sec_per_rq];
    uint32_t nlb = le16_to_cpu(dm->nlb) + 1;

    if (nlb > 1) {
        nvme_addr_read(n, spba, (void *)psl, nlb * sizeof(void *));
    } else {
        psl[0] = spba;
    }

    req->slba = spba;
    req->meta_size = 0;
    req->status = NVME_SUCCESS;
    req->nlb = nlb;
    req->ns = ns;

    if (nvme_erase_meta(ns, ln, psl, nlb)) {
        printf("Erased failed\n");
        print_ppa(ln, psl[0]);
        req->status = 0x40ff;

        return NVME_INVALID_FIELD | NVME_DNR;
    }

    erase_io_complete_cb(req, 0);
    return NVME_NO_COMPLETE;
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
    case LNVM_CMD_HYBRID_WRITE:
    case LNVM_CMD_PHYS_READ:
    case LNVM_CMD_PHYS_WRITE:
        return nvme_lnvm_rw(n, ns, cmd, req);
    case NVME_CMD_READ:
    case NVME_CMD_WRITE:
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

    case NVME_CMD_WRITE_ZEROS:
        if (NVME_ONCS_WRITE_ZEROS & n->oncs) {
            return nvme_write_zeros(n, ns, cmd, req);
        }
        return NVME_INVALID_OPCODE | NVME_DNR;

    case NVME_CMD_WRITE_UNCOR:
        if (NVME_ONCS_WRITE_UNCORR & n->oncs) {
            return nvme_write_uncor(n, ns, cmd, req);
        }
        return NVME_INVALID_OPCODE | NVME_DNR;
    case LNVM_CMD_ERASE_ASYNC:
        if (lightnvm_dev(n))
            return lightnvm_erase_async(n, ns, cmd, req);
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
            blk_aio_cancel(req->aiocb);
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

    sq->io_req = g_malloc0(sq->size * sizeof(*sq->io_req));
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
    sq->db_addr = 0;
    sq->eventidx_addr = 0;

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
    cq->db_addr = 0;
    cq->eventidx_addr = 0;
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

    if (cns == 1) {
        return nvme_dma_read_prp(n, (uint8_t *)&n->id_ctrl, sizeof(n->id_ctrl),
            prp1, prp2);
    } else if (cns != 0) {
        return NVME_INVALID_FIELD | NVME_DNR;
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
        req->cqe.n.result = cpu_to_le32(n->features.arbitration);
        break;
    case NVME_POWER_MANAGEMENT:
        req->cqe.n.result = cpu_to_le32(n->features.power_mgmt);
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
        req->cqe.n.result = cpu_to_le32(n->num_queues | (n->num_queues << 16));
        break;
    case NVME_TEMPERATURE_THRESHOLD:
        req->cqe.n.result = cpu_to_le32(n->features.temp_thresh);
        break;
    case NVME_ERROR_RECOVERY:
        req->cqe.n.result = cpu_to_le32(n->features.err_rec);
        break;
    case NVME_VOLATILE_WRITE_CACHE:
        req->cqe.n.result = cpu_to_le32(n->features.volatile_wc);
        break;
    case NVME_INTERRUPT_COALESCING:
        req->cqe.n.result = cpu_to_le32(n->features.int_coalescing);
        break;
    case NVME_INTERRUPT_VECTOR_CONF:
        if ((dw11 & 0xffff) > n->num_queues) {
            return NVME_INVALID_FIELD | NVME_DNR;
        }
        req->cqe.n.result = cpu_to_le32(
            n->features.int_vector_config[dw11 & 0xffff]);
        break;
    case NVME_WRITE_ATOMICITY:
        req->cqe.n.result = cpu_to_le32(n->features.write_atomicity);
        break;
    case NVME_ASYNCHRONOUS_EVENT_CONF:
        req->cqe.n.result = cpu_to_le32(n->features.async_config);
        break;
    case NVME_SOFTWARE_PROGRESS_MARKER:
        req->cqe.n.result = cpu_to_le32(n->features.sw_prog_marker);
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
        req->cqe.n.result = cpu_to_le32(n->features.arbitration);
        n->features.arbitration = dw11;
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
        req->cqe.n.result = cpu_to_le32(n->num_queues | (n->num_queues << 16));
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

    BlockAcctStats *stats = blk_get_stats(n->conf.blk);

    trans_len = MIN(sizeof(smart), buf_len);
    memset(&smart, 0x0, sizeof(smart));
    smart.data_units_read[0] = cpu_to_le64(stats->nr_bytes[BLOCK_ACCT_READ]);
    smart.data_units_written[0] = cpu_to_le64(stats->nr_bytes[BLOCK_ACCT_WRITE]);
    smart.host_read_commands[0] = cpu_to_le64(stats->nr_ops[BLOCK_ACCT_READ]);
    smart.host_write_commands[0] = cpu_to_le64(stats->nr_ops[BLOCK_ACCT_WRITE]);

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
        nvme_addr_read(n, addr, (void *)&abort_cmd, sizeof(abort_cmd));
        if (abort_cmd.cid == cid) {
            *result = 0;
            req = QTAILQ_FIRST(&sq->req_list);
            QTAILQ_REMOVE(&sq->req_list, req, entry);
            QTAILQ_INSERT_TAIL(&sq->out_req_list, req, entry);

            memset(&req->cqe, 0, sizeof(req->cqe));
            req->cqe.cid = cid;
            req->status = NVME_CMD_ABORT_REQ;

            abort_cmd.opcode = NVME_OP_ABORTED;
            nvme_addr_write(n, addr, (void *)&abort_cmd,
                sizeof(abort_cmd));

            nvme_enqueue_req_completion(n->cq[sq->cqid], req);
            return NVME_SUCCESS;
        }

        ++index;
    }
    return NVME_SUCCESS;
}

static uint64_t ns_blks(NvmeNamespace *ns, uint8_t lba_idx)
{
    NvmeCtrl *n = ns->ctrl;
    NvmeIdNs *id_ns = &ns->id_ns;
    uint64_t ns_size = n->ns_size;

    uint32_t lba_ds = (1 << id_ns->lbaf[lba_idx].ds);
    uint32_t lba_sz = lba_ds + n->meta;

    if (lightnvm_dev(n)) {
        /* p_ent: LBA + md + L2P entry */
        uint64_t p_ent = lba_sz + sizeof(*(ns->tbl));
        uint64_t p_ents = ns_size / p_ent;

        return p_ents;
    } else {
        return ns_size / lba_sz;
    }
}

static uint64_t ns_bdrv_blks(NvmeNamespace *ns, uint64_t blks, uint8_t lba_idx)
{
    NvmeIdNs *id_ns = &ns->id_ns;

    return blks << (id_ns->lbaf[lba_idx].ds - BDRV_SECTOR_BITS);
}

static void nvme_partition_ns(NvmeNamespace *ns, uint8_t lba_idx)
{
    /*
      Issues:
      * all I/O to NS must have stopped as this frees several ns structures
        (util, uncorrectable, tbl) -- failure to do so could render I/O code
        referencing freed memory -- DANGEROUS.
    */
    NvmeCtrl *n = ns->ctrl;
    NvmeIdNs *id_ns = &ns->id_ns;
    uint64_t blks;
    uint64_t bdrv_blks;

    blks = ns->ns_blks;
    bdrv_blks = ns_bdrv_blks(ns, ns->ns_blks, lba_idx);

    if (lightnvm_dev(n) && lightnvm_hybrid_dev(n)) {
        ns->tbl_dsk_start_offset =
            (ns->start_block + bdrv_blks) << BDRV_SECTOR_BITS;
        ns->tbl_entries = blks;
        if (ns->tbl) {
            g_free(ns->tbl);
        }
        ns->tbl = qemu_blockalign(blk_bs(n->conf.blk), lightnvm_tbl_size(ns));
        lightnvm_tbl_initialize(ns);
    } else {
        ns->tbl = NULL;
        ns->tbl_entries = 0;
    }

    id_ns->nuse = id_ns->ncap = id_ns->nsze = cpu_to_le64(blks);
    ns->meta_start_offset =
        ((ns->start_block + bdrv_blks) << BDRV_SECTOR_BITS) + lightnvm_tbl_size(ns);

    if (ns->util)
        g_free(ns->util);
    ns->util = bitmap_new(blks);
    if (ns->uncorrectable)
        g_free(ns->uncorrectable);
    ns->uncorrectable = bitmap_new(blks);
}

static uint16_t nvme_format_namespace(NvmeNamespace *ns, uint8_t lba_idx,
    uint8_t meta_loc, uint8_t pil, uint8_t pi, uint8_t sec_erase)
{
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

    ns->id_ns.flbas = lba_idx | meta_loc;
    ns->id_ns.dps = pil | pi;
    ns->ns_blks = ns_blks(ns, lba_idx);
    nvme_partition_ns(ns, lba_idx);
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

static uint16_t nvme_set_db_memory(NvmeCtrl *n, const NvmeCmd *cmd)
{
    uint64_t db_addr = le64_to_cpu(cmd->prp1);
    uint64_t eventidx_addr = le64_to_cpu(cmd->prp2);
    int i;

    /* Addresses should not be NULL and should be page aligned. */
    if (db_addr == 0 || db_addr & (n->page_size - 1) ||
        eventidx_addr == 0 || eventidx_addr & (n->page_size - 1)) {
        return NVME_INVALID_MEMORY_ADDRESS | NVME_DNR;
    }

    /* This assumes all I/O queues are created before this command is handled.
     * We skip the admin queues. */
    for (i = 1; i < n->num_queues; i++) {
        NvmeSQueue *sq = n->sq[i];
        NvmeCQueue *cq = n->cq[i];

        if (sq) {
            /* Submission queue tail pointer location, 2 * QID * stride. */
            sq->db_addr = db_addr + 2 * i * (1 << (2  + n->db_stride));
            sq->eventidx_addr = eventidx_addr + 2 * i *
                                    (1 << (2 + n->db_stride));
        }
        if (cq) {
            /* Completion queue head pointer location, (2 * QID + 1) * stride. */
            cq->db_addr = db_addr + (2 * i + 1) * (1 << (2 + n->db_stride));
            cq->eventidx_addr = eventidx_addr + (2 * i + 1) *
                        (1 << (2 + n->db_stride));
        }
    }
    return NVME_SUCCESS;
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
        return nvme_abort_req(n, cmd, &req->cqe.n.result);
    case NVME_ADM_CMD_FORMAT_NVM:
        if (NVME_OACS_FORMAT & n->oacs) {
            return nvme_format(n, cmd);
        }
        return NVME_INVALID_OPCODE | NVME_DNR;
    case NVME_ADM_CMD_SET_DB_MEMORY:
        return nvme_set_db_memory(n, cmd);
    case LNVM_ADM_CMD_IDENTITY:
            return lightnvm_identity(n, cmd);
    case LNVM_ADM_CMD_GET_L2P_TBL:
            return lightnvm_get_l2p_tbl(n, cmd, req);
    case LNVM_ADM_CMD_GET_BB_TBL:
            return lightnvm_get_bb_tbl(n, cmd, req);
    case LNVM_ADM_CMD_SET_BB_TBL:
            return lightnvm_set_bb_tbl(n, cmd, req);
    case NVME_ADM_CMD_ACTIVATE_FW:
    case NVME_ADM_CMD_DOWNLOAD_FW:
    case NVME_ADM_CMD_SECURITY_SEND:
    case NVME_ADM_CMD_SECURITY_RECV:
    default:
        return NVME_INVALID_OPCODE | NVME_DNR;
    }
}

static void nvme_update_sq_eventidx(const NvmeSQueue *sq)
{
    if (sq->eventidx_addr) {
        nvme_addr_write(sq->ctrl, sq->eventidx_addr, (void *)&sq->tail,
            sizeof(sq->tail));
    }
}

static void nvme_update_sq_tail(NvmeSQueue *sq)
{
    if (sq->db_addr) {
        nvme_addr_read(sq->ctrl, sq->db_addr, &sq->tail, sizeof(sq->tail));
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

    nvme_update_sq_tail(sq);
    while (!(nvme_sq_empty(sq) || QTAILQ_EMPTY(&sq->req_list)) &&
            processed++ < sq->arb_burst) {
        if (sq->phys_contig) {
            addr = sq->dma_addr + sq->head * n->sqe_size;
        } else {
            addr = nvme_discontig(sq->prp_list, sq->head, n->page_size,
                n->sqe_size);
        }
        nvme_addr_read(n, addr, (void *)&cmd, sizeof(cmd));
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
        req->cmd_opcode = cmd.opcode;

        status = sq->sqid ? nvme_io_cmd(n, &cmd, req) :
            nvme_admin_cmd(n, &cmd, req);
        if (status != NVME_NO_COMPLETE) {
            req->status = status;
            nvme_enqueue_req_completion(cq, req);
        }
    }
    nvme_update_sq_eventidx(sq);
    nvme_update_sq_tail(sq);

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

    blk_flush(n->conf.blk);
    if (lightnvm_hybrid_dev(n))
        lightnvm_flush_tbls(n);
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

    trace_nvme_mmio_read(addr, size, val);

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

        /* When the mapped pointer memory area is setup, we don't rely on
         * the MMIO written values to update the head pointer. */
        if (!cq->db_addr) {
            cq->head = new_val;
        }
        if (start_sqs) {
            NvmeSQueue *sq;
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

        /* When the mapped pointer memory area is setup, we don't rely on
         * the MMIO written values to update the tail pointer. */
        if (!sq->db_addr) {
            sq->tail = new_val;
        }
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

    trace_nvme_mmio_write(addr, size, data);
}

static void nvme_cmb_write(void *opaque, hwaddr addr, uint64_t data,
    unsigned size)
{
    NvmeCtrl *n = (NvmeCtrl *)opaque;
    memcpy(&n->cmbuf[addr], &data, size);

    trace_nvme_cmb_write(addr, size, data);
}

static uint64_t nvme_cmb_read(void *opaque, hwaddr addr, unsigned size)
{
    uint64_t val;
    NvmeCtrl *n = (NvmeCtrl *)opaque;

    memcpy(&val, &n->cmbuf[addr], size);
    trace_nvme_cmb_read(addr, size, val);
    return val;
}

static const MemoryRegionOps nvme_cmb_ops = {
    .read = nvme_cmb_read,
    .write = nvme_cmb_write,
    .endianness = DEVICE_LITTLE_ENDIAN,
    .impl = {
        .min_access_size = 2,
        .max_access_size = 8,
    },
};

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
    if ((!(n->conf.blk)) || !(n->serial) ||
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
            NVME_ONCS_DSM | NVME_ONCS_WRITE_ZEROS))) {
        return -1;
    }
    return 0;
}

static void nvme_init_namespaces(NvmeCtrl *n)
{
    int i, j, k;
    int ji = n->meta ? 2 : 1;

    for (i = 0; i < n->num_namespaces; i++) {
        uint64_t blks;
        int lba_index;
        NvmeNamespace *ns = &n->namespaces[i];
        NvmeIdNs *id_ns = &ns->id_ns;

        id_ns->nsfeat = 0x0;
        id_ns->nlbaf = n->nlbaf - 1;
        id_ns->flbas = n->lba_index | (n->extended << 4);
        id_ns->mc = n->mc;
        id_ns->dpc = n->dpc;
        id_ns->dps = n->dps;

        if (lightnvm_dev(n))
            id_ns->vs[0] = 0x1;

        /* TODO: Jesper, please clean this mess up */
        for (j = 0; j < ji; j++) {
            for (k = 0; k < n->nlbaf / ji; k++) {
                id_ns->lbaf[k + (n->nlbaf / ji) * j].ds = BDRV_SECTOR_BITS + k;
                if (j) {
                    id_ns->lbaf[k + (n->nlbaf / ji)].ms = cpu_to_le16(n->meta);
                }
            }
        }

        lba_index = NVME_ID_NS_FLBAS_INDEX(ns->id_ns.flbas);
        blks = n->ns_size / ((1 << id_ns->lbaf[lba_index].ds));
        id_ns->nuse = id_ns->ncap = id_ns->nsze = cpu_to_le64(blks);

        ns->id = i + 1;
        ns->ctrl = n;
        ns->ns_blks = ns_blks(ns, lba_index);
        ns->start_block = i * ((n->ns_size >> BDRV_SECTOR_BITS)
                    + (n->meta * ns_bdrv_blks(ns, ns->ns_blks, lba_index)));
        ns->util = bitmap_new(blks);
        ns->uncorrectable = bitmap_new(blks);
        nvme_partition_ns(ns, lba_index);
    }
}

static void lightnvm_init_id_ctrl(LnvmCtrl *ln)
{
    LnvmIdCtrl *ln_id = &ln->id_ctrl;

    ln_id->ver_id = 1;
    ln_id->vmnt = 0;
    ln_id->cgrps = 1;
    ln_id->cap = cpu_to_le32(0x3);

    ln_id->ppaf.blk_offset = 0;
    ln_id->ppaf.blk_len = 12;
    ln_id->ppaf.pg_offset = ln_id->ppaf.blk_offset + ln_id->ppaf.blk_len;
    ln_id->ppaf.pg_len = qemu_fls(cpu_to_le16(ln->params.pgs_per_blk) - 1);
    ln_id->ppaf.sect_offset = ln_id->ppaf.pg_offset + ln_id->ppaf.pg_len;
    ln_id->ppaf.sect_len = qemu_fls(cpu_to_le16(ln->params.sec_per_pg) - 1);
    ln_id->ppaf.pln_offset = ln_id->ppaf.sect_offset + ln_id->ppaf.sect_len;
    ln_id->ppaf.pln_len = qemu_fls(cpu_to_le16(ln->params.num_pln) - 1);
    ln_id->ppaf.lun_offset = ln_id->ppaf.pln_offset + ln_id->ppaf.pln_len;
    ln_id->ppaf.lun_len = qemu_fls(cpu_to_le16(ln->params.num_lun) - 1);
    ln_id->ppaf.ch_offset = ln_id->ppaf.lun_offset + ln_id->ppaf.lun_len;
    ln_id->ppaf.ch_len = qemu_fls(cpu_to_le16(ln->params.num_ch) - 1);
}

static int lightnvm_init(NvmeCtrl *n)
{
    LnvmCtrl *ln;
    LnvmIdGroup *c;
    NvmeNamespace *ns;
    unsigned int i;
    uint64_t chnl_blks;
    uint32_t nr_total_blocks;
    int ret = 0;

    ln = &n->lightnvm_ctrl;

    if (ln->params.mtype != 0)
        error_report("nvme: Only NAND Flash Memory supported at the moment\n");
    if (ln->params.fmtype != 0)
        error_report("nvme: Only SLC Flash is supported at the moment\n");
    if (ln->params.num_ch != 1)
        error_report("nvme: Only 1 channel is supported at the moment\n");
    if ((ln->params.num_pln > 4) || (ln->params.num_pln == 3))
        error_report("nvme: Only single, dual and quad plane modes supported \n");

    for (i = 0; i < n->num_namespaces; i++) {
        ns = &n->namespaces[i];
        chnl_blks = ns->ns_blks / (ln->params.sec_per_pg * ln->params.pgs_per_blk);

        c = &ln->id_ctrl.groups[0];
        c->mtype = ln->params.mtype;
        c->fmtype = ln->params.fmtype;
        c->num_ch = ln->params.num_ch;
        c->num_lun = ln->params.num_lun;
        c->num_pln = ln->params.num_pln;

        c->num_blk = cpu_to_le16(chnl_blks) / (c->num_lun * c->num_pln);
        c->num_pg = cpu_to_le16(ln->params.pgs_per_blk);
        c->csecs = cpu_to_le16(ln->params.sec_size);
        c->fpg_sz = cpu_to_le16(ln->params.sec_size * ln->params.sec_per_pg);
        c->sos = cpu_to_le16(ln->params.sos);

        c->trdt = cpu_to_le32(70000);
        c->trdm = cpu_to_le32(100000);
        c->tprt = cpu_to_le32(1900000);
        c->tprm = cpu_to_le32(3500000);
        c->tbet = cpu_to_le32(3000000);
        c->tbem = cpu_to_le32(3000000);

        switch(c->num_pln) {
            case 1:
                c->mpos = cpu_to_le32(0x10101); /* single plane */
                break;
            case 2:
                c->mpos = cpu_to_le32(0x20202); /* dual plane */
                break;
            case 4:
                c->mpos = cpu_to_le32(0x40404); /* quad plane */
                break;
            default:
                error_report("nvme: Invalid plane mode\n");
                return -EINVAL;
        }

        nr_total_blocks = c->num_blk * c->num_pln * c->num_lun;
        c->cpar = cpu_to_le16(0);
        c->mccap = 1;
        ns->bbtbl = qemu_blockalign(blk_bs(n->conf.blk), nr_total_blocks);
        memset(ns->bbtbl, 0, nr_total_blocks);

        ret = (lightnvm_read_bbtbl(ns, nr_total_blocks, 0, ns->bbtbl));
        if (ret)
            return ret;

        /* We devide the address space linearly to be able to fit into the 4KB
         * sectors that the nvme driver divides the backend file. We do the
         * division in LUNS - BLOCKS - PLANES - PAGES - SECTORS.
         *
         * For example a quad plane configuration is layed out as:
         * -----------------------------------------------------------
         * |                        QUAD PLANE                       |
         * -------------- -------------- -------------- --------------
         * |   LUN 00   | |   LUN 01   | |   LUN 02   | |   LUN 03   |
         * -------------- -------------- -------------- --------------
         * |   BLOCKS            |          ...          |   BLOCKS  |
         * ----------------------
         * |   PLANES   |              ...               |   PLANES  |
         * -------------                                 -------------
         * | PAGES |                 ...                 |   PAGES   |
         * -----------------------------------------------------------
         * |                        ALL SECTORS                      |
         * -----------------------------------------------------------
         */

        /* calculated values */
        ln->params.sec_per_pl = ln->params.sec_per_pg * c->num_pln;
        ln->params.sec_per_blk = ln->params.sec_per_pl * ln->params.pgs_per_blk;
        ln->params.sec_per_lun = ln->params.sec_per_blk * c->num_blk;
        ln->params.total_secs = ln->params.sec_per_lun * c->num_lun;

        /* Address format */
        ln->ppaf.blk_offset = 0;
        ln->ppaf.pg_offset = ln->id_ctrl.ppaf.blk_len;
        ln->ppaf.sec_offset = ln->ppaf.pg_offset + ln->id_ctrl.ppaf.pg_len;
        ln->ppaf.pln_offset = ln->ppaf.sec_offset + ln->id_ctrl.ppaf.sect_len;
        ln->ppaf.lun_offset = ln->ppaf.pln_offset + ln->id_ctrl.ppaf.pln_len;
        ln->ppaf.ch_offset = ln->ppaf.lun_offset + ln->id_ctrl.ppaf.lun_len;
	ln->ppaf.blk_mask = ((1 << ln->id_ctrl.ppaf.blk_len) - 1);
	ln->ppaf.pg_mask = ((1 << ln->id_ctrl.ppaf.pg_len) - 1) <<
							ln->ppaf.pg_offset;
	ln->ppaf.sec_mask = ((1 << ln->id_ctrl.ppaf.sect_len) - 1) <<
                                                        ln->ppaf.sec_offset;
	ln->ppaf.pln_mask = ((1 << ln->id_ctrl.ppaf.pln_len) - 1) <<
							ln->ppaf.pln_offset;
	ln->ppaf.lun_mask = ((1 << ln->id_ctrl.ppaf.lun_len) -1) <<
							ln->ppaf.lun_offset;
	ln->ppaf.ch_mask = ((1 << ln->id_ctrl.ppaf.ch_len) - 1) <<
							ln->ppaf.ch_offset;
    }

    if (!ln->bb_tbl_name) {
        ln->bb_auto_gen = 1;
        ln->bb_tbl_name = malloc(13);
        if (!ln->bb_tbl_name)
            return -ENOMEM;
        strncpy(ln->bb_tbl_name, "bbtable.qemu\0", 13);
    } else {
        ln->bb_auto_gen = 0;
    }

    if (!ln->meta_name) {
        ln->meta_auto_gen = 1;
        ln->meta_name = malloc(10);
        if (!ln->meta_name)
            return -ENOMEM;
        strncpy(ln->meta_name, "meta.qemu\0", 10);
    } else {
        ln->meta_auto_gen = 0;
    }

    ln->metadata = fopen(ln->meta_name, "w+");
    if (!ln->metadata) {
        error_report("nvme: could not open metadata file: %s\n", ln->meta_name);
        return -EEXIST;
    }

    ln->int_meta_size = 4;

    ret = (n->lightnvm_ctrl.read_l2p_tbl) ? lightnvm_read_tbls(n) : 0;
    if (ret) {
        error_report("nvme: cannot read l2p table\n");
        return ret;
    }

    return 0;
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
    if (lightnvm_dev(n)) {
        NVME_CAP_SET_LIGHTNVM(n->bar.cap, 1);
        lightnvm_init_id_ctrl(&n->lightnvm_ctrl);
    }
    NVME_CAP_SET_MPSMIN(n->bar.cap, n->mpsmin);
    NVME_CAP_SET_MPSMAX(n->bar.cap, n->mpsmax);

    if (n->cmbsz)
        n->bar.vs = 0x00010200;
    else
        n->bar.vs = 0x00010100;
    n->bar.intmc = n->bar.intms = 0;
    n->temperature = NVME_TEMPERATURE;
}

static void nvme_init_pci(NvmeCtrl *n)
{
    uint8_t *pci_conf = n->parent_obj.config;

    pci_conf[PCI_INTERRUPT_PIN] = 1;
    pci_config_set_prog_interface(pci_conf, 0x2);
    pci_config_set_vendor_id(pci_conf, n->vid);
    pci_config_set_device_id(pci_conf, n->did);
    pci_config_set_class(pci_conf, PCI_CLASS_STORAGE_EXPRESS);
    pcie_endpoint_cap_init(&n->parent_obj, 0x80);

    memory_region_init_io(&n->iomem, OBJECT(n), &nvme_mmio_ops, n, "nvme",
        n->reg_size);
    pci_register_bar(&n->parent_obj, 0,
        PCI_BASE_ADDRESS_SPACE_MEMORY | PCI_BASE_ADDRESS_MEM_TYPE_64,
        &n->iomem);
    msix_init_exclusive_bar(&n->parent_obj, n->num_queues, 4);
    msi_init(&n->parent_obj, 0x50, 32, true, false);

    if (n->cmbsz) {

        n->bar.cmbloc = n->cmbloc;
        n->bar.cmbsz  = n->cmbsz;

        n->cmbuf = g_malloc0(NVME_CMBSZ_GETSIZE(n->bar.cmbsz));
        memory_region_init_io(&n->ctrl_mem, OBJECT(n), &nvme_cmb_ops, n, "nvme-cmb",
                              NVME_CMBSZ_GETSIZE(n->bar.cmbsz));
        pci_register_bar(&n->parent_obj, NVME_CMBLOC_BIR(n->bar.cmbloc),
            PCI_BASE_ADDRESS_SPACE_MEMORY | PCI_BASE_ADDRESS_MEM_TYPE_64,
            &n->ctrl_mem);

    }
}

static int nvme_init(PCIDevice *pci_dev)
{
    NvmeCtrl *n = NVME(pci_dev);
    int64_t bs_size;

    blkconf_serial(&n->conf, &n->serial);
    if (nvme_check_constraints(n)) {
        return -1;
    }

    bs_size = blk_getlength(n->conf.blk);
    if (bs_size < 0) {
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
    n->features.int_vector_config = g_malloc0(n->num_queues *
        sizeof(*n->features.int_vector_config));

    nvme_init_pci(n);
    nvme_init_ctrl(n);
    nvme_init_namespaces(n);
    if (lightnvm_dev(n))
        return lightnvm_init(n);
    return 0;
}

static void lightnvm_exit(NvmeCtrl *n)
{
    LnvmCtrl *ln = &n->lightnvm_ctrl;

    if (ln->bb_auto_gen)
        free(ln->bb_tbl_name);
    if (ln->meta_auto_gen)
        free(ln->meta_name);
    fclose(n->lightnvm_ctrl.bb_tbl);
    fclose(n->lightnvm_ctrl.metadata);
    n->lightnvm_ctrl.bb_tbl = NULL;
    n->lightnvm_ctrl.metadata = NULL;
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
    memory_region_unref(&n->iomem);
    if (n->cmbsz) {
        memory_region_unref(&n->ctrl_mem);
    }

    if (lightnvm_dev(n)) {
        lightnvm_exit(n);
    }
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
    DEFINE_PROP_UINT8("mdts", NvmeCtrl, mdts, 10),
    DEFINE_PROP_UINT8("cqr", NvmeCtrl, cqr, 1),
    DEFINE_PROP_UINT8("vwc", NvmeCtrl, vwc, 0),
    DEFINE_PROP_UINT8("intc", NvmeCtrl, intc, 0),
    DEFINE_PROP_UINT8("intc_thresh", NvmeCtrl, intc_thresh, 0),
    DEFINE_PROP_UINT8("intc_time", NvmeCtrl, intc_time, 0),
    DEFINE_PROP_UINT8("mpsmin", NvmeCtrl, mpsmin, 0),
    DEFINE_PROP_UINT8("mpsmax", NvmeCtrl, mpsmax, 0),
    DEFINE_PROP_UINT8("nlbaf", NvmeCtrl, nlbaf, 5),
    DEFINE_PROP_UINT8("lba_index", NvmeCtrl, lba_index, 3),
    DEFINE_PROP_UINT8("extended", NvmeCtrl, extended, 0),
    DEFINE_PROP_UINT8("dpc", NvmeCtrl, dpc, 0),
    DEFINE_PROP_UINT8("dps", NvmeCtrl, dps, 0),
    DEFINE_PROP_UINT8("mc", NvmeCtrl, mc, 0),
    DEFINE_PROP_UINT8("meta", NvmeCtrl, meta, 0),
    DEFINE_PROP_UINT32("cmbsz", NvmeCtrl, cmbsz, 0),
    DEFINE_PROP_UINT32("cmbloc", NvmeCtrl, cmbloc, 0),
    DEFINE_PROP_UINT16("oacs", NvmeCtrl, oacs, NVME_OACS_FORMAT),
    DEFINE_PROP_UINT16("oncs", NvmeCtrl, oncs, NVME_ONCS_DSM),
    DEFINE_PROP_UINT16("vid", NvmeCtrl, vid, 0x1d1d),
    DEFINE_PROP_UINT16("did", NvmeCtrl, did, 0x1f1f),
    DEFINE_PROP_UINT8("lver", NvmeCtrl, lightnvm_ctrl.id_ctrl.ver_id, 0),
    DEFINE_PROP_UINT32("ll2pmode", NvmeCtrl, lightnvm_ctrl.id_ctrl.dom, 1),
    DEFINE_PROP_UINT16("lsec_size", NvmeCtrl, lightnvm_ctrl.params.sec_size, 4096),
    DEFINE_PROP_UINT8("lsecs_per_pg", NvmeCtrl, lightnvm_ctrl.params.sec_per_pg, 1),
    DEFINE_PROP_UINT16("lpgs_per_blk", NvmeCtrl, lightnvm_ctrl.params.pgs_per_blk, 256),
    DEFINE_PROP_UINT8("lmax_sec_per_rq", NvmeCtrl, lightnvm_ctrl.params.max_sec_per_rq, 64),
    DEFINE_PROP_UINT8("lmtype", NvmeCtrl, lightnvm_ctrl.params.mtype, 0),
    DEFINE_PROP_UINT8("lfmtype", NvmeCtrl, lightnvm_ctrl.params.fmtype, 0),
    DEFINE_PROP_UINT8("lnum_ch", NvmeCtrl, lightnvm_ctrl.params.num_ch, 1),
    DEFINE_PROP_UINT8("lnum_lun", NvmeCtrl, lightnvm_ctrl.params.num_lun, 1),
    DEFINE_PROP_UINT8("lnum_pln", NvmeCtrl, lightnvm_ctrl.params.num_pln, 1),
    DEFINE_PROP_UINT8("lreadl2ptbl", NvmeCtrl, lightnvm_ctrl.read_l2p_tbl, 1),
    DEFINE_PROP_STRING("lbbtable", NvmeCtrl, lightnvm_ctrl.bb_tbl_name),
    DEFINE_PROP_STRING("lmetadata", NvmeCtrl, lightnvm_ctrl.meta_name),
    DEFINE_PROP_UINT16("lmetasize", NvmeCtrl, lightnvm_ctrl.params.sos, 16),
    DEFINE_PROP_UINT8("lbbfrequency", NvmeCtrl, lightnvm_ctrl.bb_gen_freq, 0),
    DEFINE_PROP_UINT32("lb_err_write", NvmeCtrl, lightnvm_ctrl.err_write, 0),
    DEFINE_PROP_UINT32("ln_err_write", NvmeCtrl, lightnvm_ctrl.n_err_write, 0),
    DEFINE_PROP_UINT8("ldebug", NvmeCtrl, lightnvm_ctrl.debug, 0),
    DEFINE_PROP_UINT8("lstrict", NvmeCtrl, lightnvm_ctrl.strict, 0),
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
    pc->vendor_id = 0x1d1d;
    pc->is_express = 1;

    set_bit(DEVICE_CATEGORY_STORAGE, dc->categories);
    dc->desc = "Non-Volatile Memory Express";
    dc->props = nvme_props;
    dc->vmsd = &nvme_vmstate;
}

static void nvme_get_bootindex(Object *obj, Visitor *v, void *opaque,
                                  const char *name, Error **errp)
{
    NvmeCtrl *s = NVME(obj);

    visit_type_int32(v, &s->conf.bootindex, name, errp);
}

static void nvme_set_bootindex(Object *obj, Visitor *v, void *opaque,
                                  const char *name, Error **errp)
{
    NvmeCtrl *s = NVME(obj);
    int32_t boot_index;
    Error *local_err = NULL;

    visit_type_int32(v, &boot_index, name, &local_err);
    if (local_err) {
        goto out;
    }
    /* check whether bootindex is present in fw_boot_order list  */
    check_boot_index(boot_index, &local_err);
    if (local_err) {
        goto out;
    }
    /* change bootindex to a new one */
    s->conf.bootindex = boot_index;

out:
    if (local_err) {
        error_propagate(errp, local_err);
    }
}

static void nvme_instance_init(Object *obj)
{
    object_property_add(obj, "bootindex", "int32",
                        nvme_get_bootindex,
                        nvme_set_bootindex, NULL, NULL, NULL);
    object_property_set_int(obj, -1, "bootindex", NULL);
}

static const TypeInfo nvme_info = {
    .name          = "nvme",
    .parent        = TYPE_PCI_DEVICE,
    .instance_size = sizeof(NvmeCtrl),
    .class_init    = nvme_class_init,
    .instance_init = nvme_instance_init,
};

static void nvme_register_types(void)
{
    type_register_static(&nvme_info);
}

type_init(nvme_register_types)
