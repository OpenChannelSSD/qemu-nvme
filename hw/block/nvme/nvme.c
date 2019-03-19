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
 *  namespaces=<int>      : Namespaces to make out of the backing storage,
 *                          Default:1
 *  num_queues=<int>      : Number of possible IO Queues, Default:64
 *  cmb_size_mb=<int>     : Size of CMB in MBs, Default:0
 *  entries=<int>         : Maximum number of Queue entires possible,
 *                          Default:0x7ff
 *  max_cqes=<int>        : Maximum completion queue entry size, Default:0x4
 *  max_sqes=<int>        : Maximum submission queue entry size, Default:0x6
 *  mpsmin=<int>          : Minimum page size supported, Default:0
 *  mpsmax=<int>          : Maximum page size supported, Default:0
 *  stride=<int>          : Doorbell stride, Default:0
 *  aerl=<int>            : Async event request limit, Default:3
 *  acl=<int>             : Abort command limit, Default:3
 *  elpe=<int>            : Error log page entries, Default:3
 *  mdts=<int>            : Maximum data transfer size, Default:7
 *  cqr=<int>             : Contiguous queues required, Default:1
 *  vwc=<int>             : Volatile write cache enabled, Default:0
 *  intc=<int>            : Interrupt configuration disabled, Default:0
 *  intc_thresh=<int>     : Interrupt coalesce threshold, Default:0
 *  intc_ttime=<int>      : Interrupt coalesce time 100's of usecs, Default:0
 *  extended=<int>        : Use extended-lba for meta-data, Default:0
 *  dpc=<int>             : Data protection capabilities, Default:0
 *  dps=<int>             : Data protection settings, Default:0
 *  mc=<int>              : Meta-data capabilities, Default:0x2
 *  ms=<int>              : Meta-data size in bytes, Default:16, Max:64
 *  ms_max=<int>          : Maximum meta-data size in bytes, Default:64
 *  dlfeat=<int>          : Control DLFEAT, Default:0x1
 *  oncs=<oncs>           : Optional NVMe command support, Default:DSM
 *  oacs=<oacs>           : Optional Admin command support, Default:Format
 *  dialect=<dialect>     : Set the dialect to implement, Default: 0x1,
 *                          Supported: {0x0: NVMe v1.3, 0x1: OCSSD v2.0}
 *
 * LightNVM specific options:
 *
 *  lmccap=<int>          : Media and Controller Capabilities (MCCAP),
 *                          Default:0
 *  lws_min=<int>         : Mininum write size for device in sectors,
 *                          Default:4
 *  lws_opt=<int>         : Optimal write size for device in sectors,
 *                          Default:8
 *  lmw_cunits=<int>      : Number of written sectors required in chunk before
 *                          read, Default:32
 *  lchunkstate=<file>    : Load state table from file destination (Provide
 *                          path to file. If no file is provided a state table
 *                          will be generated.
 *  lchunkinfo_size       : Size of the chunk info log page.
 *                          Default:4194304 (4 MB)
 *  lresetfail=<file>     : Reset fail injection configuration file.
 *  lwritefail=<file>     : Write fail injection configuration file.
 *  ldebug                : Enable LightNVM debugging, Default:0 (disabled)
 *  learly_reset          : Allow early resets (reset open chunks),
 *                          Default:1 (enabled)
 *  lsgl_lbal             : If DPTR is an SGL, interpret LBAL as an SGL too,
 *                          Default:0 (disabled)
 *
 * Parameters will be verified against conflicting capabilities and attributes
 * and fail to load if there is a conflict or a configuration the emulated
 * device is unable to handle.
 *
 * Note cmb_size_mb denotes size of CMB in MB. CMB is assumed to be at
 * offset 0 in BAR2 and supports only WDS, RDS and SQS for now.
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

#include "qemu/osdep.h"
#include "qemu/units.h"
#include "hw/block/block.h"
#include "hw/hw.h"
#include "hw/pci/msix.h"
#include "hw/pci/pci.h"
#include "sysemu/sysemu.h"
#include "qapi/error.h"
#include "qapi/visitor.h"
#include "sysemu/block-backend.h"

#include "qemu/log.h"
#include "qemu/cutils.h"
#include "trace.h"

#include "nvme.h"
#include "lightnvm.h"

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

#define NVME_DIALECT_NVME13 0x0
#define NVME_DIALECT_OCSSD20 0x1

#define NVME_GUEST_ERR(trace, fmt, ...) \
    do { \
        (trace_##trace)(__VA_ARGS__); \
        qemu_log_mask(LOG_GUEST_ERROR, #trace \
            " in %s: " fmt "\n", __func__, ## __VA_ARGS__); \
    } while (0)

static void nvme_process_sq(void *opaque);

static inline uint8_t nvme_addr_is_cmb(NvmeCtrl *n, hwaddr addr)
{
    return n->cmbsz && addr >= n->ctrl_mem.addr &&
        addr < n ->ctrl_mem.addr + int128_get64(n->ctrl_mem.size);
}

void nvme_addr_read(NvmeCtrl *n, hwaddr addr, void *buf, int size)
{
    if (nvme_addr_is_cmb(n, addr)) {
        memcpy(buf, (void *)&n->cmbuf[addr - n->ctrl_mem.addr], size);

        return;
    }

    pci_dma_read(&n->parent_obj, addr, buf, size);
}

void nvme_addr_write(NvmeCtrl *n, hwaddr addr, void *buf, int size)
{
    if (nvme_addr_is_cmb(n, addr)) {
        memcpy((void *)&n->cmbuf[addr - n->ctrl_mem.addr], buf, size);

        return;
    }

    pci_dma_write(&n->parent_obj, addr, buf, size);
}

static int nvme_check_sqid(NvmeCtrl *n, uint16_t sqid)
{
    return sqid < n->params.num_queues && n->sq[sqid] != NULL ? 0 : -1;
}

static int nvme_check_cqid(NvmeCtrl *n, uint16_t cqid)
{
    return cqid < n->params.num_queues && n->cq[cqid] != NULL ? 0 : -1;
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

static void nvme_irq_check(NvmeCtrl *n)
{
    if (msix_enabled(&(n->parent_obj))) {
        return;
    }
    if (~n->bar.intms & n->irq_status) {
        pci_irq_assert(&n->parent_obj);
    } else {
        pci_irq_deassert(&n->parent_obj);
    }
}

static void nvme_irq_assert(NvmeCtrl *n, NvmeCQueue *cq)
{
    if (cq->irq_enabled) {
        if (msix_enabled(&(n->parent_obj))) {
            trace_nvme_irq_msix(cq->vector);
            msix_notify(&(n->parent_obj), cq->vector);
        } else {
            trace_nvme_irq_pin();
            assert(cq->cqid < 64);
            n->irq_status |= 1 << cq->cqid;
            nvme_irq_check(n);
        }
    } else {
        trace_nvme_irq_masked();
    }
}

static void nvme_irq_deassert(NvmeCtrl *n, NvmeCQueue *cq)
{
    if (cq->irq_enabled) {
        if (msix_enabled(&(n->parent_obj))) {
            return;
        } else {
            assert(cq->cqid < 64);
            n->irq_status &= ~(1 << cq->cqid);
            nvme_irq_check(n);
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
    uint64_t *prp_list = g_malloc0_n(total_prps, sizeof(*prp_list));

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

void nvme_set_error_page(NvmeCtrl *n, uint16_t sqid, uint16_t cid,
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
    n->elp_index = (n->elp_index + 1) % n->params.elpe;
    ++n->num_errors;
}

static hwaddr nvme_discontig(uint64_t *dma_addr, uint16_t page_size,
    uint16_t queue_idx, uint16_t entry_size)
{
    uint16_t entries_per_page = page_size / entry_size;
    uint16_t prp_index = queue_idx / entries_per_page;
    uint16_t index_in_prp = queue_idx % entries_per_page;

    return dma_addr[prp_index] + index_in_prp * entry_size;
}

NvmeBlockBackendRequest *nvme_blk_req_new(NvmeCtrl *n, NvmeRequest *req)
{
    NvmeBlockBackendRequest *blk_req = g_malloc0(sizeof(*blk_req));
    blk_req->req = req;

    if (req->cmb) {
        qemu_iovec_init(&blk_req->iov, 1);
    } else {
        pci_dma_sglist_init(&blk_req->qsg, &n->parent_obj, 1);
    }

    return blk_req;
}

static void nvme_blk_req_destroy(NvmeBlockBackendRequest *blk_req) {
    if (blk_req->qsg.nalloc) {
        qemu_sglist_destroy(&blk_req->qsg);
    }

    if (blk_req->iov.nalloc) {
        qemu_iovec_destroy(&blk_req->iov);
    }

    g_free(blk_req);
}

static uint16_t nvme_map_prp(NvmeCtrl *n, QEMUSGList *qsg, uint64_t prp1,
    uint64_t prp2, uint32_t len, NvmeRequest *req)
{
    hwaddr trans_len = n->page_size - (prp1 % n->page_size);
    trans_len = MIN(len, trans_len);
    int num_prps = (len >> n->page_bits) + 1;

    trace_nvme_map_prp(req->cmd_opcode, trans_len, len, prp1, prp2, num_prps);

    if (unlikely(!prp1)) {
        trace_nvme_err_invalid_prp();
        return NVME_INVALID_FIELD | NVME_DNR;
    }

    if (nvme_addr_is_cmb(n, prp1)) {
        NvmeSQueue *sq = req->sq;
        if (!(sq->phys_contig && nvme_addr_is_cmb(n, sq->dma_addr))) {
            return NVME_INVALID_USE_OF_CMB | NVME_DNR;
        }

        req->cmb = true;
    } else {
        req->cmb = false;
    }

    pci_dma_sglist_init(qsg, &n->parent_obj, num_prps);

    qemu_sglist_add(qsg, prp1, trans_len);

    len -= trans_len;
    if (len) {
        if (unlikely(!prp2)) {
            trace_nvme_err_invalid_prp2_missing();
            goto unmap;
        }

        if (req->cmb && !nvme_addr_is_cmb(n, prp2)) {
            return NVME_INVALID_USE_OF_CMB | NVME_DNR;
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

                if (req->cmb && !nvme_addr_is_cmb(n, prp_ent)) {
                    return NVME_INVALID_USE_OF_CMB | NVME_DNR;
                }

                if (i == n->max_prp_ents - 1 && len > n->page_size) {
                    if (unlikely(!prp_ent || prp_ent & (n->page_size - 1))) {
                        trace_nvme_err_invalid_prplist_ent(prp_ent);
                        goto unmap;
                    }

                    i = 0;
                    nents = (len + n->page_size - 1) >> n->page_bits;
                    prp_trans = MIN(n->max_prp_ents, nents) * sizeof(uint64_t);
                    nvme_addr_read(n, prp_ent, (void *)prp_list, prp_trans);
                    prp_ent = le64_to_cpu(prp_list[i]);
                }

                if (unlikely(!prp_ent || prp_ent & (n->page_size - 1))) {
                    trace_nvme_err_invalid_prplist_ent(prp_ent);
                    goto unmap;
                }

                trans_len = MIN(len, n->page_size);
                qemu_sglist_add(qsg, prp_ent, trans_len);

                len -= trans_len;
                i++;
            }
        } else {
            if (unlikely(prp2 & (n->page_size - 1))) {
                trace_nvme_err_invalid_prp2_align(prp2);
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

static uint16_t nvme_map_sgl(NvmeCtrl *n, QEMUSGList *qsg,
    NvmeSglDescriptor sgl, uint32_t len, NvmeRequest *req)
{
    NvmeSglDescriptor *sgl_descriptors;
    uint64_t nsgld;

    int cmb = 0;

    switch (le64_to_cpu(sgl.generic.type)) {
    case SGL_DESCR_TYPE_DATA_BLOCK:
        sgl_descriptors = &sgl;
        nsgld = 1;

        break;

    case SGL_DESCR_TYPE_LAST_SEGMENT:
        sgl_descriptors = g_malloc0(le64_to_cpu(sgl.unkeyed.len));
        nsgld = le64_to_cpu(sgl.unkeyed.len) / sizeof(NvmeSglDescriptor);

        if (nvme_addr_is_cmb(n, sgl.addr)) {
            cmb = 1;
        }

        nvme_addr_read(n, le64_to_cpu(sgl.addr), sgl_descriptors,
            le64_to_cpu(sgl.unkeyed.len));

        break;

    default:
        return NVME_SGL_DESCRIPTOR_TYPE_INVALID | NVME_DNR;
    }

    if (nvme_addr_is_cmb(n, le64_to_cpu(sgl_descriptors[0].addr))) {
        if (!cmb) {
            return NVME_INVALID_USE_OF_CMB | NVME_DNR;
        }

        req->cmb = true;
    } else {
        if (cmb) {
            return NVME_INVALID_USE_OF_CMB | NVME_DNR;
        }

        req->cmb = false;
    }

    pci_dma_sglist_init(qsg, &n->parent_obj, nsgld);

    for (int i = 0; i < nsgld; i++) {
        uint64_t addr;
        uint32_t trans_len;

        if (len == 0) {
            if (!NVME_CTRL_SGLS_EXCESS_LENGTH(n->sgls)) {
                qemu_sglist_destroy(qsg);

                return NVME_DATA_SGL_LENGTH_INVALID | NVME_DNR;
            }

            break;
        }

        addr = le64_to_cpu(sgl_descriptors[i].addr);
        trans_len = MIN(len, le64_to_cpu(sgl_descriptors[i].unkeyed.len));

        if (req->cmb && !nvme_addr_is_cmb(n,addr)) {
            return NVME_INVALID_USE_OF_CMB | NVME_DNR;
        }

        qemu_sglist_add(qsg, addr, trans_len);

        len -= trans_len;
    }

    if (nsgld > 1) {
        g_free(sgl_descriptors);
    }

    return NVME_SUCCESS;
}

static uint16_t nvme_blk_setup(NvmeCtrl *n, QEMUSGList *qsg,
    uint64_t blk_offset, uint32_t unit_len, NvmeRequest *req)
{
    NvmeNamespace *ns = req->ns;
    NvmeBlockBackendRequest *blk_req, *blk_req_predef;
    size_t curr_offset = 0;
    int curr_sge = 0;

    uint64_t soffset = n->dialect.blk_idx(n, ns, req->slba);

    if (NULL == (blk_req = nvme_blk_req_new(n, req))) {
        return NVME_INTERNAL_DEV_ERROR;
    }

    blk_req->slba = req->slba;
    blk_req->nlb = req->nlb;
    blk_req->blk_offset = blk_offset + soffset * unit_len;

    if (req->is_write || req->predef == -1) {
        ScatterGatherEntry *tmp;

        if (blk_req->qsg.nalloc < qsg->nsg) {
            tmp = g_realloc(blk_req->qsg.sg,
                qsg->nalloc * sizeof(ScatterGatherEntry));
            if (!tmp) {
                nvme_blk_req_destroy(blk_req);
                return NVME_INTERNAL_DEV_ERROR;
            }

            blk_req->qsg.sg = tmp;
        }

        memcpy(blk_req->qsg.sg, qsg->sg,
            qsg->nsg * sizeof(ScatterGatherEntry));

        blk_req->qsg.nalloc = qsg->nalloc;
        blk_req->qsg.nsg = qsg->nsg;
        blk_req->qsg.size = qsg->size;

        goto out;
    }

    blk_req->nlb = req->predef - req->slba;
    qemu_sglist_yank(qsg, &blk_req->qsg, &curr_sge, &curr_offset,
        blk_req->nlb * unit_len);

    if (ns->id_ns.dlfeat) {
        for (uint16_t i = 0; i < (req->nlb - blk_req->nlb); i++) {
            if (NULL == (blk_req_predef = nvme_blk_req_new(n, req))) {
                return NVME_INTERNAL_DEV_ERROR;
            }

            blk_req_predef->slba = req->predef + i;
            blk_req_predef->nlb = 1;
            blk_req_predef->blk_offset = NVME_NS_PREDEF_BLK_OFFSET(n, ns);

            qemu_sglist_yank(qsg, &blk_req_predef->qsg, &curr_sge,
                &curr_offset, unit_len);

            QTAILQ_INSERT_TAIL(&req->blk_req_tailq_head, blk_req_predef,
                blk_req_tailq);
        }
    }

out:
    QTAILQ_INSERT_TAIL(&req->blk_req_tailq_head, blk_req, blk_req_tailq);

    return NVME_SUCCESS;
}

uint16_t nvme_blk_map(NvmeCtrl *n, NvmeCmd *cmd, NvmeRequest *req,
    NvmeBlockSetupFn blk_setup)
{
    NvmeNamespace *ns = req->ns;
    uint16_t err;

    QEMUSGList qsg;
    NvmeSglDescriptor sgl;

    uint32_t unit_len = 1 << NVME_ID_NS_LBADS(ns);
    uint32_t len = req->nlb * unit_len;
    uint32_t meta_unit_len = NVME_ID_NS_MS(ns);
    uint32_t meta_len = req->nlb * meta_unit_len;

    if (cmd->psdt) {
        err = nvme_map_sgl(n, &qsg, cmd->dptr.sgl, len, req);
        if (err) {
            nvme_set_error_page(n, req->sq->sqid, req->cqe.cid, err,
                offsetof(NvmeRwCmd, dptr.sgl), 0, req->ns->id);
            return err;
        }
    } else {
        uint64_t prp1 = le64_to_cpu(cmd->dptr.prp.prp1);
        uint64_t prp2 = le64_to_cpu(cmd->dptr.prp.prp2);

        err = nvme_map_prp(n, &qsg, prp1, prp2, len, req);
        if (err) {
            nvme_set_error_page(n, req->sq->sqid, req->cqe.cid, err,
                offsetof(NvmeRwCmd, dptr.prp.prp1), 0, req->ns->id);
            return err;
        }
    }

    err = blk_setup(n, &qsg, ns->blk.data, unit_len, req);
    if (err) {
        return err;
    }

    qemu_sglist_reset(&qsg);

    if (cmd->mptr) {
        if (cmd->psdt & PSDT_SGL_MPTR_SGL) {
            nvme_addr_read(n, le64_to_cpu(cmd->mptr), &sgl,
                sizeof(NvmeSglDescriptor));

            err = nvme_map_sgl(n, &qsg, sgl, meta_len, req);
            if (err) {
                // nvme_map_sgl does not know if it was mapping a data or meta
                // data SGL, so fix the error code if needed.
                if (err & NVME_DATA_SGL_LENGTH_INVALID) {
                    err &= ~NVME_DATA_SGL_LENGTH_INVALID;
                    err |= NVME_METADATA_SGL_LENGTH_INVALID;
                }

                nvme_set_error_page(n, req->sq->sqid, req->cqe.cid, err,
                    offsetof(NvmeRwCmd, mptr), 0, req->ns->id);
                return err;
            }
        } else {
            qemu_sglist_add(&qsg, le64_to_cpu(cmd->mptr), meta_len);
        }

        err = blk_setup(n, &qsg, ns->blk.meta, meta_unit_len, req);
        if (err) {
            return err;
        }
    }

    return NVME_SUCCESS;
}

static void dma_to_cmb(NvmeCtrl *n, QEMUSGList *qsg, QEMUIOVector *iov)
{
    for (int i = 0; i < qsg->nsg; i++) {
        void *addr = &n->cmbuf[qsg->sg[i].base - n->ctrl_mem.addr];
        qemu_iovec_add(iov, addr, qsg->sg[i].len);
    }
}

static uint16_t nvme_dma_write_prp(NvmeCtrl *n, uint8_t *ptr, uint32_t len,
    uint64_t prp1, uint64_t prp2, NvmeRequest *req)
{
    QEMUSGList qsg;
    uint16_t err = NVME_SUCCESS;

    err = nvme_map_prp(n, &qsg, prp1, prp2, len, req);
    if (err) {
        return err;
    }

    if (req->cmb) {
        QEMUIOVector iov;

        qemu_iovec_init(&iov, qsg.nsg);
        dma_to_cmb(n, &qsg, &iov);

        if (unlikely(qemu_iovec_to_buf(&iov, 0, ptr, len) != len)) {
            trace_nvme_err_invalid_dma();
            err = NVME_INVALID_FIELD | NVME_DNR;
        }

        qemu_iovec_destroy(&iov);

        return err;
    }

    if (unlikely(dma_buf_write(ptr, len, &qsg))) {
        trace_nvme_err_invalid_dma();
        err = NVME_INVALID_FIELD | NVME_DNR;
    }

    qemu_sglist_destroy(&qsg);

    return err;
}

static uint16_t nvme_dma_write_sgl(NvmeCtrl *n, uint8_t *ptr, uint32_t len,
    NvmeSglDescriptor sgl, NvmeRequest *req)
{
    QEMUSGList qsg;
    uint16_t err = NVME_SUCCESS;

    err = nvme_map_sgl(n, &qsg, sgl, len, req);
    if (err) {
        return err;
    }

    if (req->cmb) {
        QEMUIOVector iov;

        qemu_iovec_init(&iov, qsg.nsg);
        dma_to_cmb(n, &qsg, &iov);

        if (unlikely(qemu_iovec_to_buf(&iov, 0, ptr, len) != len)) {
            trace_nvme_err_invalid_dma();
            err = NVME_INVALID_FIELD | NVME_DNR;
        }

        qemu_iovec_destroy(&iov);

        return err;
    }

    if (unlikely(dma_buf_write(ptr, len, &qsg))) {
        trace_nvme_err_invalid_dma();
        err = NVME_INVALID_FIELD | NVME_DNR;
    }

    qemu_sglist_destroy(&qsg);

    return err;
}

uint16_t nvme_dma_write(NvmeCtrl *n, uint8_t *ptr, uint32_t len, NvmeCmd *cmd,
    NvmeRequest *req)
{
    if (cmd->psdt) {
        return nvme_dma_write_sgl(n, ptr, len, cmd->dptr.sgl, req);
    }

    uint64_t prp1 = le64_to_cpu(cmd->dptr.prp.prp1);
    uint64_t prp2 = le64_to_cpu(cmd->dptr.prp.prp2);

    return nvme_dma_write_prp(n, ptr, len, prp1, prp2, req);
}

static uint16_t nvme_dma_read_prp(NvmeCtrl *n, uint8_t *ptr, uint32_t len,
    uint64_t prp1, uint64_t prp2, NvmeRequest *req)
{
    QEMUSGList qsg;
    uint16_t err = NVME_SUCCESS;

    err = nvme_map_prp(n, &qsg, prp1, prp2, len, req);
    if (err) {
        return err;
    }

    if (req->cmb) {
        QEMUIOVector iov;

        qemu_iovec_init(&iov, qsg.nsg);
        dma_to_cmb(n, &qsg, &iov);

        if (unlikely(qemu_iovec_from_buf(&iov, 0, ptr, len) != len)) {
            trace_nvme_err_invalid_dma();
            err = NVME_INVALID_FIELD | NVME_DNR;
        }

        qemu_iovec_destroy(&iov);

        return err;
    }

    if (unlikely(dma_buf_read(ptr, len, &qsg))) {
        trace_nvme_err_invalid_dma();
        err = NVME_INVALID_FIELD | NVME_DNR;
    }

    qemu_sglist_destroy(&qsg);

    return err;
}

uint16_t nvme_dma_read_sgl(NvmeCtrl *n, uint8_t *ptr, uint32_t len,
    NvmeSglDescriptor sgl, NvmeRequest *req)
{
    QEMUSGList qsg;
    uint16_t err = NVME_SUCCESS;

    err = nvme_map_sgl(n, &qsg, sgl, len, req);
    if (err) {
        return err;
    }

    if (req->cmb) {
        QEMUIOVector iov;

        qemu_iovec_init(&iov, qsg.nsg);
        dma_to_cmb(n, &qsg, &iov);

        if (unlikely(qemu_iovec_from_buf(&iov, 0, ptr, len) != len)) {
            trace_nvme_err_invalid_dma();
            err = NVME_INVALID_FIELD | NVME_DNR;
        }

        qemu_iovec_destroy(&iov);

        return err;
    }

    if (unlikely(dma_buf_read(ptr, len, &qsg))) {
        trace_nvme_err_invalid_dma();
        err = NVME_INVALID_FIELD | NVME_DNR;
    }

    qemu_sglist_destroy(&qsg);

    return err;
}

uint16_t nvme_dma_read(NvmeCtrl *n, uint8_t *ptr, uint32_t len,
    NvmeCmd *cmd, NvmeRequest *req)
{
    if (cmd->psdt) {
        return nvme_dma_read_sgl(n, ptr, len, cmd->dptr.sgl, req);
    }

    uint64_t prp1 = le64_to_cpu(cmd->dptr.prp.prp1);
    uint64_t prp2 = le64_to_cpu(cmd->dptr.prp.prp2);

    return nvme_dma_read_prp(n, ptr, len, prp1, prp2, req);
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

    if (n->dialect.post_cqe) {
        n->dialect.post_cqe(n, req);
    }

    cqe->status = cpu_to_le16((req->status << 1) | cq->phase);
    cqe->sq_id = cpu_to_le16(sq->sqid);
    cqe->sq_head = cpu_to_le16(sq->head);
    nvme_addr_write(n, addr, (void *)cqe, sizeof(*cqe));
    nvme_inc_cq_tail(cq);

    QTAILQ_INSERT_TAIL(&sq->req_list, req, entry);
}

static void nvme_post_cqes(void *opaque)
{
    NvmeCQueue *cq = opaque;
    NvmeCtrl *n = cq->ctrl;
    NvmeRequest *req, *next;

    QTAILQ_FOREACH_SAFE(req, &cq->req_list, entry, next) {
        if (nvme_cq_full(cq)) {
            break;
        }
        QTAILQ_REMOVE(&cq->req_list, req, entry);
        nvme_post_cqe(cq, req);
    }
    if (cq->tail != cq->head) {
        nvme_irq_assert(n, cq);
    }
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
        nvme_irq_assert(n, cq);
        if (timer_pending(cq->timer)) {
            timer_del(cq->timer);
        }
    }
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
    NvmeAsyncEvent *event, *next;

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

void nvme_rw_cb(void *opaque, int ret)
{
    NvmeBlockBackendRequest *blk_req = opaque;
    NvmeRequest *req = blk_req->req;
    NvmeSQueue *sq = req->sq;
    NvmeCtrl *n = sq->ctrl;
    NvmeCQueue *cq = n->cq[sq->cqid];
    NvmeNamespace *ns = req->ns;

    trace_nvme_rw_cb(req->cqe.cid);

    QTAILQ_REMOVE(&req->blk_req_tailq_head, blk_req, blk_req_tailq);

    if (!ret) {
        block_acct_done(blk_get_stats(n->conf.blk), &blk_req->acct);

        if (n->dialect.blk_req_epilogue) {
            uint16_t err = n->dialect.blk_req_epilogue(n, ns, blk_req, req);
            if (err) {
                req->status = err;
            }
        }
    } else {
        block_acct_failed(blk_get_stats(n->conf.blk), &blk_req->acct);
        req->status = NVME_INTERNAL_DEV_ERROR | NVME_DNR;
    }

    if (QTAILQ_EMPTY(&req->blk_req_tailq_head)) {
        if (req->status != NVME_SUCCESS) {
            nvme_set_error_page(n, sq->sqid, req->cqe.cid, req->status,
                offsetof(NvmeRwCmd, slba), blk_req->blk_offset, ns->id);
        }

        nvme_enqueue_req_completion(cq, req);
    }

    nvme_blk_req_destroy(blk_req);
}

static uint16_t nvme_flush(NvmeCtrl *n, NvmeCmd *cmd, NvmeRequest *req)
{
    NvmeBlockBackendRequest *blk_req = nvme_blk_req_new(n, req);

    block_acct_start(blk_get_stats(n->conf.blk), &blk_req->acct, 0,
         BLOCK_ACCT_FLUSH);
    blk_req->aiocb = blk_aio_flush(n->conf.blk, nvme_rw_cb, blk_req);

    return NVME_NO_COMPLETE;
}

static uint16_t nvme_write_zeros(NvmeCtrl *n, NvmeCmd *cmd, NvmeRequest *req)
{
    NvmeRwCmd *rw = (NvmeRwCmd *)cmd;
    NvmeBlockBackendRequest *blk_req;
    const uint8_t lbads = NVME_ID_NS_LBADS(req->ns);
    uint64_t slba = le64_to_cpu(rw->slba);
    uint32_t nlb  = le16_to_cpu(rw->nlb) + 1;
    uint64_t data_offset = slba << lbads;
    uint32_t data_count = nlb << lbads;

    if (unlikely(slba + nlb > req->ns->nsze)) {
        trace_nvme_err_invalid_lba_range(slba, nlb, req->ns->nsze);
        return NVME_LBA_RANGE | NVME_DNR;
    }

    blk_req = nvme_blk_req_new(n, req);

    block_acct_start(blk_get_stats(n->conf.blk), &blk_req->acct, 0,
        BLOCK_ACCT_WRITE);

    blk_req->aiocb = blk_aio_pwrite_zeroes(n->conf.blk, data_offset,
        data_count, BDRV_REQ_MAY_UNMAP, nvme_rw_cb, blk_req);

    return NVME_NO_COMPLETE;
}

uint16_t nvme_rw_check_req(NvmeCtrl *n, NvmeCmd *cmd, NvmeRequest *req)
{
    NvmeNamespace *ns = req->ns;
    NvmeRwCmd *rw = (NvmeRwCmd *) cmd;

    uint16_t ctrl = le16_to_cpu(rw->control);
    uint32_t data_size = req->nlb << NVME_ID_NS_LBADS(ns);

    if (n->params.mdts && data_size > n->page_size * (1 << n->params.mdts)) {
        trace_nvme_err_invalid_field(req->cqe.cid, "NLB", "MDTS exceeded");
        nvme_set_error_page(n, req->sq->sqid, req->cqe.cid, NVME_INVALID_FIELD,
            offsetof(NvmeRwCmd, nlb), req->nlb, ns->id);
        return NVME_INVALID_FIELD | NVME_DNR;
    }

    if ((ctrl & NVME_RW_PRINFO_PRACT) && !(ns->id_ns.dps & DPS_TYPE_MASK)) {
        nvme_set_error_page(n, req->sq->sqid, req->cqe.cid, NVME_INVALID_FIELD,
            offsetof(NvmeRwCmd, control), ctrl, ns->id);
        return NVME_INVALID_FIELD | NVME_DNR;
    }

    return NVME_SUCCESS;
}

uint16_t nvme_blk_submit_io(NvmeCtrl *n, NvmeRequest *req)
{
    NvmeBlockBackendRequest *blk_req;

    if (QTAILQ_EMPTY(&req->blk_req_tailq_head)) {
        return NVME_SUCCESS;
    }

    QTAILQ_FOREACH(blk_req, &req->blk_req_tailq_head, blk_req_tailq) {
        if (req->cmb) {
            dma_to_cmb(n, &blk_req->qsg, &blk_req->iov);

            block_acct_start(blk_get_stats(n->conf.blk), &blk_req->acct,
                blk_req->iov.size,
                req->is_write ? BLOCK_ACCT_WRITE : BLOCK_ACCT_READ);

            blk_req->aiocb = req->is_write ?
                blk_aio_pwritev(n->conf.blk, blk_req->blk_offset,
                    &blk_req->iov, 0, nvme_rw_cb, blk_req) :
                blk_aio_preadv(n->conf.blk, blk_req->blk_offset,
                    &blk_req->iov, 0, nvme_rw_cb, blk_req);
        } else {
            dma_acct_start(n->conf.blk, &blk_req->acct, &blk_req->qsg,
                req->is_write ? BLOCK_ACCT_WRITE : BLOCK_ACCT_READ);

            blk_req->aiocb = req->is_write ?
                dma_blk_write(n->conf.blk, &blk_req->qsg, blk_req->blk_offset,
                    BDRV_SECTOR_SIZE, nvme_rw_cb, blk_req) :
                dma_blk_read(n->conf.blk, &blk_req->qsg, blk_req->blk_offset,
                    BDRV_SECTOR_SIZE, nvme_rw_cb, blk_req);
        }
    }

    return NVME_NO_COMPLETE;
}

static uint16_t nvme_rw(NvmeCtrl *n, NvmeCmd *cmd, NvmeRequest *req)
{
    NvmeRwCmd *rw = (NvmeRwCmd *)cmd;

    uint16_t nlb  = le16_to_cpu(rw->nlb) + 1;
    uint64_t slba = le64_to_cpu(rw->slba);

    trace_nvme_rw(req->cqe.cid, cmd->opcode, nlb, slba);

    int err;

    req->status = NVME_SUCCESS;
    req->nlb = nlb;
    req->slba = slba;
    req->predef = -1;

    if (nvme_rw_is_write(req)) {
        req->is_write = 1;
    }

    err = n->dialect.rw_check_req(n, cmd, req);
    if (err) {
        return err;
    }

    err = nvme_blk_map(n, cmd, req, nvme_blk_setup);
    if (err) {
        return err;
    }

    return nvme_blk_submit_io(n, req);
}

void nvme_discard_cb(void *opaque, int ret)
{
    NvmeBlockBackendRequest *blk_req = opaque;
    NvmeRequest *req = blk_req->req;
    NvmeSQueue *sq = req->sq;
    NvmeCtrl *n = sq->ctrl;
    NvmeCQueue *cq = n->cq[sq->cqid];

    QTAILQ_REMOVE(&req->blk_req_tailq_head, blk_req, blk_req_tailq);

    if (ret) {
        req->status = NVME_INTERNAL_DEV_ERROR;
    }

    if (QTAILQ_EMPTY(&req->blk_req_tailq_head)) {
        nvme_enqueue_req_completion(cq, req);
    }

    nvme_blk_req_destroy(blk_req);
}

static uint16_t nvme_dsm(NvmeCtrl *n, NvmeCmd *cmd, NvmeRequest *req)
{
    NvmeNamespace *ns = req->ns;
    LnvmNamespace *lns = ns->state;
    LnvmAddrF *addrf = &lns->lbaf;
    NvmeDsmCmd *dsm = (NvmeDsmCmd *)cmd;

    if (dsm->attributes & NVME_DSMGMT_AD) {
        uint8_t err;
        uint16_t nr = (dsm->nr & 0xff) + 1;
        uint8_t lbads = NVME_ID_NS_LBADS(ns);

        NvmeDsmRange range[nr];

        err = nvme_dma_write(n, (uint8_t *) range, sizeof(range), cmd, req);
        if (err) {
            nvme_set_error_page(n, req->sq->sqid, req->cqe.cid, err,
                offsetof(NvmeCmd, dptr), 0, ns->id);
            return err;
        }

        for (int i = 0; i < nr; i++) {
            uint64_t sectr_idx, slba;
            uint16_t nlb, err;

            LnvmCS *cs;
            NvmeBlockBackendRequest *blk_req = nvme_blk_req_new(n, req);

            slba = le64_to_cpu(range[i].slba);
            if (LNVM_LBA_GET_SECTR(addrf, slba)) {
                nvme_set_error_page(n, req->sq->sqid, req->cqe.cid,
                    NVME_INVALID_FIELD, 0, slba, ns->id);
                return NVME_INVALID_FIELD | NVME_DNR;
            }

            sectr_idx = n->dialect.blk_idx(n, ns, slba);
            nlb = le32_to_cpu(range[i].nlb);

            if (NULL == (cs = lnvm_chunk_get_state(n, ns, slba))) {
                trace_lnvm_err_invalid_chunk(req->cqe.cid, slba);
                return LNVM_INVALID_RESET | NVME_DNR;
            }

            if (nlb != cs->cnlb) {
                trace_lnvm_err(req->cqe.cid, "invalid reset size",
                    NVME_LBA_RANGE);
                nvme_set_error_page(n, req->sq->sqid, req->cqe.cid,
                    NVME_LBA_RANGE, offsetof(NvmeDsmCmd, dptr), slba,
                    ns->id);
                return NVME_LBA_RANGE | NVME_DNR;
            }

            err = lnvm_chunk_set_free(n, ns, slba, 0, req);
            if (err) {
                return err;
            }

            QTAILQ_INSERT_TAIL(&req->blk_req_tailq_head, blk_req,
                blk_req_tailq);

            blk_req->aiocb = blk_aio_pdiscard(n->conf.blk,
                ns->blk.data + (sectr_idx << lbads), nlb << lbads,
                nvme_discard_cb, blk_req);
        }

        return NVME_NO_COMPLETE;
    }

    return NVME_SUCCESS;
}

static uint16_t nvme_io_cmd(NvmeCtrl *n, NvmeCmd *cmd, NvmeRequest *req)
{
    uint32_t nsid = le32_to_cpu(cmd->nsid);

    if (unlikely(nsid == 0 || nsid > n->params.num_namespaces)) {
        trace_nvme_err_invalid_ns(nsid, n->params.num_namespaces);
        return NVME_INVALID_NSID | NVME_DNR;
    }

    req->ns = &n->namespaces[nsid - 1];

    trace_nvme_io_cmd(req->cqe.cid, nsid, cmd->opcode);

    switch (cmd->opcode) {
    case NVME_CMD_READ:
    case NVME_CMD_WRITE:
        return nvme_rw(n, cmd, req);
    case NVME_CMD_FLUSH:
        if (!n->params.vwc || !n->features.volatile_wc) {
            return NVME_SUCCESS;
        }
        return nvme_flush(n, cmd, req);
    case NVME_CMD_WRITE_ZEROS:
        return nvme_write_zeros(n, cmd, req);
    case NVME_CMD_DSM:
        if (NVME_ONCS_DSM & n->params.oncs) {
            return nvme_dsm(n, cmd, req);
        }
        return NVME_INVALID_OPCODE | NVME_DNR;
    default:
        if (n->dialect.io_cmd) {
            return n->dialect.io_cmd(n, cmd, req);
        }

        trace_nvme_err_invalid_opc(cmd->opcode);
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
    NvmeBlockBackendRequest *blk_req;
    uint16_t qid = le16_to_cpu(c->qid);

    if (unlikely(!qid || nvme_check_sqid(n, qid))) {
        trace_nvme_err_invalid_del_sq(qid);
        return NVME_INVALID_QID | NVME_DNR;
    }

    trace_nvme_del_sq(qid);

    sq = n->sq[qid];
    QTAILQ_FOREACH_SAFE(req, &sq->out_req_list, entry, next) {
        QTAILQ_FOREACH(blk_req, &req->blk_req_tailq_head, blk_req_tailq) {
            if (blk_req->aiocb) {
               blk_aio_cancel(blk_req->aiocb);
            }
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

    sq->io_req = g_new(NvmeRequest, sq->size);
    QTAILQ_INIT(&sq->req_list);
    QTAILQ_INIT(&sq->out_req_list);
    for (i = 0; i < sq->size; i++) {
        sq->io_req[i].sq = sq;
        QTAILQ_INIT(&(sq->io_req[i].blk_req_tailq_head));
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

    trace_nvme_create_sq(prp1, sqid, cqid, qsize, qflags);

    if (unlikely(!cqid || nvme_check_cqid(n, cqid))) {
        trace_nvme_err_invalid_create_sq_cqid(cqid);
        return NVME_INVALID_CQID | NVME_DNR;
    }
    if (unlikely(!sqid || !nvme_check_sqid(n, sqid))) {
        trace_nvme_err_invalid_create_sq_sqid(sqid);
        return NVME_INVALID_QID | NVME_DNR;
    }
    if (unlikely(!qsize || qsize > NVME_CAP_MQES(n->bar.cap))) {
        trace_nvme_err_invalid_create_sq_size(qsize);
        return NVME_MAX_QSIZE_EXCEEDED | NVME_DNR;
    }
    if (unlikely(!prp1 || prp1 & (n->page_size - 1))) {
        trace_nvme_err_invalid_create_sq_addr(prp1);
        return NVME_INVALID_FIELD | NVME_DNR;
    }

    if (unlikely(!(NVME_SQ_FLAGS_PC(qflags)) && NVME_CAP_CQR(n->bar.cap))) {
        trace_nvme_err_invalid_create_sq_qflags(NVME_SQ_FLAGS_PC(qflags));
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

    if (unlikely(!qid || nvme_check_cqid(n, qid))) {
        trace_nvme_err_invalid_del_cq_cqid(qid);
        return NVME_INVALID_CQID | NVME_DNR;
    }

    cq = n->cq[qid];
    if (unlikely(!QTAILQ_EMPTY(&cq->sq_list))) {
        trace_nvme_err_invalid_del_cq_notempty(qid);
        return NVME_INVALID_QUEUE_DEL;
    }
    nvme_irq_deassert(n, cq);
    trace_nvme_del_cq(qid);
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
    cq->timer = timer_new_ns(QEMU_CLOCK_VIRTUAL, nvme_post_cqes, cq);

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

    trace_nvme_create_cq(prp1, cqid, vector, qsize, qflags,
                         NVME_CQ_FLAGS_IEN(qflags) != 0);

    if (unlikely(!cqid || !nvme_check_cqid(n, cqid))) {
        trace_nvme_err_invalid_create_cq_cqid(cqid);
        return NVME_INVALID_CQID | NVME_DNR;
    }
    if (unlikely(!qsize || qsize > NVME_CAP_MQES(n->bar.cap))) {
        trace_nvme_err_invalid_create_cq_size(qsize);
        return NVME_MAX_QSIZE_EXCEEDED | NVME_DNR;
    }
    if (unlikely(!prp1)) {
        trace_nvme_err_invalid_create_cq_addr(prp1);
        return NVME_INVALID_FIELD | NVME_DNR;
    }
    if (unlikely(vector > n->params.num_queues)) {
        trace_nvme_err_invalid_create_cq_vector(vector);
        return NVME_INVALID_IRQ_VECTOR | NVME_DNR;
    }
    if (unlikely(!(NVME_CQ_FLAGS_PC(qflags)) && NVME_CAP_CQR(n->bar.cap))) {
        trace_nvme_err_invalid_create_cq_qflags(NVME_CQ_FLAGS_PC(qflags));
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


static uint16_t nvme_get_feature(NvmeCtrl *n, NvmeCmd *cmd, NvmeRequest *req)
{
    NvmeRangeType *rt;
    uint32_t dw10 = le32_to_cpu(cmd->cdw10);
    uint32_t dw11 = le32_to_cpu(cmd->cdw11);
    uint32_t nsid = le32_to_cpu(cmd->nsid);

    uint32_t result;

    switch (dw10) {
    case NVME_ARBITRATION:
        result = cpu_to_le32(n->features.arbitration);
        break;
    case NVME_POWER_MANAGEMENT:
        result = cpu_to_le32(n->features.power_mgmt);
        break;
    case NVME_LBA_RANGE_TYPE:
        if (unlikely(nsid == 0 || nsid > n->params.num_namespaces)) {
            return NVME_INVALID_NSID | NVME_DNR;
        }
        rt = n->namespaces[nsid - 1].lba_range;
        return nvme_dma_read(n, (uint8_t *)rt,
            MIN(sizeof(*rt), (dw11 & 0x3f) * sizeof(*rt)),
            cmd, req);
    case NVME_NUMBER_OF_QUEUES:
        result = cpu_to_le32((n->params.num_queues - 2) |
            ((n->params.num_queues - 2) << 16));
        trace_nvme_getfeat_numq(result);
        break;
    case NVME_TEMPERATURE_THRESHOLD:
        result = cpu_to_le32(n->features.temp_thresh);
        break;
    case NVME_ERROR_RECOVERY:
        result = cpu_to_le32(n->features.err_rec);
        break;
    case NVME_VOLATILE_WRITE_CACHE:
        result = blk_enable_write_cache(n->conf.blk);
        trace_nvme_getfeat_vwcache(result ? "enabled" : "disabled");
        result = cpu_to_le32(n->features.volatile_wc);
        break;
    case NVME_INTERRUPT_COALESCING:
        result = cpu_to_le32(n->features.int_coalescing);
        break;
    case NVME_INTERRUPT_VECTOR_CONF:
        if ((dw11 & 0xffff) > n->params.num_queues) {
            return NVME_INVALID_FIELD | NVME_DNR;
        }
        result = cpu_to_le32(
            n->features.int_vector_config[dw11 & 0xffff]);
        break;
    case NVME_WRITE_ATOMICITY:
        result = cpu_to_le32(n->features.write_atomicity);
        break;
    case NVME_ASYNCHRONOUS_EVENT_CONF:
        result = cpu_to_le32(n->features.async_config);
        break;
    case NVME_SOFTWARE_PROGRESS_MARKER:
        result = cpu_to_le32(n->features.sw_prog_marker);
        break;
    default:
        trace_nvme_err_invalid_getfeat(dw10);
        return NVME_INVALID_FIELD | NVME_DNR;
    }

    req->cqe.n.result = result;
    return NVME_SUCCESS;
}

static uint16_t nvme_set_feature(NvmeCtrl *n, NvmeCmd *cmd, NvmeRequest *req)
{
    NvmeRangeType *rt;
    uint32_t len;

    uint32_t dw10 = le32_to_cpu(cmd->cdw10);
    uint32_t dw11 = le32_to_cpu(cmd->cdw11);
    uint32_t nsid = le32_to_cpu(cmd->nsid);

    switch (dw10) {
    case NVME_ARBITRATION:
        req->cqe.n.result = cpu_to_le32(n->features.arbitration);
        n->features.arbitration = dw11;
        break;
    case NVME_POWER_MANAGEMENT:
        n->features.power_mgmt = dw11;
        break;
    case NVME_LBA_RANGE_TYPE:
        if (unlikely(nsid == 0 || nsid > n->params.num_namespaces)) {
            return NVME_INVALID_NSID | NVME_DNR;
        }
        rt = n->namespaces[nsid - 1].lba_range;
        len = MIN(sizeof(*rt), (dw11 & 0x3f) * sizeof(*rt));
        return nvme_dma_write(n, (uint8_t *) rt, len, cmd, req);
    case NVME_NUMBER_OF_QUEUES:
        trace_nvme_setfeat_numq((dw11 & 0xFFFF) + 1,
            ((dw11 >> 16) & 0xFFFF) + 1, n->params.num_queues - 1,
            n->params.num_queues - 1);
        req->cqe.n.result = cpu_to_le32((n->params.num_queues - 2) |
            ((n->params.num_queues - 2) << 16));
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
        blk_set_enable_write_cache(n->conf.blk, dw11 & 1);
        n->features.volatile_wc = dw11;
        break;
    case NVME_INTERRUPT_COALESCING:
        n->features.int_coalescing = dw11;
        break;
    case NVME_INTERRUPT_VECTOR_CONF:
        if ((dw11 & 0xffff) > n->params.num_queues) {
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
        trace_nvme_err_invalid_setfeat(dw10);
        return NVME_INVALID_FIELD | NVME_DNR;
    }
    return NVME_SUCCESS;
}

static uint16_t nvme_fw_log_info(NvmeCtrl *n, NvmeCmd *cmd, uint32_t buf_len,
    NvmeRequest *req)
{
    uint32_t trans_len;
    NvmeFwSlotInfoLog fw_log;

    trans_len = MIN(sizeof(fw_log), buf_len);

    return nvme_dma_read(n, (uint8_t *)&fw_log, trans_len, cmd, req);
}

static uint16_t nvme_error_log_info(NvmeCtrl *n, NvmeCmd *cmd,
    uint32_t buf_len, NvmeRequest *req)
{
    uint32_t trans_len;

    trans_len = MIN(sizeof(*n->elpes) * n->params.elpe, buf_len);
    n->aer_mask &= ~(1 << NVME_AER_TYPE_ERROR);
    if (!QSIMPLEQ_EMPTY(&n->aer_queue)) {
        timer_mod(n->aer_timer, qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL) + 10000);
    }
    return nvme_dma_read(n, (uint8_t *)n->elpes, trans_len, cmd, req);
}

static uint16_t nvme_smart_info(NvmeCtrl *n, NvmeCmd *cmd, uint32_t buf_len,
    NvmeRequest *req)
{
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

    return nvme_dma_read(n, (uint8_t *)&smart, trans_len, cmd, req);
}

static uint16_t nvme_get_log(NvmeCtrl *n, NvmeCmd *cmd, NvmeRequest *req)
{
    uint32_t dw10 = le32_to_cpu(cmd->cdw10);
    uint32_t dw11 = le32_to_cpu(cmd->cdw11);
    uint16_t lid = dw10 & 0xff;
    uint32_t numdl, numdu, len;

    numdl = (dw10 >> 16);
    numdu = (dw11 & 0xffff);

    len = (((numdu << 16) | numdl) + 1) << 2;

    trace_nvme_get_log(req->cqe.cid, lid);

    switch (lid) {
    case NVME_LOG_ERROR_INFO:
        return nvme_error_log_info(n, cmd, len, req);
    case NVME_LOG_SMART_INFO:
        return nvme_smart_info(n, cmd, len, req);
    case NVME_LOG_FW_SLOT_INFO:
        return nvme_fw_log_info(n, cmd, len, req);
    default:
        if (n->dialect.get_log) {
            return n->dialect.get_log(n, cmd, req);
        }

        trace_nvme_err_invalid_log_page(req->cqe.cid, lid);
        return NVME_INVALID_LOG_ID | NVME_DNR;
    }
}

static uint16_t nvme_async_req(NvmeCtrl *n, NvmeCmd *cmd, NvmeRequest *req)
{
    if (n->outstanding_aers > n->params.aerl + 1) {
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
    NvmeBlockBackendRequest *blk_req;

    *result = 1;
    if (nvme_check_sqid(n, sqid)) {
        return NVME_SUCCESS;
    }

    sq = n->sq[sqid];
    QTAILQ_FOREACH_SAFE(req, &sq->out_req_list, entry, next) {
        if (sq->sqid) {
            QTAILQ_FOREACH(blk_req, &req->blk_req_tailq_head, blk_req_tailq) {
                if (blk_req->aiocb && req->cqe.cid == cid) {
                    bdrv_aio_cancel(blk_req->aiocb);
                    *result = 0;
                    return NVME_SUCCESS;
                }
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

uint64_t nvme_ns_calc_blks(NvmeCtrl *n, NvmeNamespace *ns)
{
    return n->ns_size / ((1 << NVME_ID_NS_LBADS(ns)) + NVME_ID_NS_MS(ns));
}

static uint16_t nvme_format_namespace(NvmeCtrl *n, NvmeNamespace *ns,
    uint8_t lba_idx, uint8_t meta_loc, uint8_t pil, uint8_t pi,
    uint8_t sec_erase)
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
    ns->ns_blks = nvme_ns_calc_blks(n, ns);
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

        for (i = 0; i < n->params.num_namespaces; ++i) {
            ns = &n->namespaces[i];
            ret = nvme_format_namespace(n, ns, lba_idx, meta_loc, pil, pi,
                sec_erase);
            if (ret != NVME_SUCCESS) {
                return ret;
            }
        }
        return ret;
    }

    if (unlikely(nsid == 0 || nsid > n->params.num_namespaces)) {
        return NVME_INVALID_NSID | NVME_DNR;
    }

    ns = &n->namespaces[nsid - 1];
    return nvme_format_namespace(n, ns, lba_idx, meta_loc, pil, pi,
                                 sec_erase);
}


static uint16_t nvme_identify_ctrl(NvmeCtrl *n, NvmeCmd *cmd, NvmeRequest *req)
{
    trace_nvme_identify_ctrl();

    return nvme_dma_read(n, (uint8_t *)&n->id_ctrl, sizeof(n->id_ctrl), cmd,
        req);
}

static uint16_t nvme_identify_ns(NvmeCtrl *n, NvmeCmd *cmd, NvmeRequest *req)
{
    NvmeNamespace *ns;
    uint32_t nsid = le32_to_cpu(cmd->nsid);

    trace_nvme_identify_ns(nsid);

    if (unlikely(nsid == 0 || nsid > n->params.num_namespaces)) {
        trace_nvme_err_invalid_ns(nsid, n->params.num_namespaces);
        return NVME_INVALID_NSID | NVME_DNR;
    }

    ns = &n->namespaces[nsid - 1];

    return nvme_dma_read(n, (uint8_t *)&ns->id_ns, sizeof(ns->id_ns), cmd,
        req);
}

static uint16_t nvme_identify_nslist(NvmeCtrl *n, NvmeCmd *cmd,
    NvmeRequest *req)
{
    static const int data_len = 4 * KiB;
    uint32_t min_nsid = le32_to_cpu(cmd->nsid);
    uint32_t *list;
    uint16_t ret;
    int i, j = 0;

    trace_nvme_identify_nslist(min_nsid);

    if (unlikely(min_nsid == 0xfffffffe || min_nsid == 0xffffffff)) {
        return NVME_INVALID_NSID | NVME_DNR;
    }

    list = g_malloc0(data_len);
    for (i = 0; i < n->params.num_namespaces; i++) {
        if (i < min_nsid) {
            continue;
        }
        list[j++] = cpu_to_le32(i + 1);
        if (j == data_len / sizeof(uint32_t)) {
            break;
        }
    }
    ret = nvme_dma_read(n, (uint8_t *)list, data_len, cmd, req);
    g_free(list);
    return ret;
}

static uint16_t nvme_identify(NvmeCtrl *n, NvmeCmd *cmd, NvmeRequest *req)
{
    NvmeIdentify *c = (NvmeIdentify *)cmd;

    switch (le32_to_cpu(c->cns)) {
    case 0x00:
        return nvme_identify_ns(n, cmd, req);
    case 0x01:
        return nvme_identify_ctrl(n, cmd, req);
    case 0x02:
        return nvme_identify_nslist(n, cmd, req);
    default:
        trace_nvme_err_invalid_identify_cns(le32_to_cpu(c->cns));
        return NVME_INVALID_FIELD | NVME_DNR;
    }
}

static uint16_t nvme_set_db_memory(NvmeCtrl *n, const NvmeCmd *cmd)
{
    NvmeParams *params = &n->params;

    uint64_t db_addr = le64_to_cpu(cmd->dptr.prp.prp1);
    uint64_t eventidx_addr = le64_to_cpu(cmd->dptr.prp.prp2);
    int i;

    /* Addresses should not be NULL and should be page aligned. */
    if (db_addr == 0 || db_addr & (n->page_size - 1) ||
        eventidx_addr == 0 || eventidx_addr & (n->page_size - 1)) {
        return NVME_INVALID_MEMORY_ADDRESS | NVME_DNR;
    }

    /* This assumes all I/O queues are created before this command is handled.
     * We skip the admin queues. */
    for (i = 1; i < params->num_queues; i++) {
        NvmeSQueue *sq = n->sq[i];
        NvmeCQueue *cq = n->cq[i];

        if (sq) {
            /* Submission queue tail pointer location, 2 * QID * stride. */
            sq->db_addr = db_addr + 2 * i * (1 << (2  + params->db_stride));
            sq->eventidx_addr = eventidx_addr + 2 * i *
                                    (1 << (2 + params->db_stride));
        }
        if (cq) {
            /* Completion queue head pointer location, (2 * QID + 1) * stride. */
            cq->db_addr = db_addr + (2 * i + 1) * (1 << (2 + params->db_stride));
            cq->eventidx_addr = eventidx_addr + (2 * i + 1) *
                        (1 << (2 + params->db_stride));
        }
    }
    return NVME_SUCCESS;
}

static uint16_t nvme_admin_cmd(NvmeCtrl *n, NvmeCmd *cmd, NvmeRequest *req)
{
    trace_nvme_admin_cmd(req->cqe.cid, cmd->opcode);

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
        return nvme_identify(n, cmd, req);
    case NVME_ADM_CMD_SET_FEATURES:
        return nvme_set_feature(n, cmd, req);
    case NVME_ADM_CMD_GET_FEATURES:
        return nvme_get_feature(n, cmd, req);
    case NVME_ADM_CMD_GET_LOG_PAGE:
        return nvme_get_log(n, cmd, req);
    case NVME_ADM_CMD_ASYNC_EV_REQ:
        return nvme_async_req(n, cmd, req);
    case NVME_ADM_CMD_ABORT:
        return nvme_abort_req(n, cmd, &req->cqe.n.result);
    case NVME_ADM_CMD_FORMAT_NVM:
        if (NVME_OACS_FORMAT & n->params.oacs) {
            return nvme_format(n, cmd);
        }
        return NVME_INVALID_OPCODE | NVME_DNR;
    case NVME_ADM_CMD_SET_DB_MEMORY:
        return nvme_set_db_memory(n, cmd);
    case NVME_ADM_CMD_ACTIVATE_FW:
    case NVME_ADM_CMD_DOWNLOAD_FW:
    case NVME_ADM_CMD_SECURITY_SEND:
    case NVME_ADM_CMD_SECURITY_RECV:
    default:
        if (n->dialect.admin_cmd) {
            return n->dialect.admin_cmd(n, cmd, req);
        }

        trace_nvme_err_invalid_admin_opc(cmd->opcode);
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
        req->cqe.cid = le16_to_cpu(cmd.cid);
        req->status = NVME_SUCCESS;
        req->cmd_opcode = cmd.opcode;
        req->cmb = false;
        req->ns = NULL;
        req->is_write = 0;

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

    blk_drain(n->conf.blk);

    for (i = 0; i < n->params.num_queues; i++) {
        if (n->sq[i] != NULL) {
            nvme_free_sq(n->sq[i], n);
        }
    }
    for (i = 0; i < n->params.num_queues; i++) {
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
    n->bar.cc = 0;
    n->features.temp_thresh = 0x14d;
    n->temp_warn_issued = 0;
    n->outstanding_aers = 0;
}

static int nvme_start_ctrl(NvmeCtrl *n)
{
    uint32_t page_bits = NVME_CC_MPS(n->bar.cc) + 12;
    uint32_t page_size = 1 << page_bits;

    if (unlikely(n->cq[0])) {
        trace_nvme_err_startfail_cq();
        return -1;
    }
    if (unlikely(n->sq[0])) {
        trace_nvme_err_startfail_sq();
        return -1;
    }
    if (unlikely(!n->bar.asq)) {
        trace_nvme_err_startfail_nbarasq();
        return -1;
    }
    if (unlikely(!n->bar.acq)) {
        trace_nvme_err_startfail_nbaracq();
        return -1;
    }
    if (unlikely(n->bar.asq & (page_size - 1))) {
        trace_nvme_err_startfail_asq_misaligned(n->bar.asq);
        return -1;
    }
    if (unlikely(n->bar.acq & (page_size - 1))) {
        trace_nvme_err_startfail_acq_misaligned(n->bar.acq);
        return -1;
    }
    if (unlikely(NVME_CC_MPS(n->bar.cc) <
                 NVME_CAP_MPSMIN(n->bar.cap))) {
        trace_nvme_err_startfail_page_too_small(
                    NVME_CC_MPS(n->bar.cc),
                    NVME_CAP_MPSMIN(n->bar.cap));
        return -1;
    }
    if (unlikely(NVME_CC_MPS(n->bar.cc) >
                 NVME_CAP_MPSMAX(n->bar.cap))) {
        trace_nvme_err_startfail_page_too_large(
                    NVME_CC_MPS(n->bar.cc),
                    NVME_CAP_MPSMAX(n->bar.cap));
        return -1;
    }
    if (unlikely(NVME_CC_IOCQES(n->bar.cc) <
                 NVME_CTRL_CQES_MIN(n->id_ctrl.cqes))) {
        trace_nvme_err_startfail_cqent_too_small(
                    NVME_CC_IOCQES(n->bar.cc),
                    NVME_CTRL_CQES_MIN(n->bar.cap));
        return -1;
    }
    if (unlikely(NVME_CC_IOCQES(n->bar.cc) >
                 NVME_CTRL_CQES_MAX(n->id_ctrl.cqes))) {
        trace_nvme_err_startfail_cqent_too_large(
                    NVME_CC_IOCQES(n->bar.cc),
                    NVME_CTRL_CQES_MAX(n->bar.cap));
        return -1;
    }
    if (unlikely(NVME_CC_IOSQES(n->bar.cc) <
                 NVME_CTRL_SQES_MIN(n->id_ctrl.sqes))) {
        trace_nvme_err_startfail_sqent_too_small(
                    NVME_CC_IOSQES(n->bar.cc),
                    NVME_CTRL_SQES_MIN(n->bar.cap));
        return -1;
    }
    if (unlikely(NVME_CC_IOSQES(n->bar.cc) >
                 NVME_CTRL_SQES_MAX(n->id_ctrl.sqes))) {
        trace_nvme_err_startfail_sqent_too_large(
                    NVME_CC_IOSQES(n->bar.cc),
                    NVME_CTRL_SQES_MAX(n->bar.cap));
        return -1;
    }
    if (unlikely(!NVME_AQA_ASQS(n->bar.aqa))) {
        trace_nvme_err_startfail_asqent_sz_zero();
        return -1;
    }
    if (unlikely(!NVME_AQA_ACQS(n->bar.aqa))) {
        trace_nvme_err_startfail_acqent_sz_zero();
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
    if (unlikely(offset & (sizeof(uint32_t) - 1))) {
        NVME_GUEST_ERR(nvme_ub_mmiowr_misaligned32,
                       "MMIO write not 32-bit aligned,"
                       " offset=0x%"PRIx64"", offset);
        /* should be ignored, fall through for now */
    }

    if (unlikely(size < sizeof(uint32_t))) {
        NVME_GUEST_ERR(nvme_ub_mmiowr_toosmall,
                       "MMIO write smaller than 32-bits,"
                       " offset=0x%"PRIx64", size=%u",
                       offset, size);
        /* should be ignored, fall through for now */
    }

    switch (offset) {
    case 0xc:   /* INTMS */
        if (unlikely(msix_enabled(&(n->parent_obj)))) {
            NVME_GUEST_ERR(nvme_ub_mmiowr_intmask_with_msix,
                           "undefined access to interrupt mask set"
                           " when MSI-X is enabled");
            /* should be ignored, fall through for now */
        }
        n->bar.intms |= data & 0xffffffff;
        n->bar.intmc = n->bar.intms;
        trace_nvme_mmio_intm_set(data & 0xffffffff,
                                 n->bar.intmc);
        nvme_irq_check(n);
        break;
    case 0x10:  /* INTMC */
        if (unlikely(msix_enabled(&(n->parent_obj)))) {
            NVME_GUEST_ERR(nvme_ub_mmiowr_intmask_with_msix,
                           "undefined access to interrupt mask clr"
                           " when MSI-X is enabled");
            /* should be ignored, fall through for now */
        }
        n->bar.intms &= ~(data & 0xffffffff);
        n->bar.intmc = n->bar.intms;
        trace_nvme_mmio_intm_clr(data & 0xffffffff,
                                 n->bar.intmc);
        nvme_irq_check(n);
        break;
    case 0x14:  /* CC */
        trace_nvme_mmio_cfg(data & 0xffffffff);
        /* Windows first sends data, then sends enable bit */
        if (!NVME_CC_EN(data) && !NVME_CC_EN(n->bar.cc) &&
            !NVME_CC_SHN(data) && !NVME_CC_SHN(n->bar.cc))
        {
            n->bar.cc = data;
        }

        if (NVME_CC_EN(data) && !NVME_CC_EN(n->bar.cc)) {
            n->bar.cc = data;
            if (unlikely(nvme_start_ctrl(n))) {
                trace_nvme_err_startfail();
                n->bar.csts = NVME_CSTS_FAILED;
            } else {
                trace_nvme_mmio_start_success();
                n->bar.csts = NVME_CSTS_READY;
            }
        } else if (!NVME_CC_EN(data) && NVME_CC_EN(n->bar.cc)) {
            trace_nvme_mmio_stopped();
            nvme_clear_ctrl(n);
            n->bar.csts &= ~NVME_CSTS_READY;
        }
        if (NVME_CC_SHN(data) && !(NVME_CC_SHN(n->bar.cc))) {
            trace_nvme_mmio_shutdown_set();
            nvme_clear_ctrl(n);
            n->bar.cc = data;
            n->bar.csts |= NVME_CSTS_SHST_COMPLETE;
        } else if (!NVME_CC_SHN(data) && NVME_CC_SHN(n->bar.cc)) {
            trace_nvme_mmio_shutdown_cleared();
            n->bar.csts &= ~NVME_CSTS_SHST_COMPLETE;
            n->bar.cc = data;
        }
        break;
    case 0x1C:  /* CSTS */
        if (data & (1 << 4)) {
            NVME_GUEST_ERR(nvme_ub_mmiowr_ssreset_w1c_unsupported,
                           "attempted to W1C CSTS.NSSRO"
                           " but CAP.NSSRS is zero (not supported)");
        } else if (data != 0) {
            NVME_GUEST_ERR(nvme_ub_mmiowr_ro_csts,
                           "attempted to set a read only bit"
                           " of controller status");
        }
        break;
    case 0x20:  /* NSSR */
        if (data == 0x4E564D65) {
            trace_nvme_ub_mmiowr_ssreset_unsupported();
        } else {
            /* The spec says that writes of other values have no effect */
            return;
        }
        break;
    case 0x24:  /* AQA */
        n->bar.aqa = data & 0xffffffff;
        trace_nvme_mmio_aqattr(data & 0xffffffff);
        break;
    case 0x28:  /* ASQ */
        n->bar.asq = data;
        trace_nvme_mmio_asqaddr(data);
        break;
    case 0x2c:  /* ASQ hi */
        n->bar.asq |= data << 32;
        trace_nvme_mmio_asqaddr_hi(data, n->bar.asq);
        break;
    case 0x30:  /* ACQ */
        trace_nvme_mmio_acqaddr(data);
        n->bar.acq = data;
        break;
    case 0x34:  /* ACQ hi */
        n->bar.acq |= data << 32;
        trace_nvme_mmio_acqaddr_hi(data, n->bar.acq);
        break;
    case 0x38:  /* CMBLOC */
        NVME_GUEST_ERR(nvme_ub_mmiowr_cmbloc_reserved,
                       "invalid write to reserved CMBLOC"
                       " when CMBSZ is zero, ignored");
        return;
    case 0x3C:  /* CMBSZ */
        NVME_GUEST_ERR(nvme_ub_mmiowr_cmbsz_readonly,
                       "invalid write to read only CMBSZ, ignored");
        return;
    default:
        NVME_GUEST_ERR(nvme_ub_mmiowr_invalid,
                       "invalid MMIO write,"
                       " offset=0x%"PRIx64", data=%"PRIx64"",
                       offset, data);
        break;
    }
}

static uint64_t nvme_mmio_read(void *opaque, hwaddr addr, unsigned size)
{
    NvmeCtrl *n = (NvmeCtrl *)opaque;
    uint8_t *ptr = (uint8_t *)&n->bar;
    uint64_t val = 0;

    if (unlikely(addr & (sizeof(uint32_t) - 1))) {
        NVME_GUEST_ERR(nvme_ub_mmiord_misaligned32,
                       "MMIO read not 32-bit aligned,"
                       " offset=0x%"PRIx64"", addr);
        /* should RAZ, fall through for now */
    } else if (unlikely(size < sizeof(uint32_t))) {
        NVME_GUEST_ERR(nvme_ub_mmiord_toosmall,
                       "MMIO read smaller than 32-bits,"
                       " offset=0x%"PRIx64"", addr);
        /* should RAZ, fall through for now */
    }

    if (addr < sizeof(n->bar)) {
        memcpy(&val, ptr + addr, size);
    } else {
        NVME_GUEST_ERR(nvme_ub_mmiord_invalid_ofs,
                       "MMIO read beyond last register,"
                       " offset=0x%"PRIx64", returning 0", addr);
    }

    return val;
}

static void nvme_process_db(NvmeCtrl *n, hwaddr addr, int val)
{
    uint32_t qid;
    uint16_t new_val = val & 0xffff;
    NvmeSQueue *sq;

    if (unlikely(addr & ((1 << (2 + n->params.db_stride)) - 1))) {
        NVME_GUEST_ERR(nvme_ub_db_wr_misaligned,
                       "doorbell write not 32-bit aligned,"
                       " offset=0x%"PRIx64", ignoring", addr);
        nvme_enqueue_event(n, NVME_AER_TYPE_ERROR,
            NVME_AER_INFO_ERR_INVALID_DB, NVME_LOG_ERROR_INFO);
        return;
    }

    if (((addr - 0x1000) >> (2 + n->params.db_stride)) & 1) {
        NvmeCQueue *cq;
        bool start_sqs;

        qid = (addr - (0x1000 + (1 << (2 + n->params.db_stride)))) >>
            (3 + n->params.db_stride);
        if (unlikely(nvme_check_cqid(n, qid))) {
            NVME_GUEST_ERR(nvme_ub_db_wr_invalid_cq,
                           "completion queue doorbell write"
                           " for nonexistent queue,"
                           " sqid=%"PRIu32", ignoring", qid);
            nvme_enqueue_event(n, NVME_AER_TYPE_ERROR,
                NVME_AER_INFO_ERR_INVALID_DB, NVME_LOG_ERROR_INFO);
            return;
        }

        cq = n->cq[qid];
        if (unlikely(new_val >= cq->size)) {
            NVME_GUEST_ERR(nvme_ub_db_wr_invalid_cqhead,
                           "completion queue doorbell write value"
                           " beyond queue size, sqid=%"PRIu32","
                           " new_head=%"PRIu16", ignoring",
                           qid, new_val);
            nvme_enqueue_event(n, NVME_AER_TYPE_ERROR,
                NVME_AER_INFO_ERR_INVALID_DB, NVME_LOG_ERROR_INFO);

            return;
        }

        start_sqs = nvme_cq_full(cq) ? 1 : 0;

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
        }

        if (cq->tail == cq->head) {
            nvme_irq_deassert(n, cq);
        }
    } else {
        qid = (addr - 0x1000) >> (3 + n->params.db_stride);
        if (unlikely(nvme_check_sqid(n, qid))) {
            NVME_GUEST_ERR(nvme_ub_db_wr_invalid_sq,
                           "submission queue doorbell write"
                           " for nonexistent queue,"
                           " sqid=%"PRIu32", ignoring", qid);
            nvme_enqueue_event(n, NVME_AER_TYPE_ERROR,
                NVME_AER_INFO_ERR_INVALID_SQ, NVME_LOG_ERROR_INFO);
            return;
        }
        sq = n->sq[qid];
        if (unlikely(new_val >= sq->size)) {
            NVME_GUEST_ERR(nvme_ub_db_wr_invalid_sqtail,
                           "submission queue doorbell write value"
                           " beyond queue size, sqid=%"PRIu32","
                           " new_tail=%"PRIu16", ignoring",
                           qid, new_val);
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

static void nvme_cmb_write(void *opaque, hwaddr addr, uint64_t data,
    unsigned size)
{
    NvmeCtrl *n = (NvmeCtrl *)opaque;
    stn_le_p(&n->cmbuf[addr], size, data);
}

static uint64_t nvme_cmb_read(void *opaque, hwaddr addr, unsigned size)
{
    NvmeCtrl *n = (NvmeCtrl *)opaque;
    return ldn_le_p(&n->cmbuf[addr], size);
}

static const MemoryRegionOps nvme_cmb_ops = {
    .read = nvme_cmb_read,
    .write = nvme_cmb_write,
    .endianness = DEVICE_LITTLE_ENDIAN,
    .impl = {
        .min_access_size = 1,
        .max_access_size = 8,
    },
};

static int nvme_check_constraints(NvmeCtrl *n, Error **errp)
{
    NvmeParams *params = &n->params;

    if (!n->conf.blk) {
        error_setg(errp, "nvme: block backend not configured");
        return 1;
    }

    if (!params->serial) {
        error_setg(errp, "nvme: serial not configured");
        return 1;
    }

    if (params->num_namespaces == 0 || params->num_namespaces > NVME_MAX_NUM_NAMESPACES) {
        error_setg(errp, "nvme: invalid namespace configuration");
        return 1;
    }

    if ((params->num_queues < 1 || params->num_queues > NVME_MAX_QS) ||
        (params->max_q_ents < 1) ||
        (params->max_sqes > NVME_MAX_QUEUE_ES || params->max_cqes > NVME_MAX_QUEUE_ES ||
         params->max_sqes < NVME_MIN_SQUEUE_ES || params->max_cqes < NVME_MIN_CQUEUE_ES)) {
        error_setg(errp, "nvme: invalid queue configuration");
        return 1;
    }

    if (params->db_stride > NVME_MAX_STRIDE) {
        error_setg(errp, "nvme: invalid db_stride configuration");
    }

    if (params->vwc > 1) {
        error_setg(errp, "nvme: invalid 'vwc' parameter value");
        return 1;
    }

    if (params->intc > 1) {
        error_setg(errp, "nvme: invalid 'intc' parameter value");
        return 1;
    }

    if (params->cqr > 1) {
        error_setg(errp, "nvme: invalid 'cqr' parameter value");
        return 1;
    }

    if (params->extended > 1) {
        error_setg(errp, "nvme: invalid 'extended' parameter value");
        return 1;
    }

    if ((params->ms > params->ms_max) ||
        (params->ms && !is_power_of_2(params->ms)) ||
        (params->ms && !params->mc) ||
        (params->extended && !(NVME_ID_NS_MC_EXTENDED(params->mc))) ||
        (!params->extended && params->ms && !(NVME_ID_NS_MC_SEPARATE(params->mc)))) {
        error_setg(errp, "nvme: invalid metadata configuration");
        return 1;
    }

    if ((params->dps && params->ms < 8) ||
        (params->dps && ((params->dps & DPS_FIRST_EIGHT) &&
            !NVME_ID_NS_DPC_FIRST_EIGHT(params->dpc))) ||
        (params->dps && !(params->dps & DPS_FIRST_EIGHT) &&
            !NVME_ID_NS_DPC_LAST_EIGHT(params->dpc)) ||
        (params->dps & DPS_TYPE_MASK && !((params->dpc & NVME_ID_NS_DPC_TYPE_MASK) &
            (1 << ((params->dps & DPS_TYPE_MASK) - 1))))) {
        error_setg(errp, "nvme: invalid data protection configuration");
        return 1;
    }

    if (params->mpsmax > 0xf || params->mpsmax > params->mpsmin) {
        error_setg(errp, "nvme: invalid mps configuration");
        return 1;
    }

    if (params->oacs & ~(NVME_OACS_FORMAT)) {
        error_setg(errp, "nvme: invalid oacs configuration");
        return 1;
    }

    if (params->oncs & ~(NVME_ONCS_DSM | NVME_ONCS_WRITE_ZEROS)) {
        error_setg(errp, "nvme: invalid oncs configuration");
        return 1;
    }

    return 0;
}

void nvme_ns_init_predef(NvmeCtrl *n, NvmeNamespace *ns)
{
    uint8_t *pbuf = g_malloc(NVME_ID_NS_LBADS_BYTES(ns));

    switch (n->params.dlfeat) {
    case 0x1:
        memset(pbuf, 0x00, NVME_ID_NS_LBADS_BYTES(ns));
        break;

    case 0x2:
        pbuf = g_malloc(NVME_ID_NS_LBADS_BYTES(ns));
        memset(pbuf, 0xff, NVME_ID_NS_LBADS_BYTES(ns));
        break;

    default:
        break;
    }

    blk_pwrite(n->conf.blk, NVME_NS_PREDEF_BLK_OFFSET(n, ns), pbuf,
        NVME_ID_NS_LBADS_BYTES(ns), 0);
}

void nvme_ns_init_identify(NvmeCtrl *n, NvmeIdNs *id_ns)
{
    NvmeParams *params;
    uint16_t ms_min;

    params = &n->params;

    id_ns->nsfeat = 0x4;
    id_ns->nlbaf = 0; /* 0's based value */
    id_ns->flbas = params->extended << 4;
    id_ns->mc = params->mc;
    id_ns->dpc = params->dpc;
    id_ns->dps = params->dps;
    id_ns->dlfeat = params->dlfeat;
    id_ns->vs[0] = 0x1;

    id_ns->lbaf[0].lbads = 12;
    id_ns->lbaf[0].ms = 0;

    ms_min = 8;

    for (int i = 1; i < 16 && ms_min <= params->ms_max; i++) {
        id_ns->lbaf[i].lbads = 12;
        id_ns->lbaf[i].ms = ms_min;

        if (params->ms == ms_min) {
            id_ns->flbas = i | (params->extended << 4);
        }

        ms_min *= 2;
        id_ns->nlbaf++;
    }
}

static int nvme_init_namespace(NvmeCtrl *n, NvmeNamespace *ns, Error **errp)
{
    NvmeIdNs *id_ns = &ns->id_ns;

    nvme_ns_init_identify(n, id_ns);

    /* reserve 1 block for predefined data */
    ns->ns_blks = nvme_ns_calc_blks(n, ns) - 1;

    ns->blk.predef = ns->blk.begin;
    ns->blk.data = ns->blk.begin + NVME_ID_NS_LBADS_BYTES(ns);
    ns->blk.meta = ns->blk.data + NVME_ID_NS_LBADS_BYTES(ns) * ns->ns_blks;

    id_ns->nuse = id_ns->ncap = id_ns->nsze = cpu_to_le64(ns->ns_blks);

    nvme_ns_init_predef(n, ns);

    return 0;
}

static void nvme_free_namespace(NvmeCtrl *n, NvmeNamespace *ns) {
    if (n->dialect.free_namespace) {
        n->dialect.free_namespace(n, ns);
    }

    g_free(ns->state);
}

static void nvme_init_ctrl(NvmeCtrl *n)
{
    NvmeIdCtrl *id = &n->id_ctrl;
    NvmeParams *params = &n->params;
    uint8_t *pci_conf = n->parent_obj.config;

    n->sgls = 0x80001;

    id->vid = cpu_to_le16(pci_get_word(pci_conf + PCI_VENDOR_ID));
    id->ssvid = cpu_to_le16(pci_get_word(pci_conf + PCI_SUBSYSTEM_VENDOR_ID));
    strpadcpy((char *)id->mn, sizeof(id->mn), "QEMU NVMe Ctrl", ' ');
    strpadcpy((char *)id->fr, sizeof(id->fr), "1.0", ' ');
    strpadcpy((char *)id->sn, sizeof(id->sn), params->serial, ' ');
    id->rab = 6;
    id->ieee[0] = 0x00;
    id->ieee[1] = 0x02;
    id->ieee[2] = 0xb3;
    id->cmic = 0;
    id->mdts = params->mdts;
    id->ver = 0x00010200;
    id->oacs = cpu_to_le16(params->oacs);
    id->acl = params->acl;
    id->aerl = params->aerl;
    id->frmw = 7 << 1 | 1;
    id->lpa = 1 << 2;
    id->elpe = params->elpe;
    id->npss = 0;
    id->sqes = (params->max_sqes << 4) | 0x6;
    id->cqes = (params->max_cqes << 4) | 0x4;
    id->nn = cpu_to_le32(params->num_namespaces);
    id->oncs = cpu_to_le16(params->oncs);
    id->fuses = cpu_to_le16(0);
    id->fna = 0;
    id->vwc = params->vwc;
    id->awun = cpu_to_le16(0);
    id->awupf = cpu_to_le16(0);
    id->sgls = cpu_to_le32(n->sgls);
    id->psd[0].mp = cpu_to_le16(0x9c4);
    id->psd[0].enlat = cpu_to_le32(0x10);
    id->psd[0].exlat = cpu_to_le32(0x4);
    if (blk_enable_write_cache(n->conf.blk)) {
        id->vwc = 1;
    }

    n->features.arbitration     = 0x1f0f0706;
    n->features.power_mgmt      = 0;
    n->features.temp_thresh     = 0x14d;
    n->features.err_rec         = 0;
    n->features.volatile_wc     = params->vwc;
    n->features.num_queues      = (params->num_queues - 1) |
                                 ((params->num_queues - 1) << 16);
    n->features.int_coalescing  = params->intc_thresh |
                                 (params->intc_time << 8);
    n->features.write_atomicity = 0;
    n->features.async_config    = 0x0;
    n->features.sw_prog_marker  = 0;

    for (int i = 0; i < params->num_queues; i++) {
        n->features.int_vector_config[i] = i | (params->intc << 16);
    }

    n->bar.cap = 0;
    NVME_CAP_SET_MQES(n->bar.cap, params->max_q_ents);
    NVME_CAP_SET_CQR(n->bar.cap, params->cqr);
    NVME_CAP_SET_AMS(n->bar.cap, 1);
    NVME_CAP_SET_TO(n->bar.cap, 0xf);
    NVME_CAP_SET_DSTRD(n->bar.cap, params->db_stride);
    NVME_CAP_SET_NSSRS(n->bar.cap, 0);
    NVME_CAP_SET_CSS(n->bar.cap, 1);

    NVME_CAP_SET_MPSMIN(n->bar.cap, params->mpsmin);
    NVME_CAP_SET_MPSMAX(n->bar.cap, params->mpsmax);

    n->bar.vs = 0x00010200;

    n->bar.intmc = n->bar.intms = 0;
    n->temperature = NVME_TEMPERATURE;

    if (n->dialect.init_ctrl) {
        n->dialect.init_ctrl(n);
    }
}

static void nvme_init_pci(NvmeCtrl *n, PCIDevice *pci_dev)
{
    uint8_t *pci_conf = pci_dev->config;

    pci_conf[PCI_INTERRUPT_PIN] = 1;
    pci_config_set_prog_interface(pci_conf, 0x2);
    pci_config_set_vendor_id(pci_conf, n->params.vid);
    pci_config_set_device_id(pci_conf, n->params.did);
    pci_config_set_class(pci_conf, PCI_CLASS_STORAGE_EXPRESS);
    pcie_endpoint_cap_init(pci_dev, 0x80);


    memory_region_init_io(&n->iomem, OBJECT(n), &nvme_mmio_ops, n, "nvme",
        n->reg_size);
    pci_register_bar(pci_dev, 0,
        PCI_BASE_ADDRESS_SPACE_MEMORY | PCI_BASE_ADDRESS_MEM_TYPE_64,
        &n->iomem);
    msix_init_exclusive_bar(pci_dev, n->params.num_queues, 4, NULL);

    if (n->params.cmb_size_mb) {

        NVME_CMBLOC_SET_BIR(n->bar.cmbloc, 2);
        NVME_CMBLOC_SET_OFST(n->bar.cmbloc, 0);

        NVME_CMBSZ_SET_SQS(n->bar.cmbsz, 1);
        NVME_CMBSZ_SET_CQS(n->bar.cmbsz, 0);
        NVME_CMBSZ_SET_LISTS(n->bar.cmbsz, 1);
        NVME_CMBSZ_SET_RDS(n->bar.cmbsz, 1);
        NVME_CMBSZ_SET_WDS(n->bar.cmbsz, 1);
        NVME_CMBSZ_SET_SZU(n->bar.cmbsz, 2); /* MBs */
        NVME_CMBSZ_SET_SZ(n->bar.cmbsz, n->params.cmb_size_mb);

        n->cmbloc = n->bar.cmbloc;
        n->cmbsz = n->bar.cmbsz;

        n->cmbuf = g_malloc0(NVME_CMBSZ_GETSIZE(n->bar.cmbsz));
        memory_region_init_io(&n->ctrl_mem, OBJECT(n), &nvme_cmb_ops, n,
                              "nvme-cmb", NVME_CMBSZ_GETSIZE(n->bar.cmbsz));
        pci_register_bar(pci_dev, NVME_CMBLOC_BIR(n->bar.cmbloc),
            PCI_BASE_ADDRESS_SPACE_MEMORY | PCI_BASE_ADDRESS_MEM_TYPE_64 |
            PCI_BASE_ADDRESS_MEM_PREFETCH, &n->ctrl_mem);
    }

    if (n->dialect.init_pci) {
        n->dialect.init_pci(n, pci_dev);
    }
}

static int nvme_init_namespaces(NvmeCtrl *n, Error **errp)
{
    for (int i = 0; i < n->params.num_namespaces; i++) {
        NvmeNamespace *ns = &n->namespaces[i];
        ns->id = i + 1;
        ns->blk.begin = i * n->ns_size;

        if (nvme_init_namespace(n, ns, errp)) {
            return 1;
        }
    }

    return 0;
}

static void nvme_realize(PCIDevice *pci_dev, Error **errp)
{
    NvmeCtrl *n = NVME(pci_dev);
    int64_t bs_size;

    if (!n->conf.blk) {
        error_setg(errp, "drive property not set");
        return;
    }

    bs_size = blk_getlength(n->conf.blk);
    if (bs_size < 0) {
        error_setg(errp, "could not get backing file size");
        return;
    }

    if (!n->params.serial) {
        error_setg(errp, "serial property not set");
        return;
    }
    blkconf_blocksizes(&n->conf);
    if (!blkconf_apply_backend_options(&n->conf, blk_is_read_only(n->conf.blk),
                                       false, errp)) {
        return;
    }

    if (nvme_check_constraints(n, errp)) {
        return;
    }

    n->start_time = time(NULL);
    n->reg_size = pow2ceil(0x1004 + 2 * (n->params.num_queues + 1) * 4);

    // set aside an equal amount of space for each namespace
    n->ns_size = bs_size / (uint64_t) n->params.num_namespaces;

    n->sq = g_new0(NvmeSQueue *, n->params.num_queues);
    n->cq = g_new0(NvmeCQueue *, n->params.num_queues);
    n->namespaces = g_new0(NvmeNamespace, n->params.num_namespaces);
    n->elpes = g_new0(NvmeErrorLog, n->params.elpe + 1);
    n->aer_reqs = g_new0(NvmeRequest *, n->params.aerl + 1);
    n->features.int_vector_config = g_malloc0_n(n->params.num_queues,
        sizeof(*n->features.int_vector_config));

    switch (n->params.dialect) {
    case NVME_DIALECT_OCSSD20:
        if (lnvm_realize(n, errp)) {
            return;
        }

        break;

    default:
        n->dialect = (NvmeDialect) {
            .init_namespaces = nvme_init_namespaces,
            .blk_idx         = nvme_lba_to_sector_index,
            .rw_check_req    = nvme_rw_check_req,
        };
    }

    nvme_init_pci(n, pci_dev);
    nvme_init_ctrl(n);

    if (n->dialect.init_namespaces(n, errp)) {
        return;
    }
}

static void nvme_exit(PCIDevice *pci_dev)
{
    NvmeCtrl *n = NVME(pci_dev);

    for (int i = 0; i < n->params.num_namespaces; i++) {
        nvme_free_namespace(n, &n->namespaces[i]);
    }

    nvme_clear_ctrl(n);
    g_free(n->namespaces);
    g_free(n->features.int_vector_config);
    g_free(n->aer_reqs);
    g_free(n->elpes);
    g_free(n->cq);
    g_free(n->sq);

    if (n->params.cmb_size_mb) {
        g_free(n->cmbuf);
    }
    msix_uninit_exclusive_bar(pci_dev);
}

static Property nvme_props[] = {
    DEFINE_BLOCK_PROPERTIES(NvmeCtrl, conf),
    DEFINE_NVME_PROPERTIES(NvmeCtrl, params),
    DEFINE_LNVM_PROPERTIES(NvmeCtrl, params.lnvm),
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

    pc->realize = nvme_realize;
    pc->exit = nvme_exit;
    pc->class_id = PCI_CLASS_STORAGE_EXPRESS;
    pc->vendor_id = PCI_VENDOR_ID_INTEL;
    pc->device_id = 0x5845;
    pc->revision = 2;

    set_bit(DEVICE_CATEGORY_STORAGE, dc->categories);
    dc->desc = "Non-Volatile Memory Express";
    dc->props = nvme_props;
    dc->vmsd = &nvme_vmstate;
}

static void nvme_instance_init(Object *obj)
{
    NvmeCtrl *s = NVME(obj);

    device_add_bootindex_property(obj, &s->conf.bootindex,
                                  "bootindex", "/namespace@1,0",
                                  DEVICE(obj), &error_abort);
}

static const TypeInfo nvme_info = {
    .name          = TYPE_NVME,
    .parent        = TYPE_PCI_DEVICE,
    .instance_size = sizeof(NvmeCtrl),
    .class_init    = nvme_class_init,
    .instance_init = nvme_instance_init,
    .interfaces = (InterfaceInfo[]) {
        { INTERFACE_PCIE_DEVICE },
        { }
    },
};

static void nvme_register_types(void)
{
    type_register_static(&nvme_info);
}

type_init(nvme_register_types)
