#ifndef HW_LIGHTNVM_H
#define HW_LIGHTNVM_H

#include <stdint.h>
#include <stdio.h>

#include "qapi/error.h"

#include "nvme.h"
#include "block/lightnvm.h"

#define LNVM_CMD_MAX_LBAS 64
#define LNVM_CHUNK_INFO_LOGPAGE_SIZE (4 << 20)
#define LNVM_MAGIC (LNVM_DID << 16 | LNVM_VID)

#define LNVM_NS_LNVM_METADATA_BLK_OFFSET(ns)                                  \
    ((ns)->blk.begin + NVME_ID_NS_LBADS_BYTES(ns))

#define LNVM_NS_LOGPAGE_CHUNK_INFO_BLK_OFFSET(ns)                             \
    ((ns)->blk.begin + 2 * NVME_ID_NS_LBADS_BYTES(ns))

/*#define LNVM_NS_LOGPAGE_CHUNK_INFO(ln, ns)                                    \
    (ln)->chunk_info[(ns)->id - 1]*/

#define LNVM_LBA_GET_SECTR(lns, lba)                                           \
    ((lba & (lns)->lbaf.sec_mask)                                              \
        >> (lns)->lbaf.sec_offset)

#define LNVM_LBA_GET_CHUNK(lns, lba)                                           \
    ((lba & (lns)->lbaf.chk_mask)                                              \
        >> (lns)->lbaf.chk_offset)

#define LNVM_LBA_GET_PUNIT(lns, lba)                                           \
    ((lba & (lns)->lbaf.lun_mask)                                              \
        >> (lns)->lbaf.lun_offset)

#define LNVM_LBA_GET_GROUP(lns, lba)                                           \
    (lba >> (lns)->lbaf.grp_offset)

#define LNVM_LBA(lns, group, punit, chunk, sectr)                              \
    (sectr << (lns)->lbaf.sec_offset                                           \
        | chunk << (lns)->lbaf.chk_offset                                      \
        | punit << (lns)->lbaf.lun_offset                                      \
        | group << (lns)->lbaf.grp_offset)

#define LNVM_GROUP_FROM_CHUNK_INDEX(lns, idx)                             \
    (idx / (lns)->chks_per_grp)

#define LNVM_PUNIT_FROM_CHUNK_INDEX(lns, idx)                             \
    (idx % (lns)->chks_per_grp / (lns)->chks_per_lun)

#define LNVM_CHUNK_FROM_CHUNK_INDEX(lns, idx)                             \
    (idx % (lns)->chks_per_lun)

#define LNVM_LBA_FROM_CHUNK_INDEX(lns, idx)                               \
    (LNVM_GROUP_FROM_CHUNK_INDEX(lns, idx)                                \
        << (lns)->lbaf.grp_offset                                              \
        | LNVM_PUNIT_FROM_CHUNK_INDEX(lns, idx)                           \
            << (lns)->lbaf.lun_offset                                          \
        | LNVM_CHUNK_FROM_CHUNK_INDEX(lns, idx)                           \
            << (lns)->lbaf.chk_offset)

#define LNVM_LBA_FORMAT_TEMPLATE \
    "lba 0xffffffffffffffff pugrp 255 punit 255 chunk 65535 sectr 4294967295"

typedef struct LnvmMetaBlock {
    /* magic is set to (LNVM_DID << 16 | LNVM_VID) if the device as been
       initialized */
    uint32_t magic;
} LnvmMetaBlock;

typedef struct LnvmNamespace {
    LnvmIdCtrl id_ctrl;
    LnvmAddrF  lbaf;

    /* reset and write fail error probabilities indexed by namespace */
    uint8_t *resetfail;
    uint8_t *writefail;

    uint32_t chks_per_lun;
    uint32_t chks_per_grp;
    uint32_t chks_total;
    uint32_t secs_per_chk;
    uint32_t secs_per_lun;
    uint32_t secs_per_grp;
    uint32_t secs_total;

    /* chunk info log page */
    LnvmCS chunk_info[LNVM_CHUNK_INFO_LOGPAGE_SIZE / sizeof(LnvmCS)];
} LnvmNamespace;

static inline int nvme_rw_is_write(NvmeRequest *req)
{
    return req->cmd_opcode == NVME_CMD_WRITE;
}

static inline int lnvm_rw_is_write(NvmeRequest *req)
{
    return nvme_rw_is_write(req) || req->cmd_opcode == LNVM_CMD_VECT_WRITE;
}

static inline uint64_t nvme_lba_to_sector_index(NvmeCtrl *n, NvmeNamespace *ns,
    uint64_t lba)
{
    return lba;
}

static inline int lnvm_lba_valid(NvmeCtrl *n, NvmeNamespace *ns, uint64_t lba)
{
    LnvmNamespace *lns = ns->state;
    LnvmParams *params = &n->params.lnvm;

    return LNVM_LBA_GET_SECTR(lns, lba) < lns->secs_total &&
        LNVM_LBA_GET_CHUNK(lns, lba) < lns->chks_per_lun &&
        LNVM_LBA_GET_PUNIT(lns, lba) < params->num_lun &&
        LNVM_LBA_GET_GROUP(lns, lba) < params->num_grp;
}

static inline uint64_t lnvm_lba_to_chunk_index(NvmeCtrl *n, NvmeNamespace *ns,
    uint64_t lba)
{
    LnvmNamespace *lns = ns->state;

    return LNVM_LBA_GET_CHUNK(lns, lba) +
        LNVM_LBA_GET_PUNIT(lns, lba) * lns->chks_per_lun +
        LNVM_LBA_GET_GROUP(lns, lba) * lns->chks_per_grp;
}

static inline uint64_t lnvm_lba_to_sector_index(NvmeCtrl *n, NvmeNamespace *ns,
    uint64_t lba)
{
    LnvmNamespace *lns = ns->state;

    return LNVM_LBA_GET_SECTR(lns, lba) +
        LNVM_LBA_GET_CHUNK(lns, lba) * lns->secs_per_chk +
        LNVM_LBA_GET_PUNIT(lns, lba) * lns->secs_per_lun +
        LNVM_LBA_GET_GROUP(lns, lba) * lns->secs_per_grp;
}

void lnvm_post_cqe(NvmeCtrl *n, NvmeRequest *req);
uint16_t lnvm_advance_wp(NvmeCtrl *n, NvmeNamespace *ns, uint64_t lba,
    uint16_t nlb, NvmeRequest *req);
uint16_t lnvm_commit_chunk_info(NvmeCtrl *n, NvmeNamespace *ns);
LnvmCS *lnvm_chunk_get_state(NvmeCtrl *n, NvmeNamespace *ns, uint64_t lba);
uint16_t lnvm_chunk_set_free(NvmeCtrl *n, NvmeNamespace *ns, uint64_t lba,
    hwaddr mptr, NvmeRequest *req);
void lnvm_init_ctrl(NvmeCtrl *n);
void lnvm_init_pci(NvmeCtrl *n, PCIDevice *pci_dev);
int lnvm_realize(NvmeCtrl *n, Error **errp);
void lnvm_free_namespace(NvmeCtrl *n, NvmeNamespace *ns);

#endif /* HW_LIGHTNVM_H */
