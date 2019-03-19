#ifndef HW_LIGHTNVM_H
#define HW_LIGHTNVM_H

#include <stdint.h>
#include <stdio.h>

#include "qapi/error.h"

#include "nvme.h"
#include "block/lightnvm.h"

#define LNVM_CMD_MAX_LBAS 64

#define LNVM_NS_LOGPAGE_CHUNK_INFO_BLK_OFFSET(ns)                             \
    ((ns)->blk.begin + sizeof(LnvmNamespaceGeometry))

#define LNVM_LBA_GET_SECTR(lbaf, lba) \
    ((lba & (lbaf)->sec_mask) \
        >> (lbaf)->sec_offset)

#define LNVM_LBA_GET_CHUNK(lbaf, lba) \
    ((lba & (lbaf)->chk_mask) \
        >> (lbaf)->chk_offset)

#define LNVM_LBA_GET_PUNIT(lbaf, lba) \
    ((lba & (lbaf)->lun_mask) \
        >> (lbaf)->lun_offset)

#define LNVM_LBA_GET_GROUP(lbaf, lba) \
    (lba >> (lbaf)->grp_offset)

#define LNVM_LBA(lbaf, group, punit, chunk, sectr) \
    (sectr << (lbaf)->sec_offset \
        | chunk << (lbaf)->chk_offset \
        | punit << (lbaf)->lun_offset \
        | group << (lbaf)->grp_offset)

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

typedef struct LnvmCtrl {
    LnvmHeader blk_hdr;
} LnvmCtrl;

typedef struct LnvmNamespace {
    LnvmNamespaceGeometry id_ctrl;
    LnvmAddrF  lbaf;

    /* reset and write fail error probabilities indexed by namespace */
    uint8_t *resetfail;
    uint8_t *writefail;

    /* derived values (for convenience) */
    uint32_t chks_per_grp;
    uint32_t chks_total;
    uint32_t secs_per_chk;
    uint32_t secs_per_lun;
    uint32_t secs_per_grp;
    uint32_t secs_total;

    /* chunk info log page */
    uint64_t chunkinfo_size;
    LnvmCS *chunk_info;
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
    LnvmIdGeo *geo = &lns->id_ctrl.geo;
    LnvmAddrF *addrf = &lns->lbaf;

    return LNVM_LBA_GET_SECTR(addrf, lba) < geo->clba &&
        LNVM_LBA_GET_CHUNK(addrf, lba) < geo->num_chk &&
        LNVM_LBA_GET_PUNIT(addrf, lba) < geo->num_lun &&
        LNVM_LBA_GET_GROUP(addrf, lba) < geo->num_grp;
}

static inline uint64_t lnvm_lba_to_chunk_index(NvmeCtrl *n, NvmeNamespace *ns,
    uint64_t lba)
{
    LnvmNamespace *lns = ns->state;
    LnvmIdGeo *geo = &lns->id_ctrl.geo;
    LnvmAddrF *addrf = &lns->lbaf;

    return LNVM_LBA_GET_CHUNK(addrf, lba) +
        LNVM_LBA_GET_PUNIT(addrf, lba) * geo->num_chk +
        LNVM_LBA_GET_GROUP(addrf, lba) * lns->chks_per_grp;
}

static inline uint64_t lnvm_lba_to_sector_index(NvmeCtrl *n, NvmeNamespace *ns,
    uint64_t lba)
{
    LnvmNamespace *lns = ns->state;
    LnvmAddrF *addrf = &lns->lbaf;

    return LNVM_LBA_GET_SECTR(addrf, lba) +
        LNVM_LBA_GET_CHUNK(addrf, lba) * lns->secs_per_chk +
        LNVM_LBA_GET_PUNIT(addrf, lba) * lns->secs_per_lun +
        LNVM_LBA_GET_GROUP(addrf, lba) * lns->secs_per_grp;
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
