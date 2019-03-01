#include "qemu/osdep.h"
#include "qemu/cutils.h"
#include "sysemu/block-backend.h"

#include "trace.h"
#include "nvme.h"
#include "lightnvm.h"

static int lnvm_lba_str(char *buf, NvmeCtrl *n, uint64_t lba)
{
    LnvmCtrl *ln = n->dialect.state;

    uint8_t pugrp, punit;
    uint16_t chunk;
    uint32_t sectr;

    pugrp = LNVM_LBA_GET_GROUP(ln, lba);
    punit = LNVM_LBA_GET_PUNIT(ln, lba);
    chunk = LNVM_LBA_GET_CHUNK(ln, lba);
    sectr = LNVM_LBA_GET_SECTR(ln, lba);

    return sprintf(buf, "lba 0x%016"PRIx64" pugrp %"PRIu8" punit %"PRIu8
        " chunk %"PRIu16" sectr %"PRIu32, lba, pugrp, punit, chunk, sectr);
}

static void lnvm_trace_rw(NvmeCtrl *n, NvmeRequest *req)
{
    char *buf = g_malloc_n(req->nlb, sizeof(LNVM_LBA_FORMAT_TEMPLATE) + 3 + 1);
    char *bufp = buf;
    for (uint16_t i = 0; i < req->nlb; i++) {
        bufp += sprintf(bufp, "\n  ");
        bufp += lnvm_lba_str(bufp, n, ((uint64_t *) req->slba)[i]);
    }

    trace_lnvm_rw(req->cqe.cid, req->cmd_opcode, req->nlb, buf);
    g_free(buf);
}

static void lnvm_trace_lba(NvmeCtrl *n, uint64_t lba, NvmeRequest *req)
{
    char *buf = g_malloc(sizeof(LNVM_LBA_FORMAT_TEMPLATE) + 1);
    lnvm_lba_str(buf, n, lba);
    trace_lnvm_addr(req->cqe.cid, buf);
    g_free(buf);
}

uint16_t lnvm_commit_chunk_info(NvmeCtrl *n, NvmeNamespace *ns)
{
    LnvmCtrl *ln = n->dialect.state;
    BlockBackend *blk = n->conf.blk;
    int written, nbytes = LNVM_CHUNK_INFO_LOGPAGE_SIZE;

    written = blk_pwrite(blk, LNVM_NS_LOGPAGE_CHUNK_INFO_BLK_OFFSET(ns),
        LNVM_NS_LOGPAGE_CHUNK_INFO(ln, ns), nbytes, 0);

    if (written != nbytes) {
        return NVME_INTERNAL_DEV_ERROR | NVME_DNR;
    }

    return NVME_SUCCESS;
}

static uint16_t lnvm_load_chunk_info(NvmeCtrl *n, NvmeNamespace *ns)
{
    LnvmCtrl *ln = n->dialect.state;
    BlockBackend *blk = n->conf.blk;

    blk_pread(blk, LNVM_NS_LOGPAGE_CHUNK_INFO_BLK_OFFSET(ns),
        LNVM_NS_LOGPAGE_CHUNK_INFO(ln, ns), LNVM_CHUNK_INFO_LOGPAGE_SIZE);

    return NVME_SUCCESS;
}

LnvmCS *lnvm_chunk_get_state(NvmeCtrl *n, NvmeNamespace *ns, uint64_t lba)
{
    LnvmCtrl *ln = n->dialect.state;
    if (!lnvm_lba_valid(n, lba)) {
        return NULL;
    }

    return LNVM_NS_LOGPAGE_CHUNK_INFO(ln, ns) +
        lnvm_lba_to_chunk_index(n, lba);
}

uint16_t lnvm_advance_wp(NvmeCtrl *n, uint64_t lba, uint16_t nlb,
    NvmeRequest *req)
{
    LnvmCS *chunk_meta;

    chunk_meta = lnvm_chunk_get_state(n, req->ns, lba);
    if (!chunk_meta) {
        trace_lnvm_err_invalid_chunk(req->cqe.cid, lba);
        return NVME_INTERNAL_DEV_ERROR | NVME_DNR;
    }

    if (chunk_meta->type == LNVM_CHUNK_TYPE_RAN) {
        /* do not modify the chunk state or write pointer for random chunks */
        return NVME_SUCCESS;
    }

    trace_lnvm_advance_wp(req->cqe.cid, lba, nlb);

    if (chunk_meta->state == LNVM_CHUNK_FREE) {
        chunk_meta->state = LNVM_CHUNK_OPEN;
    }

    if (chunk_meta->state != LNVM_CHUNK_OPEN) {
        trace_lnvm_err_invalid_chunk_state(req->cqe.cid, lba,
            chunk_meta->state);
        return NVME_INTERNAL_DEV_ERROR | NVME_DNR;
    }

    if ((chunk_meta->wp += nlb) == chunk_meta->cnlb) {
        chunk_meta->state = LNVM_CHUNK_CLOSED;
    }

    return NVME_SUCCESS;
}

static uint16_t lnvm_blk_setup(NvmeCtrl *n, QEMUSGList *qsg,
    uint64_t blk_offset, uint32_t unit_len, NvmeRequest *req)
{
    NvmeNamespace *ns = req->ns;
    NvmeBlockBackendRequest *blk_req = NULL;
    size_t curr_byte = 0;
    uint64_t last_lba;
    int curr_sge = 0;

    for (uint16_t i = 0; i < req->nlb; i++) {
        if (!req->is_write && req->predef & (1 << i)) {
            /* skip block request if dlfeat is 0x00 (predefined data not
               reported) */
            if (ns->id_ns.dlfeat) {
                if (NULL == (blk_req = nvme_blk_req_new(n, req))) {
                    return NVME_INTERNAL_DEV_ERROR;
                }

                blk_req->blk_offset = NVME_NS_PREDEF_BLK_OFFSET(n, ns);
                blk_req->slba = ((uint64_t *) req->slba)[i];

                QTAILQ_INSERT_TAIL(&req->blk_req_tailq_head, blk_req,
                    blk_req_tailq);
            } else {
                blk_req = NULL;
            }
        } else {
            // add a new block backend request if non-contiguous
            if (!blk_req || (i > 0 && last_lba + 1 != ((uint64_t *) req->slba)[i])) {
                uint64_t soffset = n->dialect.blk_idx(n, ((uint64_t *) req->slba)[i]);
                uint64_t offset = blk_offset + soffset * unit_len;

                if (NULL == (blk_req = nvme_blk_req_new(n, req))) {
                    return NVME_INTERNAL_DEV_ERROR;
                }

                blk_req->blk_offset = offset;
                blk_req->slba = ((uint64_t *) req->slba)[i];

                QTAILQ_INSERT_TAIL(&req->blk_req_tailq_head, blk_req,
                    blk_req_tailq);
            }
        }

        if (blk_req) {
            last_lba = blk_req->slba + blk_req->nlb;

            blk_req->nlb++;
        }

        qemu_sglist_yank(qsg, blk_req ? &blk_req->qsg : NULL, &curr_sge,
            &curr_byte, unit_len);
    }

    return NVME_SUCCESS;
}

static void lnvm_inject_write_err(NvmeCtrl *n, NvmeRequest *req)
{
    LnvmParams *params = &n->params.lnvm;
    NvmeNamespace *ns = req->ns;
    int req_fail = 0;

    if (ns && ns->writefail && req->is_write && req->slba) {
        for (int i = 0; i < req->nlb; i++) {
            uint64_t lba = ((uint64_t *) req->slba)[i];
            uint8_t err_prob = ns->writefail[n->dialect.blk_idx(n, lba)];

            LnvmCS *chunk_meta = lnvm_chunk_get_state(n, ns, lba);

            if (err_prob && (rand() % 100) < err_prob) {
                req_fail = 1;
            }

            if (req_fail) {
                trace_lnvm_inject_write_err(req->cqe.cid, lba);
                bitmap_set(&req->cqe.res64, i, 1);
                req->status = LNVM_CHUNK_EARLY_CLOSE;

                /* Rewind the wp since we've already advanced it */
                chunk_meta->wp--;
                chunk_meta->state = LNVM_CHUNK_CLOSED;

                if (lnvm_commit_chunk_info(n, ns)) {
                    return;
                }

                /* Fail the next erase */
                ns->resetfail[lnvm_lba_to_chunk_index(n, lba)] = 100;

                if (params->debug) {
                    lnvm_trace_lba(n, lba, req);
                }
            }
        }
    }
}

void lnvm_post_cqe(NvmeCtrl *n, NvmeRequest *req)
{
    /* Do post-completion processing depending on the type of command. This is
     * used primarily to inject different types of errors.
     */
    switch (req->cmd_opcode) {
    case NVME_CMD_WRITE:
    case LNVM_CMD_VECT_WRITE:
         lnvm_inject_write_err(n, req);
    }
}

static uint16_t lnvm_rw_check_chunk_write(NvmeCtrl *n, NvmeCmd *cmd, uint64_t lba,
    uint32_t ws, NvmeRequest *req)
{
    LnvmCtrl *ln = n->dialect.state;
    LnvmParams *params = &n->params.lnvm;
    NvmeNamespace *ns = req->ns;
    LnvmRwCmd *lrw = (LnvmRwCmd *) cmd;

    LnvmCS *cnk = lnvm_chunk_get_state(n, ns, lba);
    if (!cnk) {
        lba &= ~ln->lbaf.sec_mask;
        trace_lnvm_err_invalid_chunk(req->cqe.cid, lba);
        return NVME_WRITE_FAULT | NVME_DNR;
    }

    uint32_t start_sectr = lba & ln->lbaf.sec_mask;
    uint32_t end_sectr = start_sectr + ws;

    // check if we are at all allowed to write to the chunk
    if (cnk->state & LNVM_CHUNK_OFFLINE || cnk->state & LNVM_CHUNK_CLOSED) {
        trace_lnvm_err_invalid_chunk_state(req->cqe.cid,
            lba & ~(ln->lbaf.sec_mask), cnk->state);
        return NVME_WRITE_FAULT | NVME_DNR;
    }

    if (end_sectr > cnk->cnlb) {
        trace_lnvm_err_out_of_bounds(req->cqe.cid, end_sectr, cnk->cnlb);
        return NVME_WRITE_FAULT | NVME_DNR;
    }


    if (cnk->type == LNVM_CHUNK_TYPE_RAN) {
        /* for LNVM_CHUNK_TYPE_RAN, we skip the additional constraint checks
           and only check that the chunk is OPEN */
        if (cnk->state != LNVM_CHUNK_OPEN) {
            trace_lnvm_err_invalid_chunk_state(req->cqe.cid,
                lba & ~(ln->lbaf.sec_mask), cnk->state);
            return NVME_WRITE_FAULT | NVME_DNR;
        }

        return NVME_SUCCESS;
    }

    if (ws < params->ws_min || (ws % params->ws_min) != 0) {
        trace_lnvm_err_write_constraints(req->cqe.cid, ws, params->ws_min);
        nvme_set_error_page(n, req->sq->sqid, req->cqe.cid,
            NVME_INVALID_FIELD, offsetof(LnvmRwCmd, lbal),
            lrw->lbal + req->nlb, req->ns->id);
        return NVME_INVALID_FIELD | NVME_DNR;
    }

    // check that the write begins at the current wp
    if (start_sectr != cnk->wp) {
        trace_lnvm_err_out_of_order(req->cqe.cid, start_sectr, cnk->wp);
        return LNVM_OUT_OF_ORDER_WRITE | NVME_DNR;
    }

    return NVME_SUCCESS;
}

static uint16_t lnvm_rw_check_write_req(NvmeCtrl *n, NvmeCmd *cmd,
    NvmeRequest *req)
{
    LnvmCtrl *ln = n->dialect.state;

    uint64_t lba = ((uint64_t *) req->slba)[0];
    uint16_t chunk = LNVM_LBA_GET_CHUNK(ln, lba);
    uint32_t sectr = LNVM_LBA_GET_SECTR(ln, lba);
    uint16_t ws = 1;

    for (uint16_t i = 1; i < req->nlb; i++) {
        uint16_t next;

        /* it is assumed that LBAs for different chunks are laid out
           contiguously and sorted with increasing addresses. */
        if (chunk != (next = LNVM_LBA_GET_CHUNK(ln, ((uint64_t *) req->slba)[i]))) {
            uint16_t err = lnvm_rw_check_chunk_write(n, cmd, lba, ws, req);
            if (err) {
                return err;
            }

            lba = ((uint64_t *) req->slba)[i];
            chunk = next;
            sectr = LNVM_LBA_GET_SECTR(ln, ((uint64_t *) req->slba)[i]);
            ws = 1;

            continue;
        }

        if (++sectr != LNVM_LBA_GET_SECTR(ln, ((uint64_t *) req->slba)[i])) {
            return LNVM_OUT_OF_ORDER_WRITE | NVME_DNR;
        }

        ws++;
    }

    return lnvm_rw_check_chunk_write(n, cmd, lba, ws, req);
}

static uint16_t lnvm_rw_check_chunk_read(NvmeCtrl *n, NvmeCmd *cmd,
    NvmeRequest *req, uint64_t lba)
{
    LnvmCtrl *ln = n->dialect.state;
    LnvmParams *params = &n->params.lnvm;

    uint64_t sectr, mw_cunits, wp;
    uint8_t state;

    LnvmCS *cnk = lnvm_chunk_get_state(n, req->ns, lba);
    if (!cnk) {
        trace_lnvm_err_invalid_chunk(req->cqe.cid, lba);
        return NVME_DULB;
    }

    sectr = LNVM_LBA_GET_SECTR(ln, lba);
    mw_cunits = params->mw_cunits;
    wp = cnk->wp;
    state = cnk->state;

    if (cnk->type == LNVM_CHUNK_TYPE_RAN) {
        /* for LNVM_CHUNK_TYPE_RAN it is sufficient to ensure that the chunk is
           OPEN and that we are reading a valid LBA */
        if (state != LNVM_CHUNK_OPEN || sectr >= cnk->cnlb) {
            trace_lnvm_err_invalid_chunk_state(req->cqe.cid,
                lba & ~(ln->lbaf.sec_mask), cnk->state);
            return NVME_DULB;
        }

        return NVME_SUCCESS;
    }

    if (state == LNVM_CHUNK_CLOSED && sectr < wp) {
        return NVME_SUCCESS;
    }

    if (state == LNVM_CHUNK_OPEN) {
        if (wp < mw_cunits) {
            return NVME_DULB;
        }

        if (sectr < (wp - mw_cunits)) {
            return NVME_SUCCESS;
        }
    }

    return NVME_DULB;
}

static uint16_t lnvm_rw_check_read_req(NvmeCtrl *n, NvmeCmd *cmd,
    NvmeRequest *req)
{
    for (int i = 0; i < req->nlb; i++) {
        uint16_t err = lnvm_rw_check_chunk_read(n, cmd, req, ((uint64_t *) req->slba)[i]);
        if (err) {
            if (err & NVME_DULB) {
                req->predef |= (1 << i);
                continue;
            }

            return err;
        }
    }

    return NVME_SUCCESS;
}

static uint16_t lnvm_rw_check_vector_req(NvmeCtrl *n, NvmeCmd *cmd,
    NvmeRequest *req)
{
    int err = nvme_rw_check_req(n, cmd, req);
    if (err) {
        return err;
    }

    if (req->is_write) {
        return lnvm_rw_check_write_req(n, cmd, req);
    }

    return lnvm_rw_check_read_req(n, cmd, req);
}

uint16_t lnvm_chunk_set_free(NvmeCtrl *n, NvmeNamespace *ns, uint64_t lba,
    hwaddr mptr, NvmeRequest *req)
{
    LnvmParams *params = &n->params.lnvm;

    LnvmCS *chunk_meta;
    uint32_t resetfail_prob = 0;

    chunk_meta = lnvm_chunk_get_state(n, ns, lba);
    if (!chunk_meta) {
        trace_lnvm_err_invalid_chunk(req->cqe.cid, lba);
        return LNVM_INVALID_RESET | NVME_DNR;
    }

    if (ns->resetfail) {
        resetfail_prob = ns->resetfail[lnvm_lba_to_chunk_index(n, lba)];
    }

    if (resetfail_prob) {
        if ((rand() % 100) < resetfail_prob) {
            chunk_meta->state = LNVM_CHUNK_OFFLINE;
            chunk_meta->wp = 0xffff;
            trace_lnvm_inject_reset_err(req->cqe.cid, lba);
            return LNVM_INVALID_RESET | NVME_DNR;
        }
    }

    if (chunk_meta->state & LNVM_CHUNK_RESETABLE) {
        switch (chunk_meta->state) {
        case LNVM_CHUNK_FREE:
            trace_lnvm_double_reset(req->cqe.cid, lba);

            if (!(params->mccap & LNVM_PARAMS_MCCAP_MULTIPLE_RESETS)) {
                return LNVM_INVALID_RESET | NVME_DNR;
            }

            break;

        case LNVM_CHUNK_OPEN:
            trace_lnvm_early_reset(req->cqe.cid, lba, chunk_meta->wp);
            if (!(params->mccap & LNVM_PARAMS_MCCAP_EARLY_RESET)) {
                return LNVM_INVALID_RESET | NVME_DNR;
            }

            break;
        }

        chunk_meta->state = LNVM_CHUNK_FREE;
        chunk_meta->wear_index++;
        chunk_meta->wp = 0;

        if (mptr) {
            nvme_addr_write(ns->ctrl, mptr, chunk_meta, sizeof(*chunk_meta));
        }

        if (lnvm_commit_chunk_info(n, ns)) {
            return NVME_INTERNAL_DEV_ERROR | NVME_DNR;
        }

        return NVME_SUCCESS;
    }

    trace_lnvm_err_offline_chunk(req->cqe.cid, lba);

    return NVME_DNR | LNVM_OFFLINE_CHUNK;
}

static uint16_t lnvm_rw_check_req(NvmeCtrl *n, NvmeCmd *cmd, NvmeRequest *req)
{
    LnvmRwCmd *rw = (LnvmRwCmd *) cmd;
    LnvmParams *params = &n->params.lnvm;

    uint16_t nlb  = le16_to_cpu(rw->nlb) + 1;
    uint64_t slba = le64_to_cpu(rw->lbal);

    int err = nvme_rw_check_req(n, cmd, req);
    if (err) {
        return err;
    }

    switch (rw->opcode) {
    case NVME_CMD_WRITE:
        if (nlb < params->ws_min || nlb % params->ws_min != 0) {
            trace_lnvm_err_write_constraints(req->cqe.cid, nlb, params->ws_min);
            return NVME_INVALID_FIELD | NVME_DNR;
        }

        err = lnvm_rw_check_chunk_write(n, cmd, slba, nlb, req);
        if (err) {
            return err;
        }

        break;

    case NVME_CMD_READ:
        for (int i = 0; i < nlb; i++) {
            err = lnvm_rw_check_chunk_read(n, cmd, req, slba + i);
            if (err) {
                if (err & NVME_DULB) {
                    req->predef = slba + i;
                    if (NVME_ERR_REC_DULBE(n->features.err_rec)) {
                        return NVME_DULB | NVME_DNR;
                    }

                    break;
                }

                return err;
            }
        }

        break;
    }

    return NVME_SUCCESS;
}

static unsigned get_str(char *string, const char *key, char *value,
    size_t len)
{
    char *keyvalue = strstr(string, key);
    char format[32];

    if (!keyvalue) {
        return 0;
    }

    if (len == 0) {
        return 0;
    }

    snprintf(format, (int)sizeof(format), "%%%ds", (int)len - 1);

    return sscanf(keyvalue + strlen(key), format, value);
}

static unsigned get_unsigned(char *string, const char *key,
    unsigned int *value)
{
    char *keyvalue = strstr(string, key);
    if (!keyvalue) {
        return 0;
    }
    return sscanf(keyvalue + strlen(key), "%u", value);
}

static int get_ch_lun_chk(char *chunkinfo, unsigned int *grp,
                          unsigned int *lun, unsigned int *chk)
{
    if (!get_unsigned(chunkinfo, "grp=", grp)) {
        return 0;
    }

    if (!get_unsigned(chunkinfo, "pu=", lun)) {
        return 0;
    }

    if (!get_unsigned(chunkinfo, "chk=", chk)) {
        return 0;
    }

    return 1;
}

static int get_chunk_meta_index(NvmeCtrl *n, NvmeNamespace *ns,
    unsigned int grp, unsigned int lun, unsigned int chk)
{
    LnvmParams *params = &n->params.lnvm;

    if (chk >= params->num_chk) {
        return -1;
    }

    if (lun >= params->num_lun) {
        return -1;
    }

    if (grp >= params->num_grp) {
        return -1;
    }

    return params->num_chk * (grp * params->num_lun + lun) + chk;
}

static int get_state_id(char *state)
{
    if (!strcmp(state, "FREE")) {
        return LNVM_CHUNK_FREE;
    }

    if (!strcmp(state, "OFFLINE")) {
        return LNVM_CHUNK_OFFLINE;
    }

    if (!strcmp(state, "OPEN")) {
        return LNVM_CHUNK_OPEN;
    }

    if (!strcmp(state, "CLOSED")) {
        return LNVM_CHUNK_CLOSED;
    }

    return -1;
}

static int update_chunk(NvmeCtrl *n, NvmeNamespace *ns, char *chunkinfo)
{
    LnvmCtrl *ln = n->dialect.state;
    LnvmCS *chunk_meta;
    unsigned int grp, lun, chk, wp, wi;
    char status[16] = {0};
    char type[16] = {0};
    int state_id;
    int i;

    if (!get_ch_lun_chk(chunkinfo, &grp, &lun, &chk)) {
        return 1;
    }

    if (!get_unsigned(chunkinfo, "wi=", &wi)) {
        return 1;
    }

    if (!get_unsigned(chunkinfo, "wp=", &wp)) {
        return 1;
    }

    if (!get_str(chunkinfo, "state=", status, sizeof(type))) {
        return 1;
    }

    if (!get_str(chunkinfo, "type=", type, sizeof(type))) {
        return 1;
    }

    state_id = get_state_id(status);

    if (state_id < 0) {
        return 1;
    }

    i = get_chunk_meta_index(n, ns, grp, lun, chk);
    if (i < 0) {
        return 1;
    }

    chunk_meta = LNVM_NS_LOGPAGE_CHUNK_INFO(ln, ns) + i;
    chunk_meta->state = state_id;
    chunk_meta->wear_index = wi;
    chunk_meta->wp = wp;

    if (chunk_meta->state == LNVM_CHUNK_OFFLINE) {
        chunk_meta->wp = 0xffff;
    }

    if (strcmp(type, "W_SEQ") == 0) {
        chunk_meta->type = LNVM_CHUNK_TYPE_SEQ;
    } else if (strcmp(type, "W_RAN") == 0) {
        chunk_meta->type = LNVM_CHUNK_TYPE_RAN;
    } else {
        return 1;
    }

    return 0;
}

static int set_resetfail_chunk(NvmeCtrl *n, NvmeNamespace *ns, char *chunkinfo)
{
    unsigned int ch, lun, chk, resetfail_prob;
    int i;

    if (!get_ch_lun_chk(chunkinfo, &ch, &lun, &chk)) {
        return 1;
    }

    if (!get_unsigned(chunkinfo, "resetfail_prob=", &resetfail_prob)) {
        return 1;
    }

    if (resetfail_prob > 100) {
        return 1;
    }

    i = get_chunk_meta_index(n, ns, ch, lun, chk);
    if (i < 0) {
        return 1;
    }

    ns->resetfail[i] = resetfail_prob;

    return 0;
}

static int set_writefail_sector(NvmeCtrl *n, NvmeNamespace *ns, char *secinfo)
{
    LnvmCtrl *ln = n->dialect.state;
    LnvmParams *params = &n->params.lnvm;
    unsigned int ch, lun, chk, sec, writefail_prob;
    uint64_t lba;

    if (!get_ch_lun_chk(secinfo, &ch, &lun, &chk)) {
        return 1;
    }

    if (!get_unsigned(secinfo, "sec=", &sec)) {
        return 1;
    }

    if (sec >= params->num_sec) {
        return 1;
    }

    if (!get_unsigned(secinfo, "writefail_prob=", &writefail_prob)) {
        return 1;
    }

    if (writefail_prob > 100) {
        return 1;
    }

    lba = LNVM_LBA(ln, ch, lun, chk, sec);
    ns->writefail[lnvm_lba_to_sector_index(n, lba)] = writefail_prob;

    return 0;
}

static int lnvm_chunk_state_load(NvmeCtrl *n, NvmeNamespace *ns,
    uint32_t nr_chunks, Error **errp)
{
    LnvmParams *params = &n->params.lnvm;
    char line[256];
    FILE *fp;

    if (!params->chunkstate_fname) {
        return 0;
    }

    fp = fopen(params->chunkstate_fname, "r+");
    if (!fp) {
        error_setg(errp, "could not open chunk state file");
        return 1;
    }

    while (fgets(line, sizeof(line), fp)) {
        if (update_chunk(n, ns, line)) {
            error_setg(errp, "could not parse chunk state line: %s", line);
            return 1;
        }
    }

    fclose(fp);
    return 0;
}

static int lnvm_resetfail_load(NvmeCtrl *n, NvmeNamespace *ns, Error **errp)
{
    LnvmParams *params = &n->params.lnvm;
    FILE *fp;
    char line[256];

    if (!params->resetfail_fname) {
        return 0;
    }

    fp = fopen(params->resetfail_fname, "r");
    if (!fp) {
        error_setg(errp, "could not open resetfail file");
        return 1;
    }

    while (fgets(line, sizeof(line), fp)) {
        if (set_resetfail_chunk(n, ns, line)) {
            error_setg(errp, "could not parse resetfail line: %s", line);
            return 1;
        }
    }

    fclose(fp);
    return 0;
}

static int lnvm_writefail_load(NvmeCtrl *n, NvmeNamespace *ns, Error **errp)
{
    LnvmParams *params = &n->params.lnvm;
    FILE *fp;
    char line[256];

    if (!params->writefail_fname) {
        return 0;
    }

    fp = fopen(params->writefail_fname, "r");
    if (!fp) {
        error_setg(errp, "could not open writefail file");
        return 1;
    }

    while (fgets(line, sizeof(line), fp)) {
        if (set_writefail_sector(n, ns, line)) {
            error_setg(errp, "could not parse writefail line: %s", line);
            return 1;
        }
    }

    fclose(fp);
    return 0;
}

static uint16_t lnvm_rw(NvmeCtrl *n, NvmeCmd *cmd, NvmeRequest *req)
{
    LnvmRwCmd *lrw = (LnvmRwCmd *)cmd;
    LnvmParams *params = &n->params.lnvm;

    uint32_t nlb  = le16_to_cpu(lrw->nlb) + 1;
    uint64_t lbal = le64_to_cpu(lrw->lbal);
    uint16_t err;

    if (nlb > LNVM_CMD_MAX_LBAS) {
        trace_lnvm_err(req->cqe.cid, "LNVM_CMD_MAX_LBAS exceeded",
            NVME_INVALID_FIELD | NVME_DNR);
        nvme_set_error_page(n, req->sq->sqid, req->cqe.cid, NVME_INVALID_FIELD,
                offsetof(LnvmRwCmd, lbal), 0, req->ns->id);
        return NVME_INVALID_FIELD | NVME_DNR;
    }

    req->predef = 0;
    req->nlb = nlb;
    req->slba = (uint64_t) g_malloc_n(nlb, sizeof(uint64_t));

    if (lnvm_rw_is_write(req)) {
        req->is_write = 1;
    }

    if (nlb > 1) {
        uint32_t len = nlb * sizeof(uint64_t);

        if (cmd->psdt && params->sgl_lbal) {
            NvmeSglDescriptor sgl;

            nvme_addr_read(n, lbal, &sgl, sizeof(NvmeSglDescriptor));

            err = nvme_dma_read_sgl(n, (uint8_t *) req->slba, len, sgl, req);
            if (err) {
                if (err & NVME_DATA_SGL_LENGTH_INVALID) {
                    err &= ~NVME_DATA_SGL_LENGTH_INVALID;
                    err |= LNVM_LBAL_SGL_LENGTH_INVALID;
                }

                nvme_set_error_page(n, req->sq->sqid, req->cqe.cid, err,
                    offsetof(LnvmRwCmd, lbal), 0, req->ns->id);

                return err;
            }
        } else {
            nvme_addr_read(n, lbal, (void *) req->slba, len);
        }
    } else {
        ((uint64_t *) req->slba)[0] = lbal;
    }

    if (trace_event_get_state_backends(TRACE_LNVM_RW)) {
        lnvm_trace_rw(n, req);
    }

    err = lnvm_rw_check_vector_req(n, cmd, req);
    if (err) {
        trace_lnvm_err(req->cqe.cid, "lnvm_rw_check_vector_req", err);
        return err;
    }

    for (uint32_t i = 0; i < nlb; i++) {
        if ((req->predef & (1 << i)) && !req->is_write) {
            if (NVME_ERR_REC_DULBE(n->features.err_rec)) {
               return NVME_DULB | NVME_DNR;
            }
        }
    }

    err = nvme_blk_map(n, cmd, req, lnvm_blk_setup);
    if (err) {
        trace_lnvm_err(req->cqe.cid, "nvme_map", err);
        return err;
    }

    return nvme_blk_submit_io(n, req);
}

static uint16_t lnvm_identify(NvmeCtrl *n, NvmeCmd *cmd, NvmeRequest *req)
{
    LnvmCtrl *ln = n->dialect.state;
    uint32_t nsid = le32_to_cpu(cmd->nsid);

    if (unlikely(nsid == 0 || nsid > n->params.num_namespaces)) {
        return NVME_INVALID_NSID | NVME_DNR;
    }

    return nvme_dma_read(n, (uint8_t *) &ln->id_ctrl,
        sizeof(LnvmIdCtrl), cmd, req);
}

static uint16_t lnvm_erase(NvmeCtrl *n, NvmeCmd *cmd, NvmeRequest *req)
{
    LnvmRwCmd *dm = (LnvmRwCmd *)cmd;
    hwaddr mptr = le64_to_cpu(cmd->mptr);
    uint64_t lbal = le64_to_cpu(dm->lbal);
    uint32_t nlb = le16_to_cpu(dm->nlb) + 1;
    uint8_t lbads = NVME_ID_NS_LBADS(req->ns);
    uint64_t sectr_idx;

    req->nlb = nlb;
    req->slba = (uint64_t) g_malloc_n(nlb, sizeof(uint64_t));

    if (nlb > 1) {
        nvme_addr_read(n, lbal, (void *) req->slba, nlb * sizeof(void *));
    } else {
        ((uint64_t *) req->slba)[0] = lbal;
    }

    for (int i = 0; i < nlb; i++) {
        LnvmCS *cs;
        NvmeBlockBackendRequest *blk_req = nvme_blk_req_new(n, req);

        if (NULL == (cs = lnvm_chunk_get_state(n, req->ns, ((uint64_t *) req->slba)[i]))) {
            return LNVM_INVALID_RESET;
        }

        int err = lnvm_chunk_set_free(n, req->ns, ((uint64_t *) req->slba)[i], mptr, req);
        if (err) {
            return err;
        }

        if (mptr) {
            mptr += sizeof(LnvmCS);
        }

        sectr_idx = n->dialect.blk_idx(n, ((uint64_t *) req->slba)[i]);

        QTAILQ_INSERT_TAIL(&req->blk_req_tailq_head, blk_req,
            blk_req_tailq);

        blk_req->aiocb = blk_aio_pdiscard(n->conf.blk,
            req->ns->blk.data + (sectr_idx << lbads),
            cs->cnlb << lbads, nvme_discard_cb, blk_req);
    }

    return NVME_NO_COMPLETE;
}

static uint16_t lnvm_chunk_info(NvmeCtrl *n, NvmeCmd *cmd,
    uint32_t buf_len, uint64_t off, NvmeRequest *req)
{
    LnvmCtrl *ln = n->dialect.state;
    LnvmParams *params = &n->params.lnvm;
    NvmeNamespace *ns;
    uint8_t *log_page;
    uint32_t log_len, trans_len, nsid;
    uint16_t ret;

    nsid = le32_to_cpu(cmd->nsid);
    if (unlikely(nsid == 0 || nsid > n->params.num_namespaces)) {
        return NVME_INVALID_NSID | NVME_DNR;
    }

    ns = &n->namespaces[nsid - 1];

    log_len = params->chks_total * sizeof(LnvmCS);
    trans_len = MIN(log_len, buf_len);

    log_page = (uint8_t *) LNVM_NS_LOGPAGE_CHUNK_INFO(ln, ns) + off;

    if (cmd->opcode == NVME_ADM_CMD_GET_LOG_PAGE) {
        return nvme_dma_read(n, log_page, trans_len, cmd, req);
    }

    ret = nvme_dma_write(n, log_page, trans_len, cmd, req);
    if (ret) {
        return ret;
    }

    if (lnvm_commit_chunk_info(n, ns)) {
        return NVME_INTERNAL_DEV_ERROR | NVME_DNR;
    }

    return NVME_SUCCESS;
}

static uint16_t lnvm_get_log(NvmeCtrl *n, NvmeCmd *cmd, NvmeRequest *req)
{
    uint32_t dw10 = le32_to_cpu(cmd->cdw10);
    uint32_t dw11 = le32_to_cpu(cmd->cdw11);
    uint32_t dw12 = le32_to_cpu(cmd->cdw12);
    uint32_t dw13 = le32_to_cpu(cmd->cdw13);
    uint16_t lid = dw10 & 0xff;
    uint32_t numdl, numdu, len;
    uint64_t off, lpol, lpou;

    numdl = (dw10 >> 16);
    numdu = (dw11 & 0xffff);
    lpol = dw12;
    lpou = dw13;

    len = (((numdu << 16) | numdl) + 1) << 2;
    off = (lpou << 32ULL) | lpol;

    switch (lid) {
    case LNVM_CHUNK_INFO:
        return lnvm_chunk_info(n, cmd, len, off, req);
    default:
        return NVME_INVALID_LOG_ID | NVME_DNR;
    }
}

static uint16_t lnvm_set_log(NvmeCtrl *n, NvmeCmd *cmd, NvmeRequest *req)
{
    uint32_t dw10 = le32_to_cpu(cmd->cdw10);
    uint32_t dw11 = le32_to_cpu(cmd->cdw11);
    uint32_t dw12 = le32_to_cpu(cmd->cdw12);
    uint32_t dw13 = le32_to_cpu(cmd->cdw13);
    uint16_t lid = dw10 & 0xff;
    uint32_t numdl, numdu, len;
    uint64_t off, lpol, lpou;

    /* NVMe R1.3 */
    numdl = (dw10 >> 16);
    numdu = (dw11 & 0xffff);
    lpol = dw12;
    lpou = dw13;

    len = (((numdu << 16) | numdl) + 1) << 2;
    off = (lpou << 32ULL) | lpol;

    switch (lid) {
    case LNVM_CHUNK_INFO:
        return lnvm_chunk_info(n, cmd, len, off, req);
    default:
        return NVME_INVALID_LOG_ID | NVME_DNR;
    }
}

static uint16_t lnvm_admin_cmd(NvmeCtrl *n, NvmeCmd *cmd, NvmeRequest *req)
{
    switch (cmd->opcode) {
    case LNVM_ADM_CMD_IDENTIFY:
        return lnvm_identify(n, cmd, req);
    case LNVM_ADM_CMD_SET_LOG_PAGE:
        return lnvm_set_log(n, cmd, req);
    default:
        return NVME_INVALID_OPCODE | NVME_DNR;
    }
}

static uint16_t lnvm_io_cmd(NvmeCtrl *n, NvmeCmd *cmd, NvmeRequest *req)
{
    switch (cmd->opcode) {
    case LNVM_CMD_VECT_READ:
    case LNVM_CMD_VECT_WRITE:
        return lnvm_rw(n, cmd, req);
    case LNVM_CMD_VECT_ERASE:
        return lnvm_erase(n, cmd, req);
    default:
        return NVME_INVALID_OPCODE | NVME_DNR;
    }
}

static int lnvm_init_namespace(NvmeCtrl *n, NvmeNamespace *ns, Error **errp)
{
    LnvmCtrl *ln = n->dialect.state;
    LnvmParams *params = &n->params.lnvm;

    LnvmIdCtrl *id_ctrl = &ln->id_ctrl;
    LnvmIdGeo *id_geo = &ln->id_ctrl.geo;
    LnvmIdWrt *id_wrt = &ln->id_ctrl.wrt;
    LnvmIdPerf *id_perf = &ln->id_ctrl.perf;
    NvmeIdNs *id_ns = &ns->id_ns;

    LnvmAddrF *lbaf = &ln->lbaf;

    uint64_t nchks;

    ns->ctrl = n;

    /* recalculate number of blocks to account for the predefined block, the
       lightnvm meta data block and the chunk info log page */
    ns->ns_blks = nvme_ns_calc_blks(n, ns) -
        (2 + LNVM_CHUNK_INFO_LOGPAGE_SIZE / NVME_ID_NS_LBADS_BYTES(ns));

    ns->blk.data = ns->blk.begin + (2 * NVME_ID_NS_LBADS_BYTES(ns)) +
        LNVM_CHUNK_INFO_LOGPAGE_SIZE;
    ns->blk.meta = ns->blk.data + NVME_ID_NS_LBADS_BYTES(ns) * ns->ns_blks;

    nchks = ns->ns_blks / params->num_sec;

    if (nchks > (LNVM_CHUNK_INFO_LOGPAGE_SIZE / sizeof(LnvmCS))) {
        error_setg(errp, "too many chunks (%ld); max is %ld", nchks,
            LNVM_CHUNK_INFO_LOGPAGE_SIZE / sizeof(LnvmCS));
        return 1;
    }

    ln->id_ctrl.ver.major = 0x2;
    ln->id_ctrl.ver.minor = 0x0;

    if (params->early_reset) {
        params->mccap |= LNVM_PARAMS_MCCAP_EARLY_RESET;
    }

    ln->id_ctrl.mccap = cpu_to_le32(params->mccap);

    params->num_chk = nchks / (params->num_lun * params->num_grp);

    id_geo->num_grp = cpu_to_le16(params->num_grp);
    id_geo->num_lun = cpu_to_le16(params->num_lun);
    id_geo->num_chk = cpu_to_le32(params->num_chk);
    id_geo->clba = cpu_to_le32(params->num_sec);

    id_wrt->ws_min = cpu_to_le32(params->ws_min);
    id_wrt->ws_opt = cpu_to_le32(params->ws_opt);
    id_wrt->mw_cunits = cpu_to_le32(params->mw_cunits);

    id_perf->trdt = cpu_to_le32(70000);
    id_perf->trdm = cpu_to_le32(100000);
    id_perf->tprt = cpu_to_le32(1900000);
    id_perf->tprm = cpu_to_le32(3500000);
    id_perf->tbet = cpu_to_le32(3000000);
    id_perf->tbem = cpu_to_le32(3000000);

    /* calculated values */
    params->chks_per_lun = params->num_chk;
    params->chks_per_grp = params->chks_per_lun * params->num_lun;
    params->chks_total   = params->chks_per_grp * params->num_grp;
    params->secs_per_chk = params->num_sec;
    params->secs_per_lun = params->secs_per_chk * params->num_chk;
    params->secs_per_grp = params->secs_per_lun * params->num_lun;
    params->secs_total   = params->secs_per_grp * params->num_sec;

    /* calculate optimal LBAF */
    id_ctrl->lbaf.sec_len = 32 - clz32(params->num_sec - 1);
    id_ctrl->lbaf.chk_len = 32 - clz32(params->num_chk - 1);
    id_ctrl->lbaf.lun_len = 32 - clz32(params->num_lun - 1);
    id_ctrl->lbaf.grp_len = 32 - clz32(params->num_grp - 1);

    /* Address format: GRP | LUN | CHK | SEC */
    lbaf->sec_offset = 0;
    lbaf->chk_offset = id_ctrl->lbaf.sec_len;
    lbaf->lun_offset = id_ctrl->lbaf.sec_len + id_ctrl->lbaf.chk_len;
    lbaf->grp_offset = id_ctrl->lbaf.sec_len +
                            id_ctrl->lbaf.chk_len +
                            id_ctrl->lbaf.lun_len;

    /* Address component selection MASK */
    lbaf->grp_mask = ((1 << id_ctrl->lbaf.grp_len) - 1) <<
                                                    lbaf->grp_offset;
    lbaf->lun_mask = ((1 << id_ctrl->lbaf.lun_len) - 1) <<
                                                    lbaf->lun_offset;
    lbaf->chk_mask = ((1 << id_ctrl->lbaf.chk_len) - 1) <<
                                                    lbaf->chk_offset;
    lbaf->sec_mask = ((1 << id_ctrl->lbaf.sec_len) - 1) <<
                                                    lbaf->sec_offset;

    /* report size of address space */
    id_ns->nuse = id_ns->ncap = id_ns->nsze =
        1ULL << (id_ctrl->lbaf.sec_len + id_ctrl->lbaf.chk_len +
        id_ctrl->lbaf.lun_len + id_ctrl->lbaf.grp_len);

    /* initialize the chunk info log page if needed */
    LnvmMetaBlock metablk;
    blk_pread(n->conf.blk, LNVM_NS_LNVM_METADATA_BLK_OFFSET(ns), &metablk,
        sizeof(metablk));
    if (metablk.magic != LNVM_MAGIC) {
        LnvmCS *cs = LNVM_NS_LOGPAGE_CHUNK_INFO(ln, ns);

        for (int i = 0; i < params->chks_total; i++) {
            cs[i].state = LNVM_CHUNK_FREE;
            cs[i].type = LNVM_CHUNK_TYPE_SEQ;
            cs[i].wear_index = 0;
            cs[i].slba = LNVM_LBA_FROM_CHUNK_INDEX(ln, params, i);
            cs[i].cnlb = params->num_sec;
            cs[i].wp = 0;
        }

        if (lnvm_commit_chunk_info(n, ns)) {
            error_setg(errp, "nvme: could not commit chunk info");
            return 1;
        }

        /* write magic to meta block to mark initialization */
        metablk.magic = LNVM_MAGIC;
        blk_pwrite(n->conf.blk, LNVM_NS_LNVM_METADATA_BLK_OFFSET(ns), &metablk,
            sizeof(metablk), 0);
    } else {
        if (lnvm_load_chunk_info(n, ns)) {
            error_setg(errp, "nvme: could not load chunk info");
            return 1;
        }
    }

    /* overwrite chunk states if indicated by parameters */
    if (params->chunkstate_fname) {
        if (lnvm_chunk_state_load(n, ns, params->chks_total, errp)) {
            return 1;
        }

        if (lnvm_commit_chunk_info(n, ns)) {
            error_setg(errp, "nvme: could not commit chunk info");
            return 1;
        }
    }

    ns->resetfail = NULL;
    if (params->resetfail_fname) {
        ns->resetfail = g_malloc0_n(params->chks_total, sizeof(*ns->resetfail));
        if (!ns->resetfail) {
            error_setg(errp, "nvme: could not allocate memory");
            return 1;
        }

        if (lnvm_resetfail_load(n, ns, errp)) {
            return 1;
        }
    }

    ns->writefail = NULL;
    if (params->writefail_fname) {
        ns->writefail = g_malloc0_n(ns->ns_blks, sizeof(*ns->writefail));
        if (!ns->writefail) {
            error_setg(errp, "nvme: could not allocate memory");
            return 1;
        }

        if (lnvm_writefail_load(n, ns, errp)) {
            return 1;
        }

        /* We fail resets for a chunk after a write failure to it, so make
            * sure to allocate the resetfailure buffer if it has not been
            * already
            */
        if (!ns->resetfail) {
            ns->resetfail = g_malloc0_n(params->chks_total,
                sizeof(*ns->resetfail));
        }
    }

    return 0;
}

static int lnvm_init_namespaces(NvmeCtrl *n, Error **errp)
{

    LnvmCtrl *ln = n->dialect.state;
    ln->chunk_info = g_malloc0_n(n->params.num_namespaces,
        sizeof(*ln->chunk_info));

    for (int i = 0; i < n->params.num_namespaces; i++) {
        NvmeNamespace *ns = &n->namespaces[i];

        if (lnvm_init_namespace(n, ns, errp)) {
            return 1;
        }
    }

    return 0;
}

int lnvm_init(NvmeCtrl *n, Error **errp)
{
    LnvmCtrl *ln = g_malloc0(sizeof(*ln));
    n->dialect = (NvmeDialect) {
        .state        = ln,

        .blk_idx      = lnvm_lba_to_sector_index,
        .rw_check_req = lnvm_rw_check_req,
        .admin_cmd    = lnvm_admin_cmd,
        .io_cmd       = lnvm_io_cmd,
        .get_log      = lnvm_get_log
    };

    if (lnvm_init_namespaces(n, errp)) {
        return 1;
    }

    return 0;
}

void lnvm_init_ctrl(NvmeCtrl *n)
{
    NvmeIdCtrl *id = &n->id_ctrl;

    strpadcpy((char *)id->mn, sizeof(id->mn), "QEMU NVMe OCSSD Ctrl", ' ');
    strpadcpy((char *)id->fr, sizeof(id->fr), "2.0", ' ');
}

void lnvm_init_pci(NvmeCtrl *n, PCIDevice *pci_dev)
{
    uint8_t *pci_conf = pci_dev->config;
    pci_config_set_vendor_id(pci_conf, LNVM_VID);
    pci_config_set_device_id(pci_conf, LNVM_DID);
}
