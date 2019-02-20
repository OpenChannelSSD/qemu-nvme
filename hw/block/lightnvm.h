#ifndef HW_LIGHTNVM_H
#define HW_LIGHTNVM_H

#include <stdint.h>
#include <stdio.h>

#include "block/lightnvm.h"

#define LNVM_CMD_MAX_LBAS 64
#define LNVM_CHUNK_INFO_LOGPAGE_SIZE (2 << 16)
#define LNVM_MAGIC (LNVM_DID << 16 | LNVM_VID)

#define DEFINE_LNVM_PROPERTIES(_state, _props) \
    DEFINE_PROP_UINT32("lmccap", _state, _props.mccap, 0x0), \
    DEFINE_PROP_UINT32("lws_min", _state, _props.ws_min, 4), \
    DEFINE_PROP_UINT32("lws_opt", _state, _props.ws_opt, 8), \
    DEFINE_PROP_UINT32("lmw_cunits", _state, _props.mw_cunits, 32), \
    DEFINE_PROP_UINT16("lnum_grp", _state, _props.num_grp, 1), \
    DEFINE_PROP_UINT16("lnum_pu", _state, _props.num_lun, 1), \
    DEFINE_PROP_UINT32("lnum_sec", _state, _props.num_sec, 4096), \
    DEFINE_PROP_UINT32("lsec_size", _state, _props.sec_size, 4096), \
    DEFINE_PROP_STRING("lresetfail", _state, _props.resetfail_fname), \
    DEFINE_PROP_STRING("lwritefail", _state, _props.writefail_fname), \
    DEFINE_PROP_STRING("lchunkstate", _state, _props.chunkstate_fname), \
    DEFINE_PROP_UINT8("ldebug", _state, _props.debug, 0), \
    DEFINE_PROP_UINT8("learly_reset", _state, _props.early_reset, 1), \
    DEFINE_PROP_UINT8("lsgl_lbal", _state, _props.sgl_lbal, 0)

typedef struct LnvmParams {
    /* qemu configurable device characteristics */
    uint32_t sec_size;
    uint32_t mccap;
    uint16_t num_grp;
    uint16_t num_lun;
    uint32_t num_chk;
    uint32_t num_sec;
    uint32_t ws_min;
    uint32_t ws_opt;
    uint32_t mw_cunits;

    uint8_t debug;
    uint8_t early_reset;
    uint8_t	sgl_lbal;

    char *chunkstate_fname;
    char *resetfail_fname;
    char *writefail_fname;

    /* derived values */
    uint32_t chks_per_lun;
    uint32_t chks_per_grp;
    uint32_t chks_total;
    uint32_t secs_per_chk;
    uint32_t secs_per_lun;
    uint32_t secs_per_grp;
    uint32_t secs_total;
} LnvmParams;

typedef struct LnvmMetaBlock {
    /* magic is set to (LNVM_DID << 16 | LNVM_VID) if the device as been
       initialized */
    uint32_t magic;
} LnvmMetaBlock;

typedef struct LnvmCtrl {
    LnvmIdCtrl id_ctrl;
    LnvmAddrF  lbaf;

    /* chunk info log pages indexed by namespaces */
    LnvmCS (*chunk_info)[LNVM_CHUNK_INFO_LOGPAGE_SIZE / sizeof(LnvmCS)];
} LnvmCtrl;

#endif /* HW_LIGHTNVM_H */
