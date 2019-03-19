#ifndef BLOCK_LIGHTNVM_H
#define BLOCK_LIGHTNVM_H

#include "qemu/compiler.h"
#include "block/nvme.h"

#define LNVM_VID 0x1d1d
#define LNVM_DID 0x1f1f

#define LNVM_MAGIC ('L' << 24 | 'N' << 16 | 'V' << 8 | 'M')

enum LnvmAdminCommands {
    LNVM_ADM_CMD_IDENTIFY       = 0xe2,
    LNVM_ADM_CMD_SET_LOG_PAGE   = 0xc1,
};

enum LnvmIoCommands {
    LNVM_CMD_VECT_ERASE         = 0x90,
    LNVM_CMD_VECT_WRITE         = 0x91,
    LNVM_CMD_VECT_READ          = 0x92,
};

enum LnvmMetaStates {
    LNVM_SEC_UNKNOWN = 0x0,
    LNVM_SEC_WRITTEN = 0xAC,
    LNVM_SEC_ERASED = 0xDC,
};

enum LnvmChunkStates {
    LNVM_CHUNK_FREE     = 1 << 0,
    LNVM_CHUNK_CLOSED   = 1 << 1,
    LNVM_CHUNK_OPEN     = 1 << 2,
    LNVM_CHUNK_OFFLINE  = 1 << 3,
};

#define LNVM_CHUNK_RESETABLE \
    (LNVM_CHUNK_FREE | LNVM_CHUNK_CLOSED | LNVM_CHUNK_OPEN)

enum LnvmChunkTypes {
    LNVM_CHUNK_TYPE_SEQ = 1 << 0,
    LNVM_CHUNK_TYPE_RAN = 1 << 1,
    LNVM_CHUNK_TYPE_SRK = 1 << 4,
};

enum LnvmStatusCodes {
    LNVM_LBAL_SGL_LENGTH_INVALID     = 0x01c1,

    LNVM_WRITE_NEXT_UNIT             = 0x02f0,
    LNVM_CHUNK_EARLY_CLOSE           = 0x02f1,
    LNVM_OUT_OF_ORDER_WRITE          = 0x02f2,
    LNVM_OFFLINE_CHUNK               = 0x02c0,
    LNVM_INVALID_RESET               = 0x02c1,
};

typedef struct LnvmChunkState {
    uint8_t state;
    uint8_t type;
    uint8_t wear_index;
    uint8_t rsvd[5];
    uint64_t slba;
    uint64_t cnlb;
    uint64_t wp;
} LnvmCS;

typedef struct LnvmRwCmd {
    uint16_t    opcode :  8;
    uint16_t    fuse   :  2;
    uint16_t    rsvd1  :  4;
    uint16_t    psdt   :  2;
    uint16_t    cid;
    uint32_t    nsid;
    uint64_t    rsvd2;
    uint64_t    metadata;
    NvmeCmdDptr dptr;
    uint64_t    lbal;
    uint16_t    nlb;
    uint16_t    control;
    uint32_t    rsvd3;
    uint64_t    rsvd4;
} LnvmRwCmd;

typedef struct LnvmDmCmd {
    uint8_t  opcode;
    uint8_t  flags;
    uint16_t cid;
    uint32_t nsid;
    uint32_t rsvd1[8];
    uint64_t spba;
    uint32_t nlb;
    uint32_t rsvd2[3];
} LnvmDmCmd;

typedef struct LnvmAddrF {
    uint64_t grp_mask;
    uint64_t lun_mask;
    uint64_t chk_mask;
    uint64_t sec_mask;
    uint8_t  grp_offset;
    uint8_t  lun_offset;
    uint8_t  chk_offset;
    uint8_t  sec_offset;
} LnvmAddrF;

typedef struct LnvmIdGeo {
    uint16_t num_grp;
    uint16_t num_lun;
    uint32_t num_chk;
    uint32_t clba;
    uint8_t  rsvd[52];
} LnvmIdGeo;

typedef struct LnvmIdWrt {
    uint32_t ws_min;
    uint32_t ws_opt;
    uint32_t mw_cunits;
    uint8_t  rsvd[52];
} LnvmIdWrt;

typedef struct LnvmIdPerf {
    uint32_t trdt;
    uint32_t trdm;
    uint32_t tprt;
    uint32_t tprm;
    uint32_t tbet;
    uint32_t tbem;
    uint8_t  rsvd[40];
} LnvmIdPerf;

typedef struct LnvmIdLBAF {
    uint8_t grp_len;
    uint8_t lun_len;
    uint8_t chk_len;
    uint8_t sec_len;
    uint8_t rsvd[4];
} LnvmIdLBAF;

typedef struct LnvmHeader {
    uint32_t magic;
    uint32_t version;
    uint32_t num_namespaces;
    uint32_t rsvd;
    uint64_t sector_size;
    uint32_t md_size;
    uint64_t ns_size;
} LnvmHeader;

typedef struct LnvmNamespaceGeometry {
    struct {
        uint8_t major;
        uint8_t minor;
    } ver;
    uint8_t    rsvd1[6];
    LnvmIdLBAF lbaf;
    uint32_t   mccap;
    uint8_t    rsvd2[12];
    uint8_t    wit;
    uint8_t    rsvd3[31];
    LnvmIdGeo  geo;
    LnvmIdWrt  wrt;
    LnvmIdPerf perf;
    uint8_t    rsvd4[3840];
} LnvmNamespaceGeometry;

enum LnvmParamsMccap {
    LNVM_PARAMS_MCCAP_MULTIPLE_RESETS = 0x1 << 1,

    /* OCSSD 2.0 spec de-facto extension */
    LNVM_PARAMS_MCCAP_EARLY_RESET = 0x1 << 2,
};

enum LnvmLogPage {
    LNVM_CHUNK_INFO = 0xCA,
};

static inline void _lnvm_check_size(void)
{
    QEMU_BUILD_BUG_ON(sizeof(LnvmIdLBAF) != 8);
    QEMU_BUILD_BUG_ON(sizeof(LnvmIdGeo)  != 64);
    QEMU_BUILD_BUG_ON(sizeof(LnvmIdWrt)  != 64);
    QEMU_BUILD_BUG_ON(sizeof(LnvmIdPerf) != 64);
    QEMU_BUILD_BUG_ON(sizeof(LnvmRwCmd)  != 64);
    QEMU_BUILD_BUG_ON(sizeof(LnvmDmCmd)  != 64);
    QEMU_BUILD_BUG_ON(sizeof(LnvmNamespaceGeometry) != 4096);
    QEMU_BUILD_BUG_ON(sizeof(LnvmCS)     != 32);
}

#endif
