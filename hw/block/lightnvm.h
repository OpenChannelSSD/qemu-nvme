#ifndef HW_LIGHTNVM_H
#define HW_LIGHTNVM_H

#include <stdint.h>
#include <stdio.h>

#include "block/lightnvm.h"

#define LNVM_CMD_MAX_LBAS 64

typedef struct LnvmCtrl {
    LnvmParams     params;
    LnvmIdCtrl     id_ctrl;
    LnvmAddrF      lbaf;
    uint8_t        bbt_gen_freq;
    uint8_t        meta_auto_gen;
    uint8_t        debug;
    uint8_t        early_reset;
    uint8_t        state_auto_gen;
    char           *chunk_fname;
    char           *resetfail_fname;
    char           *writefail_fname;
} LnvmCtrl;


#endif
