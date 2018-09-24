#ifndef HW_NVME_H
#define HW_NVME_H

#include "block/nvme.h"
typedef struct NvmeAsyncEvent {
    QSIMPLEQ_ENTRY(NvmeAsyncEvent) entry;
    NvmeAerResult result;
} NvmeAsyncEvent;

typedef struct NvmeRequest {
    struct NvmeSQueue       *sq;
    struct NvmeNamespace    *ns;
    BlockAIOCB               *aiocb;
    uint8_t                 cmd_opcode;
    uint16_t                status;
    uint64_t                slba;
    uint16_t                is_write;
    uint16_t                nlb;
    uint8_t                 *is_predefined;
    uint16_t                ctrl;
    uint64_t                meta_size;
    uint64_t                mptr;
    void                    *meta_buf;
    uint64_t                lnvm_slba;
    bool                    has_sg;
    NvmeCqe                 cqe;
    BlockAcctCookie         acct;
    QEMUSGList              qsg;
    QEMUIOVector            iov;
    QTAILQ_ENTRY(NvmeRequest)entry;
} NvmeRequest;

typedef struct DMAOff {
    QEMUSGList *qsg;
    int ndx;
    dma_addr_t ptr;
    dma_addr_t len;
} DMAOff;

typedef struct NvmeSQueue {
    struct NvmeCtrl *ctrl;
    uint8_t     phys_contig;
    uint8_t     arb_burst;
    uint16_t    sqid;
    uint16_t    cqid;
    uint32_t    head;
    uint32_t    tail;
    uint32_t    size;
    uint64_t    dma_addr;
    uint64_t    completed;
    uint64_t    *prp_list;
    QEMUTimer   *timer;
    NvmeRequest *io_req;
    QTAILQ_HEAD(sq_req_list, NvmeRequest) req_list;
    QTAILQ_HEAD(out_req_list, NvmeRequest) out_req_list;
    QTAILQ_ENTRY(NvmeSQueue) entry;
    /* Mapped memory location where the tail pointer is stored by the guest
     * without triggering MMIO exits. */
    uint64_t    db_addr;
    /* virtio-like eventidx pointer, guest updates to the tail pointer that
     * do not go over this value will not result in MMIO writes (but will
     * still write the tail pointer to the "db_addr" location above). */
    uint64_t    eventidx_addr;
} NvmeSQueue;

typedef struct NvmeCQueue {
    struct NvmeCtrl *ctrl;
    uint8_t     phys_contig;
    uint8_t     phase;
    uint16_t    cqid;
    uint16_t    irq_enabled;
    uint32_t    head;
    uint32_t    tail;
    uint32_t    vector;
    uint32_t    size;
    uint64_t    dma_addr;
    uint64_t    *prp_list;
    QEMUTimer   *timer;
    QTAILQ_HEAD(sq_list, NvmeSQueue) sq_list;
    QTAILQ_HEAD(cq_req_list, NvmeRequest) req_list;
    /* Mapped memory location where the head pointer is stored by the guest
     * without triggering MMIO exits. */
    uint64_t    db_addr;
    /* virtio-like eventidx pointer, guest updates to the head pointer that
     * do not go over this value will not result in MMIO writes (but will
     * still write the head pointer to the "db_addr" location above). */
    uint64_t    eventidx_addr;
} NvmeCQueue;

typedef struct NvmeNamespace {
    struct NvmeCtrl *ctrl;
    NvmeIdNs        id_ns;
    NvmeRangeType   lba_range[64];
    unsigned long   *util;
    unsigned long   *uncorrectable;
    uint32_t        id;
    uint64_t        ns_blks;
    uint64_t        start_block;
    uint64_t        start_block_predef;
    uint8_t         *predef;
    LnvmCS          *chunk_meta;
} NvmeNamespace;

#define TYPE_NVME "nvme"
#define NVME(obj) \
        OBJECT_CHECK(NvmeCtrl, (obj), TYPE_NVME)

typedef struct LnvmCtrl {
    LnvmParams     params;
    LnvmIdCtrl     id_ctrl;
    LnvmAddrF      lbaf;
    uint8_t        bbt_gen_freq;
    uint8_t        meta_auto_gen;
    uint8_t        debug;
    uint8_t        strict;
    uint8_t        state_auto_gen;
    char           *meta_fname;
    char           *chunk_fname;
    uint32_t       err_write;
    uint32_t       n_err_write;
    uint32_t       err_write_cnt;
    FILE           *metadata;
    uint8_t        int_meta_size;       // # of bytes for "internal" metadata
    uint8_t        lba_meta_size; /* per lba metadata */
} LnvmCtrl;

typedef struct NvmeCtrl {
    PCIDevice    parent_obj;
    MemoryRegion iomem;
    MemoryRegion ctrl_mem;
    NvmeBar      bar;
    BlockConf    conf;

    time_t      start_time;
    uint16_t    temperature;
    uint32_t    page_size;
    uint16_t    page_bits;
    uint16_t    max_prp_ents;
    uint16_t    cqe_size;
    uint16_t    sqe_size;
    uint16_t    oacs;
    uint16_t    oncs;
    uint32_t    reg_size;
    uint32_t    num_namespaces;
    uint32_t    num_queues;
    uint32_t    max_q_ents;
    uint64_t    ns_size;
    uint8_t     db_stride;
    uint8_t     aerl;
    uint8_t     acl;
    uint8_t     elpe;
    uint8_t     elp_index;
    uint8_t     error_count;
    uint8_t     mdts;
    uint8_t     cqr;
    uint8_t     max_sqes;
    uint8_t     max_cqes;
    uint8_t     meta;
    uint8_t     vwc;
    uint8_t     mc;
    uint8_t     dpc;
    uint8_t     dps;
    uint8_t     nlbaf;
    uint8_t     extended;
    uint8_t     lba_index;
    uint8_t     mpsmin;
    uint8_t     mpsmax;
    uint8_t     intc;
    uint8_t     intc_thresh;
    uint8_t     intc_time;
    uint8_t     outstanding_aers;
    uint8_t     temp_warn_issued;
    uint8_t     num_errors;
    uint8_t     cqes_pending;
    uint16_t    vid;
    uint16_t    did;
    uint32_t    cmb_size_mb;
    uint32_t    cmbsz;
    uint32_t    cmbloc;
    uint8_t     *cmbuf;
    uint64_t    irq_status;

    char            *serial;
    NvmeErrorLog    *elpes;
    NvmeRequest     **aer_reqs;
    NvmeNamespace   *namespaces;
    NvmeSQueue      **sq;
    NvmeCQueue      **cq;
    NvmeSQueue      admin_sq;
    NvmeCQueue      admin_cq;
    NvmeFeatureVal  features;
    NvmeIdCtrl      id_ctrl;

    QSIMPLEQ_HEAD(aer_queue, NvmeAsyncEvent) aer_queue;
    QEMUTimer   *aer_timer;
    uint8_t     aer_mask;

    LnvmCtrl     lnvm_ctrl;
} NvmeCtrl;

typedef struct NvmeDifTuple {
    uint16_t guard_tag;
    uint16_t app_tag;
    uint32_t ref_tag;
} NvmeDifTuple;

#endif /* HW_NVME_H */
