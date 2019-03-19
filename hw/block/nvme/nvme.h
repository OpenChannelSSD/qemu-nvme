#ifndef HW_NVME_H
#define HW_NVME_H

#include "qemu/queue.h"

#include "block/accounting.h"
#include "block/aio.h"
#include "block/nvme.h"

#include "sysemu/dma.h"
#include "qemu/typedefs.h"

#include "hw/block/block.h"
#include "hw/pci/pci.h"

#define NVME_NS_PREDEF_BLK_OFFSET(n, ns) ((ns)->blk.predef)

#define NVME_ID_NS_LBADS(ns)                                                  \
    ((ns)->id_ns.lbaf[NVME_ID_NS_FLBAS_INDEX((ns)->id_ns.flbas)].lbads)

#define NVME_ID_NS_LBADS_BYTES(ns) (1 << NVME_ID_NS_LBADS(ns))

#define NVME_ID_NS_MS(ns)                                                     \
    le16_to_cpu(                                                              \
        ((ns)->id_ns.lbaf[NVME_ID_NS_FLBAS_INDEX((ns)->id_ns.flbas)].ms)      \
    )

typedef struct NvmeAsyncEvent {
    QSIMPLEQ_ENTRY(NvmeAsyncEvent) entry;
    NvmeAerResult result;
} NvmeAsyncEvent;

/*
 * Encapsulate a request to the block backend. Holds the byte offset in the
 * backend and an QSG or IOV depending on the request (dma or cmb) and the
 * number logical NVMe blocks this request spans.
 */
typedef struct NvmeBlockBackendRequest {
    uint64_t slba;
    uint16_t nlb;
    uint64_t blk_offset;

    struct NvmeRequest *req;

    BlockAIOCB      *aiocb;
    BlockAcctCookie acct;

    QEMUSGList   qsg;
    QEMUIOVector iov;

    QTAILQ_ENTRY(NvmeBlockBackendRequest) blk_req_tailq;
} NvmeBlockBackendRequest;

typedef struct NvmeRequest {
    struct NvmeSQueue    *sq;
    struct NvmeNamespace *ns;
    NvmeCqe              cqe;

    uint8_t  cmd_opcode;
    uint8_t  cmb;
    uint16_t status;
    uint64_t slba;
    uint16_t nlb;
    uint8_t  is_write;

    /* sector offset relative to slba where reads become invalid */
    uint64_t predef;

    QTAILQ_HEAD(, NvmeBlockBackendRequest) blk_req_tailq_head;
    QTAILQ_ENTRY(NvmeRequest) entry;
} NvmeRequest;

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
    QTAILQ_HEAD(, NvmeRequest) req_list;
    QTAILQ_HEAD(, NvmeRequest) out_req_list;
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
    QTAILQ_HEAD(, NvmeSQueue) sq_list;
    QTAILQ_HEAD(, NvmeRequest) req_list;
    /* Mapped memory location where the head pointer is stored by the guest
     * without triggering MMIO exits. */
    uint64_t    db_addr;
    /* virtio-like eventidx pointer, guest updates to the head pointer that
     * do not go over this value will not result in MMIO writes (but will
     * still write the head pointer to the "db_addr" location above). */
    uint64_t    eventidx_addr;
} NvmeCQueue;

typedef struct NvmeNamespace {
    NvmeIdNs        id_ns;
    NvmeRangeType   lba_range[64];
    uint32_t        id;
    uint64_t        ns_blks;
    uint64_t        nsze;
    struct {
        uint64_t begin;
        uint64_t predef;
        uint64_t data;
        uint64_t meta;
    } blk;

    /* any dialect additional state */
    void *state;
} NvmeNamespace;

#define TYPE_NVME "nvme"
#define NVME(obj) \
        OBJECT_CHECK(NvmeCtrl, (obj), TYPE_NVME)

typedef struct LnvmParams {
    /* qemu configurable device characteristics */
    uint32_t mccap;
    uint32_t ws_min;
    uint32_t ws_opt;
    uint32_t mw_cunits;

    uint8_t debug;
    uint8_t early_reset;
    uint8_t	sgl_lbal;

    char *chunkstate_fname;
    char *resetfail_fname;
    char *writefail_fname;
} LnvmParams;

typedef struct NvmeParams {
    char     *serial;
    uint32_t num_namespaces;
    uint32_t num_queues;
    uint32_t max_q_ents;
    uint8_t  max_sqes;
    uint8_t  max_cqes;
    uint8_t  db_stride;
    uint8_t  aerl;
    uint8_t  acl;
    uint8_t  elpe;
    uint8_t  mdts;
    uint8_t  cqr;
    uint8_t  vwc;
    uint8_t  dpc;
    uint8_t  dps;
    uint8_t  intc;
    uint8_t  intc_thresh;
    uint8_t  intc_time;
    uint8_t  extended;
    uint8_t  mpsmin;
    uint8_t  mpsmax;
    uint8_t  ms;
    uint8_t  ms_max;
    uint8_t  mc;
    uint16_t vid;
    uint16_t did;
    uint8_t  dlfeat;
    uint32_t cmb_size_mb;
    uint8_t  dialect;
    uint16_t oacs;
    uint16_t oncs;

    /* dialects */
    LnvmParams lnvm;
} NvmeParams;

#define DEFINE_NVME_PROPERTIES(_state, _props) \
    DEFINE_PROP_STRING("serial", _state, _props.serial), \
    DEFINE_PROP_UINT32("namespaces", _state, _props.num_namespaces, 1), \
    DEFINE_PROP_UINT32("num_queues", _state, _props.num_queues, 64), \
    DEFINE_PROP_UINT32("entries", _state, _props.max_q_ents, 0x7ff), \
    DEFINE_PROP_UINT8("max_cqes", _state, _props.max_cqes, 0x4), \
    DEFINE_PROP_UINT8("max_sqes", _state, _props.max_sqes, 0x6), \
    DEFINE_PROP_UINT8("stride", _state, _props.db_stride, 0), \
    DEFINE_PROP_UINT8("aerl", _state, _props.aerl, 3), \
    DEFINE_PROP_UINT8("acl", _state, _props.acl, 3), \
    DEFINE_PROP_UINT8("elpe", _state, _props.elpe, 3), \
    DEFINE_PROP_UINT8("mdts", _state, _props.mdts, 7), \
    DEFINE_PROP_UINT8("cqr", _state, _props.cqr, 1), \
    DEFINE_PROP_UINT8("vwc", _state, _props.vwc, 0), \
    DEFINE_PROP_UINT8("intc", _state, _props.intc, 0), \
    DEFINE_PROP_UINT8("intc_thresh", _state, _props.intc_thresh, 0), \
    DEFINE_PROP_UINT8("intc_time", _state, _props.intc_time, 0), \
    DEFINE_PROP_UINT8("mpsmin", _state, _props.mpsmin, 0), \
    DEFINE_PROP_UINT8("mpsmax", _state, _props.mpsmax, 0), \
    DEFINE_PROP_UINT8("extended", _state, _props.extended, 0), \
    DEFINE_PROP_UINT8("dpc", _state, _props.dpc, 0), \
    DEFINE_PROP_UINT8("dps", _state, _props.dps, 0), \
    DEFINE_PROP_UINT8("mc", _state, _props.mc, 0x2), \
    DEFINE_PROP_UINT8("ms", _state, _props.ms, 16), \
    DEFINE_PROP_UINT8("ms_max", _state, _props.ms_max, 64), \
    DEFINE_PROP_UINT8("dlfeat", _state, _props.dlfeat, 0x1), \
    DEFINE_PROP_UINT32("cmb_size_mb", _state, _props.cmb_size_mb, 0), \
    DEFINE_PROP_UINT16("oacs", _state, _props.oacs, NVME_OACS_FORMAT), \
    DEFINE_PROP_UINT16("oncs", _state, _props.oncs, NVME_ONCS_DSM), \
    DEFINE_PROP_UINT8("dialect", _state, _props.dialect, 0x1), \
    DEFINE_PROP_UINT16("vid", _state, _props.vid, PCI_VENDOR_ID_INTEL), \
    DEFINE_PROP_UINT16("did", _state, _props.did, 0x5845)

#define DEFINE_LNVM_PROPERTIES(_state, _props) \
    DEFINE_PROP_UINT32("lmccap", _state, _props.mccap, 0x0), \
    DEFINE_PROP_UINT32("lws_min", _state, _props.ws_min, 4), \
    DEFINE_PROP_UINT32("lws_opt", _state, _props.ws_opt, 8), \
    DEFINE_PROP_UINT32("lmw_cunits", _state, _props.mw_cunits, 32), \
    DEFINE_PROP_STRING("lresetfail", _state, _props.resetfail_fname), \
    DEFINE_PROP_STRING("lwritefail", _state, _props.writefail_fname), \
    DEFINE_PROP_STRING("lchunkstate", _state, _props.chunkstate_fname), \
    DEFINE_PROP_UINT8("ldebug", _state, _props.debug, 0), \
    DEFINE_PROP_UINT8("learly_reset", _state, _props.early_reset, 1), \
    DEFINE_PROP_UINT8("lsgl_lbal", _state, _props.sgl_lbal, 0)

typedef struct NvmeDialect {
    void *state;

    void (*init_ctrl)(struct NvmeCtrl *);
    void (*init_pci)(struct NvmeCtrl *, PCIDevice *);
    int (*init_namespaces)(struct NvmeCtrl *, Error **);
    void (*free_namespace)(struct NvmeCtrl *, NvmeNamespace *);

    uint16_t (*rw_check_req)(struct NvmeCtrl *, NvmeCmd *, NvmeRequest *);
    uint64_t (*blk_idx)(struct NvmeCtrl *, NvmeNamespace *, uint64_t);
    uint16_t (*admin_cmd)(struct NvmeCtrl *, NvmeCmd *, NvmeRequest *);
    uint16_t (*io_cmd)(struct NvmeCtrl *, NvmeCmd *, NvmeRequest *);
    uint16_t (*get_log)(struct NvmeCtrl *, NvmeCmd *, NvmeRequest *);

    uint16_t (*blk_req_epilogue)(struct NvmeCtrl *, NvmeNamespace *,
        NvmeBlockBackendRequest *, NvmeRequest *);
    void (*post_cqe)(struct NvmeCtrl *, NvmeRequest *);
} NvmeDialect;

typedef struct NvmeCtrl {
    PCIDevice    parent_obj;
    MemoryRegion iomem;
    MemoryRegion ctrl_mem;
    NvmeBar      bar;
    BlockConf    conf;
    NvmeParams   params;

    time_t      start_time;
    uint16_t    temperature;
    uint32_t    page_size;
    uint16_t    page_bits;
    uint16_t    max_prp_ents;
    uint16_t    cqe_size;
    uint16_t    sqe_size;
    uint32_t    reg_size;
    uint64_t    ns_size;
    uint8_t     elp_index;
    uint8_t     error_count;
    uint8_t     outstanding_aers;
    uint8_t     temp_warn_issued;
    uint8_t     num_errors;
    uint8_t     cqes_pending;

    uint32_t    cmbsz;
    uint32_t    cmbloc;
    uint8_t     *cmbuf;
    uint64_t    irq_status;
    uint32_t    sgls;

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

    NvmeDialect dialect;
} NvmeCtrl;

typedef struct NvmeDifTuple {
    uint16_t guard_tag;
    uint16_t app_tag;
    uint32_t ref_tag;
} NvmeDifTuple;

typedef uint16_t (*NvmeBlockSetupFn)(NvmeCtrl *n, QEMUSGList *qsg,
    uint64_t blk_offset, uint32_t unit_len, NvmeRequest *req);

void nvme_ns_init_predef(NvmeCtrl *n, NvmeNamespace *ns);
void nvme_ns_init_identify(NvmeCtrl *n, NvmeIdNs *id_ns);

void nvme_addr_write(NvmeCtrl *n, hwaddr addr, void *buf, int size);
void nvme_addr_read(NvmeCtrl *n, hwaddr addr, void *buf, int size);

uint16_t nvme_dma_write(NvmeCtrl *n, uint8_t *ptr, uint32_t len, NvmeCmd *cmd,
    NvmeRequest *req);
uint16_t nvme_dma_read(NvmeCtrl *n, uint8_t *ptr, uint32_t len,
    NvmeCmd *cmd, NvmeRequest *req);
uint16_t nvme_dma_read_sgl(NvmeCtrl *n, uint8_t *ptr, uint32_t len,
    NvmeSglDescriptor sgl, NvmeRequest *req);

uint16_t nvme_blk_map(NvmeCtrl *n, NvmeCmd *cmd, NvmeRequest *req,
    NvmeBlockSetupFn blk_setup);
uint16_t nvme_blk_submit_io(NvmeCtrl *n, NvmeRequest *req);
NvmeBlockBackendRequest *nvme_blk_req_new(NvmeCtrl *n, NvmeRequest *req);

void nvme_set_error_page(NvmeCtrl *n, uint16_t sqid, uint16_t cid,
    uint16_t status, uint16_t location, uint64_t lba, uint32_t nsid);

uint16_t nvme_rw_check_req(NvmeCtrl *n, NvmeCmd *cmd, NvmeRequest *req);

void nvme_discard_cb(void *opaque, int ret);

uint64_t nvme_ns_calc_blks(NvmeCtrl *n, NvmeNamespace *ns);

void nvme_rw_cb(void *opaque, int ret);

#endif /* HW_NVME_H */
