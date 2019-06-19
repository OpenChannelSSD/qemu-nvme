#ifndef NVME_NS_H
#define NVME_NS_H

#define TYPE_NVME_NS "nvme-ns"
#define NVME_NS(obj) \
    OBJECT_CHECK(NvmeNamespace, (obj), TYPE_NVME_NS)

#define DEFINE_NVME_NS_PROPERTIES(_state, _props) \
    DEFINE_PROP_UINT32("nsid", _state, _props.nsid, 0)

typedef struct NvmeNamespaceParams {
    uint32_t nsid;
} NvmeNamespaceParams;

typedef struct NvmeNamespace {
    DeviceState parent_obj;
    BlockConf   conf;
    int64_t     size;

    NvmeIdNs            id_ns;
    NvmeNamespaceParams params;
} NvmeNamespace;

static inline uint8_t nvme_ns_lbads(NvmeNamespace *ns)
{
    NvmeIdNs *id = &ns->id_ns;
    return id->lbaf[NVME_ID_NS_FLBAS_INDEX(id->flbas)].ds;
}

static inline size_t nvme_ns_lbads_bytes(NvmeNamespace *ns)
{
    return 1 << nvme_ns_lbads(ns);
}

#endif /* NVME_NS_H */
