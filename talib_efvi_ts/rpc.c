/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2020 - 2022 Xilinx, Inc. All rights reserved. */
/**
 * @brief RPC routines implementation
 *
 * EF_VI API RPC routines implementation.
 *
 * @author Damir Mansurov <Damir.Mansurov@oktetlabs.ru>
 */

#define TE_LGR_USER "SFC EF_VI RPC"

#include "te_config.h"
#include "config.h"

#include "logger_ta_lock.h"
#include "rpc_server.h"
#include "te_alloc.h"

#include "efvi_talib_common.h"

#include <etherfabric/base.h>
#include <etherfabric/pd.h>
#include <etherfabric/vi.h>
#include <etherfabric/memreg.h>

/**
 * Resolve dynamically a function from inside an accessor function
 * defined for it.
 *
 * @param _var      Variable where to save resolved function
 *                  pointer (set to @c NULL in case of failure).
 * @param _name     Name of the function to resolve.
 */
#define RESOLVE_ACC_FUNC(_var, _name) \
    do {                                                          \
        if (tarpc_find_func(TARPC_LIB_DEFAULT, #_name,            \
                            (api_func *)&_var) != 0 ||            \
            (void *)_var == (void *)&_name)                       \
        {                                                         \
            te_rpc_error_set(TE_RC(TE_TA_UNIX, TE_ENOENT),        \
                             "failed to resolve %s()",            \
                             #_name);                             \
            _var = NULL;                                          \
        }                                                         \
    } while (0)

/**
 * Convert protection domain flags to native values.
 *
 * @param flags       Flags from @ref rpc_ef_pd_flags.
 *
 * @return Flags from ef_pd_flags.
 */
static unsigned int
ef_pd_flags_rpc2h(unsigned int flags)
{
#define PARSE_FLAG(_flag) \
    if (flags & RPC_EF_PD_ ## _flag) \
    {                                               \
        res |= EF_PD_ ## _flag;                     \
        flags = (flags & ~RPC_EF_PD_ ## _flag);     \
    }

    unsigned int res = 0;

    PARSE_FLAG(VF);
    PARSE_FLAG(PHYS_MODE);
    PARSE_FLAG(RX_PACKED_STREAM);
    PARSE_FLAG(VPORT);
    PARSE_FLAG(MCAST_LOOP);
    PARSE_FLAG(MEMREG_64KiB);
    PARSE_FLAG(IGNORE_BLACKLIST);

    if (flags != 0)
    {
        ERROR("%s(): unknown 0x%x flags remain not parsed",
              __FUNCTION__, flags);
    }

    return res;
#undef PARSE_FLAG
}

/**
 * Convert virtual interface flags to native values.
 *
 * @param flags       Flags from @ref rpc_ef_vi_flags.
 *
 * @return Flags from ef_vi_flags.
 */
static unsigned int
ef_vi_flags_rpc2h(unsigned int flags)
{
#define PARSE_FLAG(_flag) \
    if (flags & RPC_EF_VI_ ## _flag) \
    {                                               \
        res |= EF_VI_ ## _flag;                     \
        flags = (flags & ~RPC_EF_VI_ ## _flag);     \
    }

    unsigned int res = 0;

    PARSE_FLAG(ISCSI_RX_HDIG);
    PARSE_FLAG(ISCSI_TX_HDIG);
    PARSE_FLAG(ISCSI_RX_DDIG);
    PARSE_FLAG(ISCSI_TX_DDIG);
    PARSE_FLAG(TX_PHYS_ADDR);
    PARSE_FLAG(RX_PHYS_ADDR);
    PARSE_FLAG(TX_IP_CSUM_DIS);
    PARSE_FLAG(TX_TCPUDP_CSUM_DIS);
    PARSE_FLAG(TX_TCPUDP_ONLY);
    PARSE_FLAG(TX_FILTER_IP);
    PARSE_FLAG(TX_FILTER_MAC);
    PARSE_FLAG(TX_FILTER_MASK_1);
    PARSE_FLAG(TX_FILTER_MASK_2);
    PARSE_FLAG(TX_PUSH_DISABLE);
    PARSE_FLAG(TX_PUSH_ALWAYS);
    PARSE_FLAG(RX_TIMESTAMPS);
    PARSE_FLAG(TX_TIMESTAMPS);
    PARSE_FLAG(RX_PACKED_STREAM);
    PARSE_FLAG(RX_PS_BUF_SIZE_64K);
    PARSE_FLAG(RX_EVENT_MERGE);
    PARSE_FLAG(TX_ALT);
    PARSE_FLAG(ENABLE_EV_TIMER);
    PARSE_FLAG(TX_CTPIO);
    PARSE_FLAG(TX_CTPIO_NO_POISON);
    PARSE_FLAG(RX_ZEROCOPY);

    if (flags != 0)
    {
        ERROR("%s(): unknown 0x%x flags remain not parsed",
              __FUNCTION__, flags);
    }

    return res;
#undef PARSE_FLAG
}

/**
 * Convert filter flags to native values.
 *
 * @param flags       Flags from @ref rpc_ef_filter_flags.
 *
 * @return Flags from ef_filter_flags.
 */
static unsigned int
ef_filter_flags_rpc2h(unsigned int flags)
{
#define PARSE_FLAG(_flag) \
    if (flags & RPC_EF_FILTER_ ## _flag) \
    {                                                   \
        res |= EF_FILTER_ ## _flag;                     \
        flags = (flags & ~RPC_EF_FILTER_ ## _flag);     \
    }

    unsigned int res = 0;

    PARSE_FLAG(FLAG_MCAST_LOOP_RECEIVE);

    if (flags != 0)
    {
        ERROR("%s(): unknown 0x%x flags remain not parsed",
              __FUNCTION__, flags);
    }

    return res;
#undef PARSE_FLAG
}

/* See the function description in etherfabric/base.h */
TARPC_FUNC(ef_driver_open, {},
{
    MAKE_CALL(out->retval = func_ptr(&out->handle));
    TE_RPC_CONVERT_NEGATIVE_ERR(out->retval);
})

/* See the function description in etherfabric/base.h */
TARPC_FUNC(ef_driver_close, {},
{
    MAKE_CALL(out->retval = func_ptr(in->handle));
})

/* See the function description in etherfabric/pd.h */
TARPC_FUNC(ef_pd_alloc, {},
{
    static rpc_ptr_id_namespace ns_pd = RPC_PTR_ID_NS_INVALID;
    ef_pd *pd;

    out->common._errno = TE_RC(TE_RCF_PCH, TE_EFAIL);
    out->retval = -1;
    RCF_PCH_MEM_NS_CREATE_IF_NEEDED_RETURN(&ns_pd,
                                           RPC_TYPE_NS_EFVI_PD,);

    pd = TE_ALLOC(sizeof(*pd));
    if (pd == NULL)
    {
        te_rpc_error_set(TE_RC(TE_TA_UNIX, TE_ENOMEM),
                         "Failed to allocate memory for ef_pd");
        return;
    }

    MAKE_CALL(out->retval = func_ptr(pd, in->pd_dh, in->ifindex,
                                     ef_pd_flags_rpc2h(in->flags)));
    TE_RPC_CONVERT_NEGATIVE_ERR(out->retval);
    if (out->retval == 0)
        out->pd = RCF_PCH_MEM_INDEX_ALLOC(pd, ns_pd);
    else
        free(pd);
})

/* See the function description in etherfabric/pd.h */
TARPC_FUNC(ef_pd_free, {},
{
    static rpc_ptr_id_namespace ns_pd = RPC_PTR_ID_NS_INVALID;
    ef_pd *pd;

    out->common._errno = TE_RC(TE_RCF_PCH, TE_EFAIL);
    out->retval = -1;
    RCF_PCH_MEM_NS_CREATE_IF_NEEDED_RETURN(&ns_pd,
                                           RPC_TYPE_NS_EFVI_PD,);
    RCF_PCH_MEM_INDEX_TO_PTR_RPC(pd, in->pd, ns_pd,);

    MAKE_CALL(out->retval = func_ptr(pd, in->pd_dh));
    TE_RPC_CONVERT_NEGATIVE_ERR(out->retval);
    if (out->retval == 0)
        RCF_PCH_MEM_INDEX_FREE(in->pd, ns_pd);
})

/* See the function description in etherfabric/vi.h */
TARPC_FUNC(ef_vi_alloc_from_pd, {},
{
    static rpc_ptr_id_namespace ns_vi = RPC_PTR_ID_NS_INVALID;
    static rpc_ptr_id_namespace ns_pd = RPC_PTR_ID_NS_INVALID;
    ef_vi *vi = NULL;
    ef_pd *pd = NULL;
    ef_vi *evq_opt = NULL;

    out->common._errno = TE_RC(TE_RCF_PCH, TE_EFAIL);
    out->retval = -1;
    RCF_PCH_MEM_NS_CREATE_IF_NEEDED_RETURN(&ns_vi,
                                           RPC_TYPE_NS_EFVI_VI,);
    RCF_PCH_MEM_NS_CREATE_IF_NEEDED_RETURN(&ns_pd,
                                           RPC_TYPE_NS_EFVI_PD,);
    RCF_PCH_MEM_INDEX_TO_PTR_RPC(pd, in->pd, ns_pd,);
    RCF_PCH_MEM_INDEX_TO_PTR_RPC(evq_opt, in->evq_opt, ns_vi,);

    vi = TE_ALLOC(sizeof(*vi));
    if (vi == NULL)
    {
        te_rpc_error_set(TE_RC(TE_TA_UNIX, TE_ENOMEM),
                         "Failed to allocate memory for ef_vi");
        return;
    }

    MAKE_CALL(out->retval = func_ptr(vi, in->vi_dh, pd, in->pd_dh,
                                     in->evq_capacity, in->rxq_capacity,
                                     in->txq_capacity, evq_opt, in->evq_dh,
                                     ef_vi_flags_rpc2h(in->flags)));
    TE_RPC_CONVERT_NEGATIVE_ERR(out->retval);
    if (out->retval == 0)
        out->vi = RCF_PCH_MEM_INDEX_ALLOC(vi, ns_vi);
    else
        free(vi);
})

/* See the function description in etherfabric/vi.h */
TARPC_FUNC(ef_vi_free, {},
{
    static rpc_ptr_id_namespace ns_vi = RPC_PTR_ID_NS_INVALID;
    ef_vi *vi = NULL;

    out->common._errno = TE_RC(TE_RCF_PCH, TE_EFAIL);
    out->retval = -1;
    RCF_PCH_MEM_NS_CREATE_IF_NEEDED_RETURN(&ns_vi,
                                           RPC_TYPE_NS_EFVI_VI,);
    RCF_PCH_MEM_INDEX_TO_PTR_RPC(vi, in->vi, ns_vi,);

    MAKE_CALL(out->retval = func_ptr(vi, in->nic_dh));
    TE_RPC_CONVERT_NEGATIVE_ERR(out->retval);
    if (out->retval == 0)
        RCF_PCH_MEM_INDEX_FREE(in->vi, ns_vi);
})

/**
 * Allocate memory for a filter specification and initialize it with
 * @b ef_filter_spec_init().
 *
 * @param flags       Flags from ef_filter_flags.
 * @param fs_out      Where to save pointer to the filter specification.
 *
 * @return @c 0 on success, @c -1 on failure.
 */
static int
ef_filter_spec_alloc(unsigned int flags, ef_filter_spec **fs_out)
{
    ef_filter_spec *fs;
    api_func_ptr fs_init;

    if (tarpc_find_func(TARPC_LIB_DEFAULT, "ef_filter_spec_init",
                        (api_func *)&fs_init) != 0)
    {
        te_rpc_error_set(TE_RC(TE_TA_UNIX, TE_ENOENT),
                         "Failed to resolve ef_filter_spec_init()");
        return -1;
    }

    fs = TE_ALLOC(sizeof(*fs));
    if (fs == NULL)
    {
        te_rpc_error_set(TE_RC(TE_TA_UNIX, TE_ENOMEM),
                         "Failed to allocate memory for ef_filter_spec");
        return -1;
    }

    fs_init(fs, flags);
    *fs_out = fs;
    return 0;
}

TARPC_FUNC_STATIC(ef_filter_spec_alloc, {},
{
    static rpc_ptr_id_namespace ns_fs = RPC_PTR_ID_NS_INVALID;
    ef_filter_spec *fs;

    out->common._errno = TE_RC(TE_RCF_PCH, TE_EFAIL);
    out->retval = -1;
    RCF_PCH_MEM_NS_CREATE_IF_NEEDED_RETURN(&ns_fs,
                                           RPC_TYPE_NS_EFVI_FILTER_SPEC,);

    MAKE_CALL(out->retval = func_ptr(ef_filter_flags_rpc2h(in->flags),
                                     &fs));
    if (out->retval == 0)
        out->fs = RCF_PCH_MEM_INDEX_ALLOC(fs, ns_fs);
})

/**
 * Release memory allocated for a filter specification.
 *
 * @param fs        Pointer to the filter specification.
 *
 * @return @c 0 on success, @c -1 on failure.
 */
static int
ef_filter_spec_free(ef_filter_spec *fs)
{
    free(fs);
    return 0;
}

TARPC_FUNC_STATIC(ef_filter_spec_free, {},
{
    static rpc_ptr_id_namespace ns_fs = RPC_PTR_ID_NS_INVALID;
    ef_filter_spec *fs;

    out->common._errno = TE_RC(TE_RCF_PCH, TE_EFAIL);
    out->retval = -1;
    RCF_PCH_MEM_NS_CREATE_IF_NEEDED_RETURN(&ns_fs,
                                           RPC_TYPE_NS_EFVI_FILTER_SPEC,);
    RCF_PCH_MEM_INDEX_TO_PTR_RPC(fs, in->fs, ns_fs,);

    MAKE_CALL(out->retval = func_ptr(fs));
    if (out->retval == 0)
        RCF_PCH_MEM_INDEX_FREE(in->fs, ns_fs);
})

/* See the function description in etherfabric/vi.h */
TARPC_FUNC(ef_filter_spec_set_ip4_local, {},
{
    static rpc_ptr_id_namespace ns_fs = RPC_PTR_ID_NS_INVALID;
    ef_filter_spec *fs;

    PREPARE_ADDR(addr, in->addr, 0);

    out->common._errno = TE_RC(TE_RCF_PCH, TE_EFAIL);
    out->retval = -1;
    RCF_PCH_MEM_NS_CREATE_IF_NEEDED_RETURN(&ns_fs,
                                           RPC_TYPE_NS_EFVI_FILTER_SPEC,);
    RCF_PCH_MEM_INDEX_TO_PTR_RPC(fs, in->fs, ns_fs,);

    MAKE_CALL(out->retval = func_ptr(fs, proto_rpc2h(in->protocol),
                                     SIN(addr)->sin_addr.s_addr,
                                     SIN(addr)->sin_port));
    TE_RPC_CONVERT_NEGATIVE_ERR(out->retval);
})

/* See the function description in etherfabric/vi.h */
TARPC_FUNC(ef_filter_spec_set_ip4_full, {},
{
    static rpc_ptr_id_namespace ns_fs = RPC_PTR_ID_NS_INVALID;
    ef_filter_spec *fs;

    PREPARE_ADDR(laddr, in->laddr, 0);
    PREPARE_ADDR(raddr, in->raddr, 0);

    out->common._errno = TE_RC(TE_RCF_PCH, TE_EFAIL);
    out->retval = -1;
    RCF_PCH_MEM_NS_CREATE_IF_NEEDED_RETURN(&ns_fs,
                                           RPC_TYPE_NS_EFVI_FILTER_SPEC,);
    RCF_PCH_MEM_INDEX_TO_PTR_RPC(fs, in->fs, ns_fs,);

    MAKE_CALL(out->retval = func_ptr(fs, proto_rpc2h(in->protocol),
                                     SIN(laddr)->sin_addr.s_addr,
                                     SIN(laddr)->sin_port,
                                     SIN(raddr)->sin_addr.s_addr,
                                     SIN(raddr)->sin_port));
    TE_RPC_CONVERT_NEGATIVE_ERR(out->retval);
})

/* See the function description in etherfabric/vi.h */
TARPC_FUNC(ef_filter_spec_set_ip6_local, {},
{
    static rpc_ptr_id_namespace ns_fs = RPC_PTR_ID_NS_INVALID;
    ef_filter_spec *fs;

    PREPARE_ADDR(addr, in->addr, 0);

    out->common._errno = TE_RC(TE_RCF_PCH, TE_EFAIL);
    out->retval = -1;
    RCF_PCH_MEM_NS_CREATE_IF_NEEDED_RETURN(&ns_fs,
                                           RPC_TYPE_NS_EFVI_FILTER_SPEC,);
    RCF_PCH_MEM_INDEX_TO_PTR_RPC(fs, in->fs, ns_fs,);

    MAKE_CALL(out->retval = func_ptr(fs, proto_rpc2h(in->protocol),
                                     &SIN6(addr)->sin6_addr,
                                     SIN6(addr)->sin6_port));
    TE_RPC_CONVERT_NEGATIVE_ERR(out->retval);
})

/* See the function description in etherfabric/vi.h */
TARPC_FUNC(ef_filter_spec_set_ip6_full, {},
{
    static rpc_ptr_id_namespace ns_fs = RPC_PTR_ID_NS_INVALID;
    ef_filter_spec *fs;

    PREPARE_ADDR(laddr, in->laddr, 0);
    PREPARE_ADDR(raddr, in->raddr, 0);

    out->common._errno = TE_RC(TE_RCF_PCH, TE_EFAIL);
    out->retval = -1;
    RCF_PCH_MEM_NS_CREATE_IF_NEEDED_RETURN(&ns_fs,
                                           RPC_TYPE_NS_EFVI_FILTER_SPEC,);
    RCF_PCH_MEM_INDEX_TO_PTR_RPC(fs, in->fs, ns_fs,);

    MAKE_CALL(out->retval = func_ptr(fs, proto_rpc2h(in->protocol),
                                     &SIN6(laddr)->sin6_addr,
                                     SIN6(laddr)->sin6_port,
                                     &SIN6(raddr)->sin6_addr,
                                     SIN6(raddr)->sin6_port));
    TE_RPC_CONVERT_NEGATIVE_ERR(out->retval);
})

/* See the function description in etherfabric/vi.h */
TARPC_FUNC(ef_vi_filter_add, {},
{
    static rpc_ptr_id_namespace ns_vi = RPC_PTR_ID_NS_INVALID;
    static rpc_ptr_id_namespace ns_fs = RPC_PTR_ID_NS_INVALID;
    ef_vi *vi;
    ef_filter_spec *fs;
    ef_filter_cookie cookie;

    out->common._errno = TE_RC(TE_RCF_PCH, TE_EFAIL);
    out->retval = -1;
    RCF_PCH_MEM_NS_CREATE_IF_NEEDED_RETURN(&ns_vi,
                                           RPC_TYPE_NS_EFVI_VI,);
    RCF_PCH_MEM_NS_CREATE_IF_NEEDED_RETURN(&ns_fs,
                                           RPC_TYPE_NS_EFVI_FILTER_SPEC,);
    RCF_PCH_MEM_INDEX_TO_PTR_RPC(vi, in->vi, ns_vi,);
    RCF_PCH_MEM_INDEX_TO_PTR_RPC(fs, in->fs, ns_fs,);

    MAKE_CALL(out->retval = func_ptr(vi, in->vi_dh, fs,
                                     (in->get_cookie ? &cookie : NULL)));
    TE_RPC_CONVERT_NEGATIVE_ERR(out->retval);

    if (in->get_cookie && out->retval == 0)
    {
        out->cookie.filter_id = cookie.filter_id;
        out->cookie.filter_type = cookie.filter_type;
    }
})

/* See the function description in etherfabric/vi.h */
TARPC_FUNC(ef_vi_filter_del, {},
{
    static rpc_ptr_id_namespace ns_vi = RPC_PTR_ID_NS_INVALID;
    ef_vi *vi;
    ef_filter_cookie cookie;

    out->common._errno = TE_RC(TE_RCF_PCH, TE_EFAIL);
    out->retval = -1;
    RCF_PCH_MEM_NS_CREATE_IF_NEEDED_RETURN(&ns_vi,
                                           RPC_TYPE_NS_EFVI_VI,);
    RCF_PCH_MEM_INDEX_TO_PTR_RPC(vi, in->vi, ns_vi,);

    memset(&cookie, 0, sizeof(cookie));
    cookie.filter_id = in->cookie.filter_id;
    cookie.filter_type = in->cookie.filter_type;

    MAKE_CALL(out->retval = func_ptr(vi, in->vi_dh, &cookie));
    TE_RPC_CONVERT_NEGATIVE_ERR(out->retval);
})

/* See the function description in etherfabric/memreg.h */
TARPC_FUNC(ef_memreg_alloc, {},
{
    static rpc_ptr_id_namespace ns_mr = RPC_PTR_ID_NS_INVALID;
    static rpc_ptr_id_namespace ns_pd = RPC_PTR_ID_NS_INVALID;
    ef_pd *pd = NULL;
    ef_memreg *mr = NULL;

    out->common._errno = TE_RC(TE_RCF_PCH, TE_EFAIL);
    out->retval = -1;
    RCF_PCH_MEM_NS_CREATE_IF_NEEDED_RETURN(&ns_pd,
                                           RPC_TYPE_NS_EFVI_PD,);
    RCF_PCH_MEM_NS_CREATE_IF_NEEDED_RETURN(&ns_mr,
                                           RPC_TYPE_NS_EFVI_MEMREG,);
    RCF_PCH_MEM_INDEX_TO_PTR_RPC(pd, in->pd, ns_pd,);

    mr = TE_ALLOC(sizeof(*mr));
    if (mr == NULL)
    {
        te_rpc_error_set(TE_RC(TE_TA_UNIX, TE_ENOMEM),
                         "Failed to allocate memory for ef_memreg");
        return;
    }

    MAKE_CALL(out->retval = func_ptr(mr, in->mr_dh, pd, in->pd_dh,
                                     rcf_pch_mem_get(in->p_mem),
                                     in->len_bytes));
    TE_RPC_CONVERT_NEGATIVE_ERR(out->retval);
    if (out->retval == 0)
        out->mr = RCF_PCH_MEM_INDEX_ALLOC(mr, ns_mr);
    else
        free(mr);
})

/* See the function description in etherfabric/memreg.h */
TARPC_FUNC(ef_memreg_free, {},
{
    static rpc_ptr_id_namespace ns_mr = RPC_PTR_ID_NS_INVALID;
    ef_memreg *mr = NULL;

    out->common._errno = TE_RC(TE_RCF_PCH, TE_EFAIL);
    out->retval = -1;
    RCF_PCH_MEM_NS_CREATE_IF_NEEDED_RETURN(&ns_mr,
                                           RPC_TYPE_NS_EFVI_MEMREG,);
    RCF_PCH_MEM_INDEX_TO_PTR_RPC(mr, in->mr, ns_mr,);

    MAKE_CALL(out->retval = func_ptr(mr, in->mr_dh));
    TE_RPC_CONVERT_NEGATIVE_ERR(out->retval);
    if (out->retval == 0)
        RCF_PCH_MEM_INDEX_FREE(in->mr, ns_mr);
})

/* See the function description in etherfabric/memreg.h */
TARPC_FUNC_STATIC(ef_memreg_dma_addr, {},
{
    static rpc_ptr_id_namespace ns_mr = RPC_PTR_ID_NS_INVALID;
    ef_memreg *mr = NULL;

    out->common._errno = TE_RC(TE_RCF_PCH, TE_EFAIL);
    out->retval = -1;
    RCF_PCH_MEM_NS_CREATE_IF_NEEDED_RETURN(&ns_mr,
                                           RPC_TYPE_NS_EFVI_MEMREG,);
    RCF_PCH_MEM_INDEX_TO_PTR_RPC(mr, in->mr, ns_mr,);

    MAKE_CALL(out->addr = func_ptr(mr, in->offset));
    out->retval = 0;
})

/**
 * Accessor for @b ef_vi_receive_init(). Currently it is a macro, so
 * it cannot be resolved normally.
 *
 * @param vi        Virtual interface.
 * @param addr      DMA address of the packet buffer to associate
 *                  with the descriptor.
 * @param dma_id    DMA ID to associate with RX descriptor.
 *
 * @return @c 0 on success, @c -1 on failure.
 */
static int
ef_vi_receive_init_rpc(ef_vi *vi, ef_addr addr, ef_request_id dma_id)
{
#ifdef ef_vi_receive_init
    int rc;

    rc = ef_vi_receive_init(vi, addr, dma_id);
    TE_RPC_CONVERT_NEGATIVE_ERR(rc);

    return rc;
#else
    te_rpc_error_set(TE_RC(TE_TA_UNIX, TE_ENOENT),
                     "ef_vi_receive_init() is no longer a macro, "
                     "implement proper accessor for it");
    return -1;
#endif
}

/* See the function description in etherfabric/ef_vi.h */
TARPC_FUNC_STATIC(ef_vi_receive_init_rpc, {},
{
    static rpc_ptr_id_namespace ns_vi = RPC_PTR_ID_NS_INVALID;
    ef_vi *vi = NULL;

    out->common._errno = TE_RC(TE_RCF_PCH, TE_EFAIL);
    out->retval = -1;
    RCF_PCH_MEM_NS_CREATE_IF_NEEDED_RETURN(&ns_vi,
                                           RPC_TYPE_NS_EFVI_VI,);
    RCF_PCH_MEM_INDEX_TO_PTR_RPC(vi, in->vi, ns_vi,);

    MAKE_CALL(out->retval = func_ptr(vi, in->addr, in->dma_id));
})

/**
 * Accessor for @b ef_vi_receive_push(). Currently it is a macro, so
 * it cannot be resolved normally.
 *
 * @param vi        Virtual interface.
 *
 * @return @c 0 on success, @c -1 on failure.
 */
static int
ef_vi_receive_push_rpc(ef_vi *vi)
{
#ifdef ef_vi_receive_push
    ef_vi_receive_push(vi);
    return 0;
#else
    te_rpc_error_set(TE_RC(TE_TA_UNIX, TE_ENOENT),
                     "ef_vi_receive_push() is no longer a macro, "
                     "implement proper accessor for it");
    return -1;
#endif
}

TARPC_FUNC_STATIC(ef_vi_receive_push_rpc, {},
{
    static rpc_ptr_id_namespace ns_vi = RPC_PTR_ID_NS_INVALID;
    ef_vi *vi = NULL;

    out->common._errno = TE_RC(TE_RCF_PCH, TE_EFAIL);
    out->retval = -1;
    RCF_PCH_MEM_NS_CREATE_IF_NEEDED_RETURN(&ns_vi,
                                           RPC_TYPE_NS_EFVI_VI,);
    RCF_PCH_MEM_INDEX_TO_PTR_RPC(vi, in->vi, ns_vi,);

    MAKE_CALL(out->retval = func_ptr(vi));
})

/* See the function description in etherfabric/ef_vi.h */
TARPC_FUNC(ef_vi_receive_post, {},
{
    static rpc_ptr_id_namespace ns_vi = RPC_PTR_ID_NS_INVALID;
    ef_vi *vi = NULL;

    out->common._errno = TE_RC(TE_RCF_PCH, TE_EFAIL);
    out->retval = -1;
    RCF_PCH_MEM_NS_CREATE_IF_NEEDED_RETURN(&ns_vi,
                                           RPC_TYPE_NS_EFVI_VI,);
    RCF_PCH_MEM_INDEX_TO_PTR_RPC(vi, in->vi, ns_vi,);

    MAKE_CALL(out->retval = func_ptr(vi, in->addr, in->dma_id));
    TE_RPC_CONVERT_NEGATIVE_ERR(out->retval);
})

/**
 * Accessor for @b ef_vi_transmit(). Currently it is a macro, so
 * it cannot be resolved normally.
 *
 * @param vi        Virtual interface.
 * @param base      DMA address of the packet buffer.
 * @param len       Length of the packet.
 * @param dma_id    Arbitrary DMA ID to associate with the TX descriptor.
 *
 * @return @c 0 on success, @c -1 on failure.
 */
static int
ef_vi_transmit_rpc(ef_vi *vi, ef_addr base, int len, ef_request_id dma_id)
{
    int rc;

#ifdef ef_vi_transmit
    rc = ef_vi_transmit(vi, base, len, dma_id);
#else
    api_func_ptr func;

    RESOLVE_ACC_FUNC(func, ef_vi_transmit);
    if (func == NULL)
        return -1;

    rc = func(vi, base, len, dma_id);
#endif

    TE_RPC_CONVERT_NEGATIVE_ERR(rc);
    return rc;
}

TARPC_FUNC_STATIC(ef_vi_transmit_rpc, {},
{
    static rpc_ptr_id_namespace ns_vi = RPC_PTR_ID_NS_INVALID;
    ef_vi *vi = NULL;

    out->common._errno = TE_RC(TE_RCF_PCH, TE_EFAIL);
    out->retval = -1;
    RCF_PCH_MEM_NS_CREATE_IF_NEEDED_RETURN(&ns_vi,
                                           RPC_TYPE_NS_EFVI_VI,);
    RCF_PCH_MEM_INDEX_TO_PTR_RPC(vi, in->vi, ns_vi,);

    MAKE_CALL(out->retval = func_ptr(vi, in->base, in->len, in->dma_id));
})

/**
 * Allocate array of ef_iovec structures and fill it with data
 * from array of tarpc_ef_iovec structures.
 *
 * @param tarpc_iov         Pointer to the array of tarpc_ef_iovec
 *                          structures.
 * @param iov_len           Length of the array.
 *
 * @return Pointer to the allocated array.
 */
static ef_iovec *
alloc_fill_ef_iovs(tarpc_ef_iovec *tarpc_iov, unsigned int iov_len)
{
    ef_iovec *iov;
    unsigned int i;

    iov = TE_ALLOC(iov_len * sizeof(*iov));
    if (iov == NULL)
    {
        te_rpc_error_set(TE_RC(TE_TA_UNIX, TE_ENOMEM),
                         "Not enough memory for iovec array");
        return NULL;
    }

    for (i = 0; i < iov_len; i++)
    {
        iov[i].iov_base = tarpc_iov[i].iov_base;
        iov[i].iov_len = tarpc_iov[i].iov_len;
    }

    return iov;
}

/**
 * Accessor for @b ef_vi_transmitv(). Currently it is a macro, so
 * it cannot be resolved normally.
 *
 * @param vi        Virtual interface.
 * @param iovs      Pointer to array of ef_iovec structures.
 * @param iov_len   Number of elements in the array.
 * @param id        DMA ID to associate with TX descriptor.
 *
 * @return @c 0 on success, @c -1 on failure.
 */
static int
ef_vi_transmitv_rpc(ef_vi *vi, const ef_iovec *iovs, int iov_len,
                    ef_request_id id)
{
#ifdef ef_vi_transmitv
    int rc;

    rc = ef_vi_transmitv(vi, iovs, iov_len, id);
    TE_RPC_CONVERT_NEGATIVE_ERR(rc);

    return rc;
#else
    te_rpc_error_set(TE_RC(TE_TA_UNIX, TE_ENOENT),
                     "ef_vi_transmitv() is no longer a macro, "
                     "implement proper accessor for it");
    return -1;
#endif
}

TARPC_FUNC_STATIC(ef_vi_transmitv_rpc, {},
{
    static rpc_ptr_id_namespace ns_vi = RPC_PTR_ID_NS_INVALID;
    ef_vi *vi = NULL;

    ef_iovec *iov;

    out->common._errno = TE_RC(TE_RCF_PCH, TE_EFAIL);
    out->retval = -1;
    RCF_PCH_MEM_NS_CREATE_IF_NEEDED_RETURN(&ns_vi,
                                           RPC_TYPE_NS_EFVI_VI,);
    RCF_PCH_MEM_INDEX_TO_PTR_RPC(vi, in->vi, ns_vi,);

    iov = alloc_fill_ef_iovs(in->iov.iov_val, in->iov.iov_len);
    if (iov == NULL)
    {
        out->retval = -1;
        return;
    }

    MAKE_CALL(out->retval = func_ptr(vi, iov, in->iov.iov_len, in->dma_id));
    free(iov);
})

TARPC_FUNC(ef_vi_transmit_init, {},
{
    static rpc_ptr_id_namespace ns_vi = RPC_PTR_ID_NS_INVALID;
    ef_vi *vi = NULL;

    out->common._errno = TE_RC(TE_RCF_PCH, TE_EFAIL);
    out->retval = -1;
    RCF_PCH_MEM_NS_CREATE_IF_NEEDED_RETURN(&ns_vi,
                                           RPC_TYPE_NS_EFVI_VI,);
    RCF_PCH_MEM_INDEX_TO_PTR_RPC(vi, in->vi, ns_vi,);

    MAKE_CALL(out->retval = func_ptr(vi, in->base, in->len, in->dma_id));
    TE_RPC_CONVERT_NEGATIVE_ERR(out->retval);
})

/**
 * Accessor for @b ef_vi_transmitv_init(). Currently it is a macro, so
 * it cannot be resolved normally.
 *
 * @param vi        Virtual interface.
 * @param iovs      Pointer to array of ef_iovec structures.
 * @param iov_len   Number of elements in the array.
 * @param id        DMA ID to associate with TX descriptor.
 *
 * @return @c 0 on success, @c -1 on failure.
 */
static int
ef_vi_transmitv_init_rpc(ef_vi *vi, const ef_iovec *iovs, int iov_len,
                         ef_request_id id)
{
#ifdef ef_vi_transmitv_init
    int rc;

    rc = ef_vi_transmitv_init(vi, iovs, iov_len, id);
    TE_RPC_CONVERT_NEGATIVE_ERR(rc);

    return rc;
#else
    te_rpc_error_set(TE_RC(TE_TA_UNIX, TE_ENOENT),
                     "ef_vi_transmitv_init() is no longer a macro, "
                     "implement proper accessor for it");
    return -1;
#endif
}

TARPC_FUNC_STATIC(ef_vi_transmitv_init_rpc, {},
{
    static rpc_ptr_id_namespace ns_vi = RPC_PTR_ID_NS_INVALID;
    ef_vi *vi = NULL;

    ef_iovec *iov;

    out->common._errno = TE_RC(TE_RCF_PCH, TE_EFAIL);
    out->retval = -1;
    RCF_PCH_MEM_NS_CREATE_IF_NEEDED_RETURN(&ns_vi,
                                           RPC_TYPE_NS_EFVI_VI,);
    RCF_PCH_MEM_INDEX_TO_PTR_RPC(vi, in->vi, ns_vi,);

    iov = alloc_fill_ef_iovs(in->iov.iov_val, in->iov.iov_len);
    if (iov == NULL)
    {
        out->retval = -1;
        return;
    }

    MAKE_CALL(out->retval = func_ptr(vi, iov, in->iov.iov_len, in->dma_id));
    free(iov);
})

/**
 * Accessor for @b ef_vi_transmit_push(). Currently it is a macro, so
 * it cannot be resolved normally.
 *
 * @param vi        Virtual interface.
 *
 * @return @c 0 on success, @c -1 on failure.
 */
static int
ef_vi_transmit_push_rpc(ef_vi *vi)
{
#ifdef ef_vi_transmit_push
    ef_vi_transmit_push(vi);
#else
    api_func_ptr func;
    int rc;

    RESOLVE_ACC_FUNC(func, ef_vi_transmit_push);
    if (func == NULL)
        return -1;

    func(vi);
#endif

    return 0;
}

TARPC_FUNC_STATIC(ef_vi_transmit_push_rpc, {},
{
    static rpc_ptr_id_namespace ns_vi = RPC_PTR_ID_NS_INVALID;
    ef_vi *vi = NULL;

    out->common._errno = TE_RC(TE_RCF_PCH, TE_EFAIL);
    out->retval = -1;
    RCF_PCH_MEM_NS_CREATE_IF_NEEDED_RETURN(&ns_vi,
                                           RPC_TYPE_NS_EFVI_VI,);
    RCF_PCH_MEM_INDEX_TO_PTR_RPC(vi, in->vi, ns_vi,);

    MAKE_CALL(out->retval = func_ptr(vi));
})

/**
 * Accessor for @b ef_eventq_poll(). Currently it is a macro, so
 * it cannot be resolved normally.
 *
 * @param vi        Virtual interface to query.
 * @param evs       Array in which to return polled events.
 * @param evs_len   Number of elements in the array
 *                  (must be not less than @c EF_VI_EVENT_POLL_MIN_EVS).
 *
 * @return The number of retrieved events.
 */
static int
ef_eventq_poll_rpc(ef_vi *vi, ef_event *evs, int evs_len)
{
    int rc;

#ifdef ef_eventq_poll
    rc = ef_eventq_poll(vi, evs, evs_len);
#else
    api_func_ptr func;

    RESOLVE_ACC_FUNC(func, ef_eventq_poll);
    if (func == NULL)
        return -1;

    rc = func(vi, evs, evs_len);
#endif

    TE_RPC_CONVERT_NEGATIVE_ERR(rc);
    return rc;
}

TARPC_FUNC_STATIC(ef_eventq_poll_rpc,
{
    COPY_ARG(events);
},
{
    static rpc_ptr_id_namespace ns_vi = RPC_PTR_ID_NS_INVALID;
    ef_vi *vi = NULL;
    ef_event *evs;

    out->common._errno = TE_RC(TE_RCF_PCH, TE_EFAIL);
    out->retval = -1;
    RCF_PCH_MEM_NS_CREATE_IF_NEEDED_RETURN(&ns_vi,
                                           RPC_TYPE_NS_EFVI_VI,);
    RCF_PCH_MEM_INDEX_TO_PTR_RPC(vi, in->vi, ns_vi,);

    evs = TE_ALLOC(sizeof(*evs) * out->events.events_len);
    if (evs == NULL)
    {
        te_rpc_error_set(TE_RC(TE_TA_UNIX, TE_ENOMEM),
                         "Failed to allocate memory for events");
        return;
    }

    INIT_CHECKED_ARG(evs, sizeof(*evs) * out->events.events_len,
                     sizeof(*evs) * in->events_num);

    ef_events_tarpc2h(out->events.events_val, evs, out->events.events_len);

    MAKE_CALL(out->retval = func_ptr(vi, evs, in->events_num));

    if (out->retval > 0)
        ef_events_h2tarpc(evs, out->events.events_val, out->retval);

    free(evs);
})

/**
 * Retrieve packet data from a given buffer.
 *
 * @note This function allocates memory and copies data to it.
 *
 * @param vi        Virtual interface on which packet was received.
 * @param buf       Pointer to the memory region registered for that
 *                  interface.
 * @param offset    Offset of the packet buffer inside the memory region.
 * @param len       Length of the packet data.
 *
 * @return Pointer to the packet data on success, @c NULL on failure.
 */
static uint8_t *
efvi_get_pkt_data(ef_vi *vi, uint8_t *buf, size_t offset, int len)
{
    int prefix_len;
    uint8_t *data;

    data = TE_ALLOC(len);
    if (data == NULL)
    {
        te_rpc_error_set(TE_RC(TE_TA_UNIX, TE_ENOMEM),
                         "Failed to allocate memory for packet data");
        return NULL;
    }

    prefix_len = ef_vi_receive_prefix_len(vi);
    memcpy(data, buf + offset + prefix_len, len);

    return data;
}

TARPC_FUNC_STATIC(efvi_get_pkt_data, {},
{
    static rpc_ptr_id_namespace ns_vi = RPC_PTR_ID_NS_INVALID;
    ef_vi *vi;
    uint8_t *mem;
    uint8_t *data;

    out->common._errno = TE_RC(TE_RCF_PCH, TE_EFAIL);
    out->retval = -1;
    RCF_PCH_MEM_NS_CREATE_IF_NEEDED_RETURN(&ns_vi,
                                           RPC_TYPE_NS_EFVI_VI,);
    RCF_PCH_MEM_INDEX_TO_PTR_RPC(vi, in->vi, ns_vi,);

    mem = rcf_pch_mem_get(in->mem);
    if (mem == NULL)
    {
        te_rpc_error_set(TE_RC(TE_TA_UNIX, TE_ENOENT),
                         "Failed to resolve memory pointer");
        return;
    }

    MAKE_CALL(data = func(vi, mem, in->offset, in->len));

    if (data == NULL)
    {
        return;
    }

    out->buf.buf_val = data;
    out->buf.buf_len = in->len;
    out->retval = in->len;
})

/**
 * Copy DMA IDs returned by ef_vi_transmit_unbundle() or
 * ef_vi_receive_unbundle() to the output parameter of RPC call.
 *
 * @param retval      Return value of RPC call (number of IDs
 *                    on success).
 * @param max_num     Maximum allowed number of IDs.
 * @param ids         Array of retrieved IDs.
 * @param out_val     Where to save pointer to the output array
 *                    of IDs.
 * @param out_len     Where to save length of the output array.
 */
static void
ids2tarpc(tarpc_int *retval, tarpc_int max_num,
          ef_request_id *ids, tarpc_int **out_val, u_int *out_len)
{
    tarpc_int *tarpc_ids = NULL;
    tarpc_int i;

    if (*retval > 0)
    {
        if (*retval > EF_VI_RECEIVE_BATCH)
        {
            te_rpc_error_set(TE_RC(TE_TA_UNIX, TE_ECORRUPTED),
                             "%s(): too big number of descriptors "
                             "is returned", __FUNCTION__);
            *retval = -1;
            return;
        }

        tarpc_ids = TE_ALLOC(sizeof(*tarpc_ids) * (*retval));
        if (tarpc_ids == NULL)
        {
            te_rpc_error_set(TE_RC(TE_TA_UNIX, TE_ENOMEM),
                             "Failed to allocate memory for array of "
                             "DMA IDs");
            *retval = -1;
            return;
        }

        for (i = 0; i < *retval; i++)
        {
            tarpc_ids[i] = ids[i];
        }

        *out_val = tarpc_ids;
        *out_len = *retval;
    }
}

/* See the function description in etherfabric/ef_vi.h */
TARPC_FUNC(ef_vi_transmit_unbundle, {},
{
    static rpc_ptr_id_namespace ns_vi = RPC_PTR_ID_NS_INVALID;
    ef_vi *vi = NULL;
    ef_event event;
    ef_request_id ids[EF_VI_TRANSMIT_BATCH];

    out->common._errno = TE_RC(TE_RCF_PCH, TE_EFAIL);
    out->retval = -1;
    RCF_PCH_MEM_NS_CREATE_IF_NEEDED_RETURN(&ns_vi,
                                           RPC_TYPE_NS_EFVI_VI,);
    RCF_PCH_MEM_INDEX_TO_PTR_RPC(vi, in->vi, ns_vi,);

    ef_events_tarpc2h(&in->event, &event, 1);

    MAKE_CALL(out->retval = func_ptr(vi, &event, ids));
    TE_RPC_CONVERT_NEGATIVE_ERR(out->retval);

    ids2tarpc(&out->retval, EF_VI_TRANSMIT_BATCH,
              ids, &out->ids.ids_val, &out->ids.ids_len);
})

/* See the function description in etherfabric/ef_vi.h */
TARPC_FUNC(ef_vi_receive_unbundle, {},
{
    static rpc_ptr_id_namespace ns_vi = RPC_PTR_ID_NS_INVALID;
    ef_vi *vi = NULL;
    ef_event event;
    ef_request_id ids[EF_VI_RECEIVE_BATCH];

    out->common._errno = TE_RC(TE_RCF_PCH, TE_EFAIL);
    out->retval = -1;
    RCF_PCH_MEM_NS_CREATE_IF_NEEDED_RETURN(&ns_vi,
                                           RPC_TYPE_NS_EFVI_VI,);
    RCF_PCH_MEM_INDEX_TO_PTR_RPC(vi, in->vi, ns_vi,);

    ef_events_tarpc2h(&in->event, &event, 1);

    MAKE_CALL(out->retval = func_ptr(vi, &event, ids));
    TE_RPC_CONVERT_NEGATIVE_ERR(out->retval);

    ids2tarpc(&out->retval, EF_VI_RECEIVE_BATCH,
              ids, &out->ids.ids_val, &out->ids.ids_len);
})

TARPC_FUNC(ef_vi_receive_get_bytes, {},
{
    static rpc_ptr_id_namespace ns_vi = RPC_PTR_ID_NS_INVALID;
    ef_vi *vi;
    uint8_t *mem;
    uint16_t len;

    out->common._errno = TE_RC(TE_RCF_PCH, TE_EFAIL);
    out->retval = -1;
    RCF_PCH_MEM_NS_CREATE_IF_NEEDED_RETURN(&ns_vi,
                                           RPC_TYPE_NS_EFVI_VI,);
    RCF_PCH_MEM_INDEX_TO_PTR_RPC(vi, in->vi, ns_vi,);

    mem = rcf_pch_mem_get(in->mem);
    if (mem == NULL)
    {
        te_rpc_error_set(TE_RC(TE_TA_UNIX, TE_ENOENT),
                         "Failed to resolve memory pointer");
        return;
    }

    MAKE_CALL(out->retval = func(vi, mem + in->offset, &len));
    TE_RPC_CONVERT_NEGATIVE_ERR(out->retval);

    out->len = len;
})
