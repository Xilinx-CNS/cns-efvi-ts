/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2020 - 2022 Xilinx, Inc. All rights reserved. */
/** @file
 * @brief Test API - EF_VI API RPC functions definition
 *
 * Implementation of TAPI for AMD EF_VI API remote calls.
 *
 * @author Damir Mansurov <Damir.Mansurov@oktetlabs.ru>
 */

#include "te_config.h"

#include "tapi_rpc_internal.h"
#include "efvi_rpc.h"
#include "te_alloc.h"

#undef TE_LGR_USER
#define TE_LGR_USER "EFVI TAPI RPC"

/**
 * Try to append to TE string, return error code if it fails.
 *
 * @param _str        TE string to which to append.
 * @param _fmt        Format and arguments.
 */
#define STR_APPEND(_str, _fmt...) \
    do {                                      \
        te_errno _rc;                         \
        _rc = te_string_append(_str, _fmt);   \
        if (_rc != 0)                         \
            return _rc;                       \
    } while (0)


/* See description in efvi_rpc.h */
int
rpc_ef_driver_open(rcf_rpc_server *rpcs, rpc_ef_driver_handle *handle)
{
    tarpc_ef_driver_open_in     in;
    tarpc_ef_driver_open_out    out;

    memset(&in, 0, sizeof(in));
    memset(&out, 0, sizeof(out));

    rcf_rpc_call(rpcs, "ef_driver_open", &in, &out);

    CHECK_RETVAL_VAR_IS_GTE_MINUS_ONE(ef_driver_open, out.retval);
    TAPI_RPC_LOG(rpcs, ef_driver_open, "", "%d, handle=%d",
                 out.retval, out.handle);

    if (out.retval >= 0)
        *handle = out.handle;

    RETVAL_INT(ef_driver_open, out.retval);
}

/* See description in efvi_rpc.h */
int
rpc_ef_driver_close(rcf_rpc_server *rpcs, rpc_ef_driver_handle handle)
{
    tarpc_ef_driver_close_in     in;
    tarpc_ef_driver_close_out    out;

    memset(&in, 0, sizeof(in));
    memset(&out, 0, sizeof(out));

    in.handle = handle;
    rcf_rpc_call(rpcs, "ef_driver_close", &in, &out);

    CHECK_RETVAL_VAR_IS_GTE_MINUS_ONE(ef_driver_close, out.retval);
    TAPI_RPC_LOG(rpcs, ef_driver_close, "handle=%d", "%d",
                 in.handle, out.retval);

    RETVAL_INT(ef_driver_close, out.retval);
}

/* See description in efvi_rpc.h */
int
rpc_ef_pd_alloc(rcf_rpc_server *rpcs, rpc_ef_pd_p *pd,
                rpc_ef_driver_handle pd_dh, int ifindex,
                unsigned int flags)
{
    tarpc_ef_pd_alloc_in     in;
    tarpc_ef_pd_alloc_out    out;

    if (pd == NULL)
    {
        ERROR("%s(): pd parameter must not be NULL", __FUNCTION__);
        rpcs->_errno = TE_RC(TE_RCF, TE_EINVAL);
        RETVAL_INT(ef_pd_alloc, -1);
    }

    memset(&in, 0, sizeof(in));
    memset(&out, 0, sizeof(out));

    in.pd_dh = pd_dh;
    in.ifindex = ifindex;
    in.flags = flags;

    rcf_rpc_call(rpcs, "ef_pd_alloc", &in, &out);

    CHECK_RETVAL_VAR_IS_GTE_MINUS_ONE(ef_pd_alloc, out.retval);

    TAPI_RPC_LOG(rpcs, ef_pd_alloc, "%p, %d, %d, %s",
                 "%d, pd=" RPC_PTR_FMT, pd, pd_dh, ifindex,
                 ef_pd_flags_rpc2str(flags),
                 out.retval, RPC_PTR_VAL(out.pd));

    if (RPC_IS_CALL_OK(rpcs) && rpcs->op != RCF_RPC_WAIT &&
        out.retval >= 0)
    {
        TAPI_RPC_NAMESPACE_CHECK_JUMP(rpcs, out.pd,
                                      RPC_TYPE_NS_EFVI_PD);
        *pd = out.pd;
    }

    RETVAL_INT(ef_pd_alloc, out.retval);
}

/* See description in efvi_rpc.h */
int
rpc_ef_pd_free(rcf_rpc_server *rpcs, rpc_ef_pd_p pd,
               rpc_ef_driver_handle pd_dh)
{
    tarpc_ef_pd_free_in     in;
    tarpc_ef_pd_free_out    out;

    memset(&in, 0, sizeof(in));
    memset(&out, 0, sizeof(out));

    TAPI_RPC_NAMESPACE_CHECK_JUMP(rpcs, pd, RPC_TYPE_NS_EFVI_PD);
    in.pd = pd;
    in.pd_dh = pd_dh;

    rcf_rpc_call(rpcs, "ef_pd_free", &in, &out);

    CHECK_RETVAL_VAR_IS_GTE_MINUS_ONE(ef_pd_free, out.retval);

    TAPI_RPC_LOG(rpcs, ef_pd_free, RPC_PTR_FMT ", %d", "%d",
                 RPC_PTR_VAL(pd), pd_dh, out.retval);

    RETVAL_INT(ef_pd_free, out.retval);
}

/* See description in efvi_rpc.h */
int
rpc_ef_vi_alloc_from_pd(rcf_rpc_server *rpcs, rpc_ef_vi_p *vi,
                        rpc_ef_driver_handle vi_dh,
                        rpc_ef_pd_p pd,
                        rpc_ef_driver_handle pd_dh,
                        int evq_capacity, int rxq_capacity,
                        int txq_capacity,
                        rpc_ef_vi_p evq_opt,
                        rpc_ef_driver_handle evq_dh,
                        unsigned int flags)
{
    tarpc_ef_vi_alloc_from_pd_in     in;
    tarpc_ef_vi_alloc_from_pd_out    out;

    te_bool saved_errno_change_check;

    if (vi == NULL)
    {
        ERROR("%s(): vi parameter must not be NULL", __FUNCTION__);
        rpcs->_errno = TE_RC(TE_RCF, TE_EINVAL);
        RETVAL_INT(ef_vi_alloc_from_pd, -1);
    }

    memset(&in, 0, sizeof(in));
    memset(&out, 0, sizeof(out));

    TAPI_RPC_NAMESPACE_CHECK_JUMP(rpcs, pd, RPC_TYPE_NS_EFVI_PD);
    TAPI_RPC_NAMESPACE_CHECK_JUMP(rpcs, evq_opt, RPC_TYPE_NS_EFVI_VI);
    in.vi_dh = vi_dh;
    in.pd = pd;
    in.pd_dh = pd_dh;
    in.evq_capacity = evq_capacity;
    in.rxq_capacity = rxq_capacity;
    in.txq_capacity = txq_capacity;
    in.evq_opt = evq_opt;
    in.evq_dh = evq_dh;
    in.flags = flags;

    rcf_rpc_call(rpcs, "ef_vi_alloc_from_pd", &in, &out);

    /*
     * This function changes errno to ENOENT in case of success,
     * see ON-12875.
     */
    saved_errno_change_check = rpcs->errno_change_check;
    rpcs->errno_change_check = FALSE;

    CHECK_RETVAL_VAR_IS_GTE_MINUS_ONE(ef_vi_alloc_from_pd, out.retval);

    TAPI_RPC_LOG(rpcs, ef_vi_alloc_from_pd, "%p, %d, " RPC_PTR_FMT ", "
                 "%d, %d, %d, %d, " RPC_PTR_FMT ", %d, %s",
                 "%d, vi=" RPC_PTR_FMT, vi, vi_dh, RPC_PTR_VAL(pd),
                 pd_dh, evq_capacity, rxq_capacity, txq_capacity,
                 RPC_PTR_VAL(evq_opt), evq_dh,
                 ef_vi_flags_rpc2str(flags), out.retval,
                 RPC_PTR_VAL(out.vi));

    rpcs->errno_change_check = saved_errno_change_check;

    if (RPC_IS_CALL_OK(rpcs) && rpcs->op != RCF_RPC_WAIT &&
        out.retval >= 0)
    {
        TAPI_RPC_NAMESPACE_CHECK_JUMP(rpcs, out.vi,
                                      RPC_TYPE_NS_EFVI_VI);
        *vi = out.vi;
    }

    RETVAL_INT(ef_vi_alloc_from_pd, out.retval);
}

/* See description in efvi_rpc.h */
int
rpc_ef_vi_free(rcf_rpc_server *rpcs, rpc_ef_vi_p vi,
               rpc_ef_driver_handle nic_dh)
{
    tarpc_ef_vi_free_in     in;
    tarpc_ef_vi_free_out    out;

    memset(&in, 0, sizeof(in));
    memset(&out, 0, sizeof(out));

    TAPI_RPC_NAMESPACE_CHECK_JUMP(rpcs, vi, RPC_TYPE_NS_EFVI_VI);
    in.vi = vi;
    in.nic_dh = nic_dh;

    rcf_rpc_call(rpcs, "ef_vi_free", &in, &out);

    CHECK_RETVAL_VAR_IS_GTE_MINUS_ONE(ef_vi_free, out.retval);

    TAPI_RPC_LOG(rpcs, ef_vi_free, RPC_PTR_FMT ", %d", "%d",
                 RPC_PTR_VAL(vi), nic_dh, out.retval);

    RETVAL_INT(ef_vi_free, out.retval);
}

/* See description in efvi_rpc.h */
int
rpc_ef_filter_spec_alloc(rcf_rpc_server *rpcs, rpc_ef_filter_spec_p *fs,
                         unsigned int flags)
{
    tarpc_ef_filter_spec_alloc_in     in;
    tarpc_ef_filter_spec_alloc_out    out;

    if (fs == NULL)
    {
        ERROR("%s(): fs parameter must not be NULL", __FUNCTION__);
        rpcs->_errno = TE_RC(TE_RCF, TE_EINVAL);
        RETVAL_INT(ef_filter_spec_alloc, -1);
    }

    memset(&in, 0, sizeof(in));
    memset(&out, 0, sizeof(out));

    in.flags = flags;

    rcf_rpc_call(rpcs, "ef_filter_spec_alloc", &in, &out);

    CHECK_RETVAL_VAR_IS_GTE_MINUS_ONE(ef_filter_spec_alloc, out.retval);

    TAPI_RPC_LOG(rpcs, ef_filter_spec_alloc, "%p, %s",
                 "%d, fs=" RPC_PTR_FMT, fs,
                 ef_filter_flags_rpc2str(flags),
                 out.retval, RPC_PTR_VAL(out.fs));

    if (RPC_IS_CALL_OK(rpcs) && rpcs->op != RCF_RPC_WAIT &&
        out.retval >= 0)
    {
        TAPI_RPC_NAMESPACE_CHECK_JUMP(rpcs, out.fs,
                                      RPC_TYPE_NS_EFVI_FILTER_SPEC);
        *fs = out.fs;
    }

    RETVAL_INT(ef_filter_spec_alloc, out.retval);
}

/* See description in efvi_rpc.h */
int
rpc_ef_filter_spec_free(rcf_rpc_server *rpcs, rpc_ef_filter_spec_p fs)
{
    tarpc_ef_filter_spec_free_in     in;
    tarpc_ef_filter_spec_free_out    out;

    memset(&in, 0, sizeof(in));
    memset(&out, 0, sizeof(out));

    TAPI_RPC_NAMESPACE_CHECK_JUMP(rpcs, fs, RPC_TYPE_NS_EFVI_FILTER_SPEC);
    in.fs = fs;

    rcf_rpc_call(rpcs, "ef_filter_spec_free", &in, &out);

    CHECK_RETVAL_VAR_IS_GTE_MINUS_ONE(ef_filter_spec_free, out.retval);

    TAPI_RPC_LOG(rpcs, ef_filter_spec_free, RPC_PTR_FMT,
                 "%d", RPC_PTR_VAL(fs), out.retval);

    RETVAL_INT(ef_filter_spec_free, out.retval);
}

/* See description in efvi_rpc.h */
int
rpc_ef_filter_spec_set_ip4_local(rcf_rpc_server *rpcs,
                                 rpc_ef_filter_spec_p fs,
                                 rpc_socket_proto protocol,
                                 const struct sockaddr *addr)
{
    tarpc_ef_filter_spec_set_ip4_local_in   in;
    tarpc_ef_filter_spec_set_ip4_local_out  out;

    if (addr->sa_family != AF_INET)
    {
        ERROR("%s(): address family should be AF_INET", __FUNCTION__);
        rpcs->_errno = TE_RC(TE_RCF, TE_EINVAL);
        RETVAL_INT(ef_filter_spec_set_ip4_local, -1);
    }

    memset(&in, 0, sizeof(in));
    memset(&out, 0, sizeof(out));

    TAPI_RPC_NAMESPACE_CHECK_JUMP(rpcs, fs, RPC_TYPE_NS_EFVI_FILTER_SPEC);
    in.fs = fs;
    in.protocol = protocol;
    sockaddr_input_h2rpc(addr, &in.addr);

    rcf_rpc_call(rpcs, "ef_filter_spec_set_ip4_local", &in, &out);

    CHECK_RETVAL_VAR_IS_GTE_MINUS_ONE(ef_filter_spec_set_ip4_local,
                                      out.retval);

    TAPI_RPC_LOG(rpcs, ef_filter_spec_set_ip4_local, RPC_PTR_FMT ", %s, %s",
                 "%d", RPC_PTR_VAL(fs), proto_rpc2str(protocol),
                 sockaddr_h2str(addr), out.retval);

    RETVAL_INT(ef_filter_spec_set_ip4_local, out.retval);
}

/* See description in efvi_rpc.h */
int
rpc_ef_filter_spec_set_ip4_full(rcf_rpc_server *rpcs,
                                rpc_ef_filter_spec_p fs,
                                rpc_socket_proto protocol,
                                const struct sockaddr *laddr,
                                const struct sockaddr *raddr)
{
    tarpc_ef_filter_spec_set_ip4_full_in   in;
    tarpc_ef_filter_spec_set_ip4_full_out  out;

    if (laddr->sa_family != AF_INET ||
        raddr->sa_family != AF_INET)
    {
        ERROR("%s(): address family should be AF_INET", __FUNCTION__);
        rpcs->_errno = TE_RC(TE_RCF, TE_EINVAL);
        RETVAL_INT(ef_filter_spec_set_ip4_full, -1);
    }

    memset(&in, 0, sizeof(in));
    memset(&out, 0, sizeof(out));

    TAPI_RPC_NAMESPACE_CHECK_JUMP(rpcs, fs, RPC_TYPE_NS_EFVI_FILTER_SPEC);
    in.fs = fs;
    in.protocol = protocol;
    sockaddr_input_h2rpc(laddr, &in.laddr);
    sockaddr_input_h2rpc(raddr, &in.raddr);

    rcf_rpc_call(rpcs, "ef_filter_spec_set_ip4_full", &in, &out);

    CHECK_RETVAL_VAR_IS_GTE_MINUS_ONE(ef_filter_spec_set_ip4_full,
                                      out.retval);

    TAPI_RPC_LOG(rpcs, ef_filter_spec_set_ip4_full,
                 RPC_PTR_FMT ", %s, %s, %s", "%d", RPC_PTR_VAL(fs),
                 proto_rpc2str(protocol), sockaddr_h2str(laddr),
                 sockaddr_h2str(raddr), out.retval);

    RETVAL_INT(ef_filter_spec_set_ip4_full, out.retval);
}

/* See description in efvi_rpc.h */
int
rpc_ef_filter_spec_set_ip6_local(rcf_rpc_server *rpcs,
                                 rpc_ef_filter_spec_p fs,
                                 rpc_socket_proto protocol,
                                 const struct sockaddr *addr)
{
    tarpc_ef_filter_spec_set_ip6_local_in   in;
    tarpc_ef_filter_spec_set_ip6_local_out  out;

    if (addr->sa_family != AF_INET6)
    {
        ERROR("%s(): address family should be AF_INET6", __FUNCTION__);
        rpcs->_errno = TE_RC(TE_RCF, TE_EINVAL);
        RETVAL_INT(ef_filter_spec_set_ip6_local, -1);
    }

    memset(&in, 0, sizeof(in));
    memset(&out, 0, sizeof(out));

    TAPI_RPC_NAMESPACE_CHECK_JUMP(rpcs, fs, RPC_TYPE_NS_EFVI_FILTER_SPEC);
    in.fs = fs;
    in.protocol = protocol;
    sockaddr_input_h2rpc(addr, &in.addr);

    rcf_rpc_call(rpcs, "ef_filter_spec_set_ip6_local", &in, &out);

    CHECK_RETVAL_VAR_IS_GTE_MINUS_ONE(ef_filter_spec_set_ip6_local,
                                      out.retval);

    TAPI_RPC_LOG(rpcs, ef_filter_spec_set_ip6_local, RPC_PTR_FMT ", %s, %s",
                 "%d", RPC_PTR_VAL(fs), proto_rpc2str(protocol),
                 sockaddr_h2str(addr), out.retval);

    RETVAL_INT(ef_filter_spec_set_ip6_local, out.retval);
}

/* See description in efvi_rpc.h */
int
rpc_ef_filter_spec_set_ip6_full(rcf_rpc_server *rpcs,
                                rpc_ef_filter_spec_p fs,
                                rpc_socket_proto protocol,
                                const struct sockaddr *laddr,
                                const struct sockaddr *raddr)
{
    tarpc_ef_filter_spec_set_ip6_full_in   in;
    tarpc_ef_filter_spec_set_ip6_full_out  out;

    if (laddr->sa_family != AF_INET6 ||
        raddr->sa_family != AF_INET6)
    {
        ERROR("%s(): address family should be AF_INET6", __FUNCTION__);
        rpcs->_errno = TE_RC(TE_RCF, TE_EINVAL);
        RETVAL_INT(ef_filter_spec_set_ip6_full, -1);
    }

    memset(&in, 0, sizeof(in));
    memset(&out, 0, sizeof(out));

    TAPI_RPC_NAMESPACE_CHECK_JUMP(rpcs, fs, RPC_TYPE_NS_EFVI_FILTER_SPEC);
    in.fs = fs;
    in.protocol = protocol;
    sockaddr_input_h2rpc(laddr, &in.laddr);
    sockaddr_input_h2rpc(raddr, &in.raddr);

    rcf_rpc_call(rpcs, "ef_filter_spec_set_ip6_full", &in, &out);

    CHECK_RETVAL_VAR_IS_GTE_MINUS_ONE(ef_filter_spec_set_ip6_full,
                                      out.retval);

    TAPI_RPC_LOG(rpcs, ef_filter_spec_set_ip6_full,
                 RPC_PTR_FMT ", %s, %s, %s", "%d", RPC_PTR_VAL(fs),
                 proto_rpc2str(protocol), sockaddr_h2str(laddr),
                 sockaddr_h2str(raddr), out.retval);

    RETVAL_INT(ef_filter_spec_set_ip6_full, out.retval);
}

/* See description in efvi_rpc.h */
int
rpc_ef_filter_spec_set_ip(rcf_rpc_server *rpcs,
                          rpc_ef_filter_spec_p fs,
                          rpc_socket_proto protocol,
                          const struct sockaddr *laddr,
                          const struct sockaddr *raddr)
{
    if (laddr->sa_family == AF_INET)
    {
        if (raddr != NULL)
        {
            return rpc_ef_filter_spec_set_ip4_full(rpcs, fs, protocol,
                                                   laddr, raddr);
        }
        else
        {
            return rpc_ef_filter_spec_set_ip4_local(rpcs, fs, protocol,
                                                    laddr);
        }
    }
    else
    {
        if (raddr != NULL)
        {
            return rpc_ef_filter_spec_set_ip6_full(rpcs, fs, protocol,
                                                   laddr, raddr);
        }
        else
        {
            return rpc_ef_filter_spec_set_ip6_local(rpcs, fs, protocol,
                                                    laddr);
        }
    }
}

/**
 * Get string representation of @ref tarpc_ef_filter_cookie.
 *
 * @param cookie      Pointer to the value.
 * @param str         String to which to append string representation.
 *
 * @return Status code.
 */
static te_errno
fcookie_tarpc2str_append(tarpc_ef_filter_cookie *cookie, te_string *str)
{
    if (cookie == NULL)
        return te_string_append(str, "(null)");

    return te_string_append(str, "{ filter_id: %d, filter_type %d }",
                            cookie->filter_id, cookie->filter_type);
}

/* See description in efvi_rpc.h */
int
rpc_ef_vi_filter_add(rcf_rpc_server *rpcs,
                     rpc_ef_vi_p vi,
                     rpc_ef_driver_handle vi_dh,
                     rpc_ef_filter_spec_p fs,
                     tarpc_ef_filter_cookie *cookie)
{
    tarpc_ef_vi_filter_add_in   in;
    tarpc_ef_vi_filter_add_out  out;

    te_string str = TE_STRING_INIT_STATIC(256);

    memset(&in, 0, sizeof(in));
    memset(&out, 0, sizeof(out));

    TAPI_RPC_NAMESPACE_CHECK_JUMP(rpcs, vi, RPC_TYPE_NS_EFVI_VI);
    TAPI_RPC_NAMESPACE_CHECK_JUMP(rpcs, fs, RPC_TYPE_NS_EFVI_FILTER_SPEC);
    in.vi = vi;
    in.vi_dh = vi_dh;
    in.fs = fs;
    if (cookie != NULL)
        in.get_cookie = TRUE;

    rcf_rpc_call(rpcs, "ef_vi_filter_add", &in, &out);

    CHECK_RETVAL_VAR_IS_GTE_MINUS_ONE(ef_vi_filter_add, out.retval);

    fcookie_tarpc2str_append(&out.cookie, &str);
    TAPI_RPC_LOG(rpcs, ef_vi_filter_add, RPC_PTR_FMT ", %d, " RPC_PTR_FMT
                 ", %p", "%d cookie=%s", RPC_PTR_VAL(vi), vi_dh,
                 RPC_PTR_VAL(fs), cookie, out.retval, str.ptr);

    if (RPC_IS_CALL_OK(rpcs) && rpcs->op != RCF_RPC_WAIT &&
        out.retval >= 0 && cookie != NULL)
    {
        memcpy(cookie, &out.cookie, sizeof(*cookie));
    }

    RETVAL_INT(ef_vi_filter_add, out.retval);
}

/* See description in efvi_rpc.h */
int
rpc_ef_vi_filter_del(rcf_rpc_server *rpcs,
                     rpc_ef_vi_p vi,
                     rpc_ef_driver_handle vi_dh,
                     tarpc_ef_filter_cookie *cookie)
{
    tarpc_ef_vi_filter_del_in   in;
    tarpc_ef_vi_filter_del_out  out;

    te_string str = TE_STRING_INIT_STATIC(256);

    memset(&in, 0, sizeof(in));
    memset(&out, 0, sizeof(out));

    TAPI_RPC_NAMESPACE_CHECK_JUMP(rpcs, vi, RPC_TYPE_NS_EFVI_VI);
    in.vi = vi;
    in.vi_dh = vi_dh;
    in.cookie.filter_id = cookie->filter_id;
    in.cookie.filter_type = cookie->filter_type;

    rcf_rpc_call(rpcs, "ef_vi_filter_del", &in, &out);

    CHECK_RETVAL_VAR_IS_GTE_MINUS_ONE(ef_vi_filter_del, out.retval);

    fcookie_tarpc2str_append(cookie, &str);
    TAPI_RPC_LOG(rpcs, ef_vi_filter_del, RPC_PTR_FMT ", %d, %s",
                 "%d", RPC_PTR_VAL(vi), vi_dh, str.ptr,
                 out.retval);

    RETVAL_INT(ef_vi_filter_del, out.retval);
}

/* See description in efvi_rpc.h */
int
rpc_ef_memreg_alloc(rcf_rpc_server *rpcs, rpc_ef_memreg_p *mr,
                    rpc_ef_driver_handle mr_dh, rpc_ef_pd_p pd,
                    rpc_ef_driver_handle pd_dh, rpc_ptr p_mem,
                    size_t len_bytes)
{
    tarpc_ef_memreg_alloc_in     in;
    tarpc_ef_memreg_alloc_out    out;

    if (mr == NULL)
    {
        ERROR("%s(): mr parameter must not be NULL", __FUNCTION__);
        rpcs->_errno = TE_RC(TE_RCF, TE_EINVAL);
        RETVAL_INT(ef_memreg_alloc, -1);
    }

    memset(&in, 0, sizeof(in));
    memset(&out, 0, sizeof(out));

    TAPI_RPC_NAMESPACE_CHECK_JUMP(rpcs, pd, RPC_TYPE_NS_EFVI_PD);
    in.mr_dh = mr_dh;
    in.pd = pd;
    in.pd_dh = pd_dh;
    in.p_mem = p_mem;
    in.len_bytes = len_bytes;

    rcf_rpc_call(rpcs, "ef_memreg_alloc", &in, &out);

    CHECK_RETVAL_VAR_IS_GTE_MINUS_ONE(ef_memreg_alloc, out.retval);

    TAPI_RPC_LOG(rpcs, ef_memreg_alloc, "%p, %d, " RPC_PTR_FMT ", %d, "
                 RPC_PTR_FMT ", %" TE_PRINTF_SIZE_T "u",
                 "%d, mr=" RPC_PTR_FMT, mr, mr_dh, RPC_PTR_VAL(pd),
                 pd_dh, RPC_PTR_VAL(p_mem), len_bytes,
                 out.retval, RPC_PTR_VAL(out.mr));

    if (RPC_IS_CALL_OK(rpcs) && rpcs->op != RCF_RPC_WAIT &&
        out.retval >= 0)
    {
        TAPI_RPC_NAMESPACE_CHECK_JUMP(rpcs, out.mr,
                                      RPC_TYPE_NS_EFVI_MEMREG);
        *mr = out.mr;
    }

    RETVAL_INT(ef_memreg_alloc, out.retval);
}

/* See description in efvi_rpc.h */
int
rpc_ef_memreg_free(rcf_rpc_server *rpcs, rpc_ef_memreg_p mr,
                   rpc_ef_driver_handle mr_dh)
{
    tarpc_ef_memreg_free_in     in;
    tarpc_ef_memreg_free_out    out;

    memset(&in, 0, sizeof(in));
    memset(&out, 0, sizeof(out));

    TAPI_RPC_NAMESPACE_CHECK_JUMP(rpcs, mr, RPC_TYPE_NS_EFVI_MEMREG);
    in.mr = mr;
    in.mr_dh = mr_dh;

    rcf_rpc_call(rpcs, "ef_memreg_free", &in, &out);

    CHECK_RETVAL_VAR_IS_GTE_MINUS_ONE(ef_memreg_free, out.retval);

    TAPI_RPC_LOG(rpcs, ef_memreg_free, RPC_PTR_FMT ", %d", "%d",
                 RPC_PTR_VAL(mr), mr_dh, out.retval);

    RETVAL_INT(ef_memreg_free, out.retval);
}

/* See description in efvi_rpc.h */
int
rpc_ef_memreg_dma_addr(rcf_rpc_server *rpcs,
                       rpc_ef_memreg_p mr,
                       size_t offset,
                       rpc_ef_addr *addr)
{
    tarpc_ef_memreg_dma_addr_in     in;
    tarpc_ef_memreg_dma_addr_out    out;

    memset(&in, 0, sizeof(in));
    memset(&out, 0, sizeof(out));

    TAPI_RPC_NAMESPACE_CHECK_JUMP(rpcs, mr, RPC_TYPE_NS_EFVI_MEMREG);
    in.mr = mr;
    in.offset = offset;

    rcf_rpc_call(rpcs, "ef_memreg_dma_addr", &in, &out);

    CHECK_RETVAL_VAR_IS_GTE_MINUS_ONE(ef_memreg_dma_addr, out.retval);

    TAPI_RPC_LOG(rpcs, ef_memreg_dma_addr,
                 RPC_PTR_FMT ", %" TE_PRINTF_SIZE_T "u",
                 "%d, addr=%" TE_PRINTF_64 "u",
                 RPC_PTR_VAL(mr), offset, out.retval, out.addr);

    if (RPC_IS_CALL_OK(rpcs) && rpcs->op != RCF_RPC_WAIT &&
        out.retval >= 0 && addr != NULL)
        *addr = out.addr;

    RETVAL_INT(ef_memreg_dma_addr, out.retval);
}

/* See description in efvi_rpc.h */
int
rpc_ef_vi_receive_init(rcf_rpc_server *rpcs, rpc_ef_vi_p vi,
                       rpc_ef_addr addr,
                       rpc_ef_request_id dma_id)
{
    tarpc_ef_vi_receive_init_rpc_in     in;
    tarpc_ef_vi_receive_init_rpc_out    out;

    memset(&in, 0, sizeof(in));
    memset(&out, 0, sizeof(out));

    TAPI_RPC_NAMESPACE_CHECK_JUMP(rpcs, vi, RPC_TYPE_NS_EFVI_VI);
    in.vi = vi;
    in.addr = addr;
    in.dma_id = dma_id;

    rcf_rpc_call(rpcs, "ef_vi_receive_init_rpc", &in, &out);

    CHECK_RETVAL_VAR_IS_GTE_MINUS_ONE(ef_vi_receive_init_rpc, out.retval);

    TAPI_RPC_LOG(rpcs, ef_vi_receive_init_rpc, RPC_PTR_FMT
                 ", %" TE_PRINTF_64 "u, %d", "%d",
                 RPC_PTR_VAL(vi), addr, dma_id, out.retval);

    RETVAL_INT(ef_vi_receive_init_rpc, out.retval);
}

/* See description in efvi_rpc.h */
int
rpc_ef_vi_receive_push(rcf_rpc_server *rpcs, rpc_ef_vi_p vi)
{
    tarpc_ef_vi_receive_push_rpc_in     in;
    tarpc_ef_vi_receive_push_rpc_out    out;

    memset(&in, 0, sizeof(in));
    memset(&out, 0, sizeof(out));

    TAPI_RPC_NAMESPACE_CHECK_JUMP(rpcs, vi, RPC_TYPE_NS_EFVI_VI);
    in.vi = vi;

    rcf_rpc_call(rpcs, "ef_vi_receive_push_rpc", &in, &out);

    CHECK_RETVAL_VAR_IS_GTE_MINUS_ONE(ef_vi_receive_push_rpc, out.retval);

    TAPI_RPC_LOG(rpcs, ef_vi_receive_push_rpc, RPC_PTR_FMT, "%d",
                 RPC_PTR_VAL(vi), out.retval);

    RETVAL_INT(ef_vi_receive_push_rpc, out.retval);
}

/* See description in efvi_rpc.h */
int
rpc_ef_vi_receive_post(rcf_rpc_server *rpcs, rpc_ef_vi_p vi,
                       rpc_ef_addr addr,
                       rpc_ef_request_id dma_id)
{
    tarpc_ef_vi_receive_post_in     in;
    tarpc_ef_vi_receive_post_out    out;

    memset(&in, 0, sizeof(in));
    memset(&out, 0, sizeof(out));

    TAPI_RPC_NAMESPACE_CHECK_JUMP(rpcs, vi, RPC_TYPE_NS_EFVI_VI);
    in.vi = vi;
    in.addr = addr;
    in.dma_id = dma_id;

    rcf_rpc_call(rpcs, "ef_vi_receive_post", &in, &out);

    CHECK_RETVAL_VAR_IS_GTE_MINUS_ONE(ef_vi_receive_post, out.retval);

    TAPI_RPC_LOG(rpcs, ef_vi_receive_post, RPC_PTR_FMT
                 ", %" TE_PRINTF_64 "u, %d", "%d",
                 RPC_PTR_VAL(vi), addr, dma_id, out.retval);

    RETVAL_INT(ef_vi_receive_post, out.retval);
}

/* See description in efvi_rpc.h */
int
rpc_ef_vi_transmit(rcf_rpc_server *rpcs, rpc_ef_vi_p vi,
                   rpc_ef_addr base, int len,
                   rpc_ef_request_id dma_id)
{
    tarpc_ef_vi_transmit_rpc_in     in;
    tarpc_ef_vi_transmit_rpc_out    out;

    memset(&in, 0, sizeof(in));
    memset(&out, 0, sizeof(out));

    TAPI_RPC_NAMESPACE_CHECK_JUMP(rpcs, vi, RPC_TYPE_NS_EFVI_VI);
    in.vi = vi;
    in.base = base;
    in.len = len;
    in.dma_id = dma_id;

    rcf_rpc_call(rpcs, "ef_vi_transmit_rpc", &in, &out);

    CHECK_RETVAL_VAR_IS_GTE_MINUS_ONE(ef_vi_transmit_rpc, out.retval);

    TAPI_RPC_LOG(rpcs, ef_vi_transmit_rpc, RPC_PTR_FMT
                 ", %" TE_PRINTF_64 "u, %d, %d", "%d",
                 RPC_PTR_VAL(vi), base, len, dma_id, out.retval);

    RETVAL_INT(ef_vi_transmit_rpc, out.retval);
}

/**
 * Append string representation of array of tarpc_ef_iovec to TE string.
 *
 * @param iov           Pointer to the array.
 * @param iov_len       Number of elements in the array.
 * @param str           TE string to which to append.
 *
 * @return Status code.
 */
static te_errno
ef_iovec_tarpc2str_append(tarpc_ef_iovec *iov, int iov_len, te_string *str)
{
    int i;

    STR_APPEND(str, "{");
    for (i = 0; i < iov_len; i++)
    {
        STR_APPEND(str, " { .iov_base=%" TE_PRINTF_64 "u, .iov_len=%d },",
                   iov[i].iov_base, (int)(iov[i].iov_len));
    }

    if (iov_len > 0)
        te_string_cut(str, 1);

    STR_APPEND(str, " }");

    return 0;
}

/* See description in efvi_rpc.h */
int
rpc_ef_vi_transmitv(rcf_rpc_server *rpcs, rpc_ef_vi_p vi,
                    tarpc_ef_iovec *iov, int iov_len,
                    rpc_ef_request_id dma_id)
{
    tarpc_ef_vi_transmitv_rpc_in     in;
    tarpc_ef_vi_transmitv_rpc_out    out;

    te_string str = TE_STRING_INIT_STATIC(4096);

    memset(&in, 0, sizeof(in));
    memset(&out, 0, sizeof(out));

    TAPI_RPC_NAMESPACE_CHECK_JUMP(rpcs, vi, RPC_TYPE_NS_EFVI_VI);
    in.vi = vi;
    in.iov.iov_val = iov;
    in.iov.iov_len = iov_len;
    in.dma_id = dma_id;

    rcf_rpc_call(rpcs, "ef_vi_transmitv_rpc", &in, &out);

    CHECK_RETVAL_VAR_IS_GTE_MINUS_ONE(ef_vi_transmitv_rpc, out.retval);

    ef_iovec_tarpc2str_append(iov, iov_len, &str);
    TAPI_RPC_LOG(rpcs, ef_vi_transmitv_rpc, RPC_PTR_FMT
                 ", %s, %d", "%d", RPC_PTR_VAL(vi), str.ptr, dma_id,
                 out.retval);

    RETVAL_INT(ef_vi_transmitv_rpc, out.retval);
}

/* See description in efvi_rpc.h */
int
rpc_ef_vi_transmit_init(rcf_rpc_server *rpcs, rpc_ef_vi_p vi,
                        rpc_ef_addr base, int len,
                        rpc_ef_request_id dma_id)
{
    tarpc_ef_vi_transmit_init_in     in;
    tarpc_ef_vi_transmit_init_out    out;

    memset(&in, 0, sizeof(in));
    memset(&out, 0, sizeof(out));

    TAPI_RPC_NAMESPACE_CHECK_JUMP(rpcs, vi, RPC_TYPE_NS_EFVI_VI);
    in.vi = vi;
    in.base = base;
    in.len = len;
    in.dma_id = dma_id;

    rcf_rpc_call(rpcs, "ef_vi_transmit_init", &in, &out);

    CHECK_RETVAL_VAR_IS_GTE_MINUS_ONE(ef_vi_transmit_init, out.retval);

    TAPI_RPC_LOG(rpcs, ef_vi_transmit_init, RPC_PTR_FMT
                 ", %" TE_PRINTF_64 "u, %d, %d", "%d",
                 RPC_PTR_VAL(vi), base, len, dma_id, out.retval);

    RETVAL_INT(ef_vi_transmit_init, out.retval);
}

/* See description in efvi_rpc.h */
int
rpc_ef_vi_transmitv_init(rcf_rpc_server *rpcs, rpc_ef_vi_p vi,
                         tarpc_ef_iovec *iov, int iov_len,
                         rpc_ef_request_id dma_id)
{
    tarpc_ef_vi_transmitv_init_rpc_in     in;
    tarpc_ef_vi_transmitv_init_rpc_out    out;

    te_string str = TE_STRING_INIT_STATIC(4096);

    memset(&in, 0, sizeof(in));
    memset(&out, 0, sizeof(out));

    TAPI_RPC_NAMESPACE_CHECK_JUMP(rpcs, vi, RPC_TYPE_NS_EFVI_VI);
    in.vi = vi;
    in.iov.iov_val = iov;
    in.iov.iov_len = iov_len;
    in.dma_id = dma_id;

    rcf_rpc_call(rpcs, "ef_vi_transmitv_init_rpc", &in, &out);

    CHECK_RETVAL_VAR_IS_GTE_MINUS_ONE(ef_vi_transmitv_init_rpc, out.retval);

    ef_iovec_tarpc2str_append(iov, iov_len, &str);
    TAPI_RPC_LOG(rpcs, ef_vi_transmitv_init_rpc, RPC_PTR_FMT
                 ", %s, %d", "%d", RPC_PTR_VAL(vi), str.ptr, dma_id,
                 out.retval);

    RETVAL_INT(ef_vi_transmitv_init_rpc, out.retval);
}

/* See description in efvi_rpc.h */
int
rpc_ef_vi_transmit_push(rcf_rpc_server *rpcs, rpc_ef_vi_p vi)
{
    tarpc_ef_vi_transmit_push_rpc_in     in;
    tarpc_ef_vi_transmit_push_rpc_out    out;

    memset(&in, 0, sizeof(in));
    memset(&out, 0, sizeof(out));

    TAPI_RPC_NAMESPACE_CHECK_JUMP(rpcs, vi, RPC_TYPE_NS_EFVI_VI);
    in.vi = vi;

    rcf_rpc_call(rpcs, "ef_vi_transmit_push_rpc", &in, &out);

    CHECK_RETVAL_VAR_IS_GTE_MINUS_ONE(ef_vi_transmit_push_rpc, out.retval);

    TAPI_RPC_LOG(rpcs, ef_vi_transmit_push_rpc, RPC_PTR_FMT, "%d",
                 RPC_PTR_VAL(vi), out.retval);

    RETVAL_INT(ef_vi_transmit_push_rpc, out.retval);
}

/* See description in efvi_rpc.h */
const char *
ef_event_type_h2str(int type)
{
#define EVT2STR(_evt) \
    case EF_EVENT_TYPE_ ## _evt:      \
        return #_evt;

    switch (type)
    {
        EVT2STR(RX);
        EVT2STR(TX);
        EVT2STR(RX_DISCARD);
        EVT2STR(TX_ERROR);
        EVT2STR(RX_NO_DESC_TRUNC);
        EVT2STR(SW);
        EVT2STR(OFLOW);
        EVT2STR(TX_WITH_TIMESTAMP);
        EVT2STR(RX_PACKED_STREAM);
        EVT2STR(RX_MULTI);
        EVT2STR(TX_ALT);
        EVT2STR(RX_MULTI_DISCARD);
        EVT2STR(RX_MULTI_PKTS);

        default:
            return "<UNKNOWN>";
    }

#undef EVT2STR
}

#define EVENT_FLAG_ENTRY(_val) \
    { #_val, (unsigned int)EF_EVENT_FLAG_ ## _val }

/**
 * Get string representation of ef_event RX flags.
 *
 * @param flags       RX flags.
 *
 * @return String representation.
 */
static const char *
ef_event_rx_flags_h2str(unsigned int flags)
{

    struct rpc_bit_map_entry map[] = {
        EVENT_FLAG_ENTRY(SOP),
        EVENT_FLAG_ENTRY(CONT),
        EVENT_FLAG_ENTRY(ISCSI_OK),
        EVENT_FLAG_ENTRY(MULTICAST),
        EVENT_FLAG_ENTRY(PS_NEXT_BUFFER),
        { NULL, 0 }
    };

    return bitmask2str(map, flags);
}

/**
 * Get string representation of ef_event TX flags.
 *
 * @param flags       TX flags.
 *
 * @return String representation.
 */
static const char *
ef_event_tx_flags_h2str(unsigned int flags)
{
    struct rpc_bit_map_entry map[] = {
        EVENT_FLAG_ENTRY(CTPIO),
        { NULL, 0 }
    };

    return bitmask2str(map, flags);
}

#undef EVENT_FLAG_ENTRY

/**
 * Append to TE string a representation of ef_event.
 *
 * @param evt           Pointer to the ef_event.
 * @param str           String to which to append the string
 *                      representation.
 *
 * @return Status code.
 */
static te_errno
ef_event_h2str_append(ef_event *evt, te_string *str)
{
#define STR_APPEND_FIELD(_str, _evt, _field, _fmt) \
    STR_APPEND(_str, ", " #_field ": " _fmt,       \
               evt->_evt._field)

    STR_APPEND(str, "{ type: %d (%s)", evt->generic.type,
               ef_event_type_h2str(evt->generic.type));

    switch (evt->generic.type)
    {
        case EF_EVENT_TYPE_RX:
            STR_APPEND_FIELD(str, rx, q_id, "%u");
            STR_APPEND_FIELD(str, rx, __reserved, "%u");
            STR_APPEND_FIELD(str, rx, rq_id, "%u");
            STR_APPEND_FIELD(str, rx, len, "%u");
            STR_APPEND(str, ", flags: %s",
                       ef_event_rx_flags_h2str(
                          evt->rx.flags));
            STR_APPEND_FIELD(str, rx, ofs, "%u");
            break;

        case EF_EVENT_TYPE_RX_DISCARD:
            STR_APPEND_FIELD(str, rx_discard, q_id, "%u");
            STR_APPEND_FIELD(str, rx_discard, __reserved, "%u");
            STR_APPEND_FIELD(str, rx_discard, rq_id, "%u");
            STR_APPEND_FIELD(str, rx_discard, len, "%u");
            STR_APPEND(str, ", flags: %s",
                       ef_event_rx_flags_h2str(
                          evt->rx_discard.flags));
            STR_APPEND_FIELD(str, rx_discard, subtype, "%u");
            break;

        case EF_EVENT_TYPE_TX:
            STR_APPEND_FIELD(str, tx, q_id, "%u");
            STR_APPEND(str, ", flags: %s",
                       ef_event_tx_flags_h2str(
                          evt->tx.flags));
            STR_APPEND_FIELD(str, tx, desc_id, "%u");
            break;

        case EF_EVENT_TYPE_TX_ERROR:
            STR_APPEND_FIELD(str, tx_error, q_id, "%u");
            STR_APPEND(str, ", flags: %s",
                       ef_event_tx_flags_h2str(
                          evt->tx_error.flags));
            STR_APPEND_FIELD(str, tx_error, desc_id, "%u");
            STR_APPEND_FIELD(str, tx_error, subtype, "%u");
            break;

        case EF_EVENT_TYPE_TX_WITH_TIMESTAMP:
            STR_APPEND_FIELD(str, tx_timestamp, q_id, "%u");
            STR_APPEND(str, ", flags: %s",
                       ef_event_tx_flags_h2str(
                          evt->tx_timestamp.flags));
            STR_APPEND_FIELD(str, tx_timestamp, rq_id, "%u");
            STR_APPEND_FIELD(str, tx_timestamp, ts_sec, "%u");
            STR_APPEND_FIELD(str, tx_timestamp, ts_nsec, "%u");
            break;

        case EF_EVENT_TYPE_TX_ALT:
            STR_APPEND_FIELD(str, tx_alt, q_id, "%u");
            STR_APPEND_FIELD(str, tx_alt, __reserved, "%u");
            STR_APPEND_FIELD(str, tx_alt, alt_id, "%u");
            break;

        case EF_EVENT_TYPE_RX_NO_DESC_TRUNC:
            STR_APPEND_FIELD(str, rx_no_desc_trunc, q_id, "%u");
            break;

        case EF_EVENT_TYPE_RX_PACKED_STREAM:
            STR_APPEND_FIELD(str, rx_packed_stream, q_id, "%u");
            STR_APPEND_FIELD(str, rx_packed_stream, __reserved, "%u");
            STR_APPEND(str, ", flags: %s",
                 ef_event_rx_flags_h2str(
                    evt->rx_packed_stream.flags));
            STR_APPEND_FIELD(str, rx_packed_stream, n_pkts, "%u");
            STR_APPEND_FIELD(str, rx_packed_stream, ps_flags, "0x%x");
            break;

        case EF_EVENT_TYPE_SW:
            STR_APPEND_FIELD(str, sw, data, "%u");
            break;

        case EF_EVENT_TYPE_RX_MULTI:
            STR_APPEND_FIELD(str, rx_multi, q_id, "%u");
            STR_APPEND_FIELD(str, rx_multi, __reserved, "%u");
            STR_APPEND_FIELD(str, rx_multi, n_descs, "%u");
            STR_APPEND(str, ", flags: %s",
                       ef_event_rx_flags_h2str(
                          evt->rx_multi.flags));
            break;

        case EF_EVENT_TYPE_RX_MULTI_DISCARD:
            STR_APPEND_FIELD(str, rx_multi_discard, q_id, "%u");
            STR_APPEND_FIELD(str, rx_multi_discard, __reserved, "%u");
            STR_APPEND_FIELD(str, rx_multi_discard, n_descs, "%u");
            STR_APPEND(str, ", flags: %s",
                 ef_event_rx_flags_h2str(
                    evt->rx_multi_discard.flags));
            STR_APPEND_FIELD(str, rx_multi_discard, subtype, "%u");
            break;

        case EF_EVENT_TYPE_RX_MULTI_PKTS:
            STR_APPEND_FIELD(str, rx_multi_pkts, q_id, "%u");
            STR_APPEND_FIELD(str, rx_multi_pkts, __reserved, "%u");
            STR_APPEND_FIELD(str, rx_multi_pkts, n_pkts, "%u");
            STR_APPEND(str, ", flags: %s",
                 ef_event_rx_flags_h2str(
                    evt->rx_multi_pkts.flags));
            break;

        default:
            break;
    }

    STR_APPEND(str, " }");

    return 0;
}

/**
 * Append to TE string a string representation of an array of
 * ef_event structures.
 *
 * @param evts          Pointer to the array.
 * @param evts_num      Number of elements in the array.
 * @param str           String to which to append the string
 *                      representation.
 *
 * @return Status code.
 */
static te_errno
ef_events_h2str_append(ef_event *evts, int evts_num, te_string *str)
{
    int i;
    te_errno rc;

    STR_APPEND(str, "{");
    for (i = 0; i < evts_num; i++)
    {
        STR_APPEND(str, " ");
        rc = ef_event_h2str_append(&evts[i], str);
        if (rc != 0)
            return rc;
        STR_APPEND(str, ",");
    }

    if (evts_num > 0)
        te_string_cut(str, 1); /* Trailing comma */

    STR_APPEND(str, " }");
    return 0;
}

/* See description in efvi_rpc.h */
int
rpc_ef_eventq_poll(rcf_rpc_server *rpcs, rpc_ef_vi_p vi,
                   ef_event *evts, int evts_num)
{
    te_string str = TE_STRING_INIT_STATIC(4096);

    tarpc_ef_eventq_poll_rpc_in     in;
    tarpc_ef_eventq_poll_rpc_out    out;

    tarpc_ef_event *tarpc_evts;

    tarpc_evts = TE_ALLOC(sizeof(*tarpc_evts) * evts_num);
    if (tarpc_evts == NULL)
    {
        ERROR("%s(): not enough memory for array of events",
              __FUNCTION__);
        rpcs->_errno = TE_RC(TE_RCF, TE_ENOMEM);
        RETVAL_INT(ef_eventq_poll_rpc, -1);
    }

    memset(&in, 0, sizeof(in));
    memset(&out, 0, sizeof(out));

    TAPI_RPC_NAMESPACE_CHECK_JUMP(rpcs, vi, RPC_TYPE_NS_EFVI_VI);
    in.vi = vi;
    in.events_num = evts_num;

    ef_events_h2tarpc(evts, tarpc_evts, evts_num);
    in.events.events_val = tarpc_evts;
    in.events.events_len = evts_num;

    rcf_rpc_call(rpcs, "ef_eventq_poll_rpc", &in, &out);
    free(tarpc_evts);

    CHECK_RETVAL_VAR_IS_GTE_MINUS_ONE(ef_eventq_poll_rpc, out.retval);

    if (RPC_IS_CALL_OK(rpcs) && rpcs->op != RCF_RPC_WAIT &&
        out.retval >= 0)
    {
        ef_events_tarpc2h(out.events.events_val, evts,
                          out.events.events_len);
        ef_events_h2str_append(evts, out.retval, &str);
    }

    TAPI_RPC_LOG(rpcs, ef_eventq_poll_rpc, RPC_PTR_FMT ", %p [%d]",
                 "%d evts=%s", RPC_PTR_VAL(vi), evts, evts_num,
                 out.retval, str.ptr);

    RETVAL_INT(ef_eventq_poll_rpc, out.retval);
}

/* See description in efvi_rpc.h */
int
rpc_efvi_get_pkt_data(rcf_rpc_server *rpcs, rpc_ef_vi_p vi,
                      tarpc_ptr mem, size_t offset, int len,
                      uint8_t *buf, int buf_len)
{
    tarpc_efvi_get_pkt_data_in     in;
    tarpc_efvi_get_pkt_data_out    out;

    memset(&in, 0, sizeof(in));
    memset(&out, 0, sizeof(out));

    TAPI_RPC_NAMESPACE_CHECK_JUMP(rpcs, vi, RPC_TYPE_NS_EFVI_VI);
    in.vi = vi;
    in.mem = mem;
    in.offset = offset;
    in.len = len;

    rcf_rpc_call(rpcs, "efvi_get_pkt_data", &in, &out);

    CHECK_RETVAL_VAR_IS_GTE_MINUS_ONE(efvi_get_pkt_data, out.retval);

    TAPI_RPC_LOG(rpcs, efvi_get_pkt_data, RPC_PTR_FMT ", " RPC_PTR_FMT
                 ", %" TE_PRINTF_SIZE_T "u, %d", "%d",
                 RPC_PTR_VAL(vi), RPC_PTR_VAL(mem), offset, len,
                 out.retval);

    if (RPC_IS_CALL_OK(rpcs) && rpcs->op != RCF_RPC_WAIT &&
        out.retval >= 0)
    {
        if (buf_len < out.retval)
        {
            ERROR("%s(): buffer length is %d, however data length is %d",
                  __FUNCTION__, buf_len, out.retval);
            rpcs->_errno = TE_RC(TE_RCF, TE_ESMALLBUF);
            RETVAL_INT(efvi_get_pkt_data, -1);
        }

        memcpy(buf, out.buf.buf_val, out.retval);
    }

    RETVAL_INT(efvi_get_pkt_data, out.retval);
}

/**
 * Append to TE string a string representation of array of
 * @ref rpc_ef_request_id values.
 *
 * @param ids         Pointer to the array.
 * @param num         Number of elements in the array.
 * @param str         String to which to append.
 *
 * @return Status code.
 */
static te_errno
ef_request_ids_rpc2str_append(rpc_ef_request_id *ids, int num,
                              te_string *str)
{
    int i;

    STR_APPEND(str, "[");

    for (i = 0; i < num; i++)
    {
        STR_APPEND(str, " %d,", ids[i]);
    }

    if (num > 0)
        te_string_cut(str, 1);

    STR_APPEND(str, " ]");
    return 0;
}

/* See description in efvi_rpc.h */
int
rpc_ef_vi_transmit_unbundle(rcf_rpc_server *rpcs, rpc_ef_vi_p vi,
                            ef_event *event, rpc_ef_request_id *ids)
{
    tarpc_ef_vi_transmit_unbundle_in     in;
    tarpc_ef_vi_transmit_unbundle_out    out;

    te_string str_evt = TE_STRING_INIT_STATIC(256);
    te_string str_ids = TE_STRING_INIT_STATIC(1024);
    int i;

    memset(&in, 0, sizeof(in));
    memset(&out, 0, sizeof(out));

    TAPI_RPC_NAMESPACE_CHECK_JUMP(rpcs, vi, RPC_TYPE_NS_EFVI_VI);
    in.vi = vi;
    ef_events_h2tarpc(event, &in.event, 1);

    rcf_rpc_call(rpcs, "ef_vi_transmit_unbundle", &in, &out);

    CHECK_RETVAL_VAR_IS_GTE_MINUS_ONE(ef_vi_transmit_unbundle, out.retval);

    if (RPC_IS_CALL_OK(rpcs) && rpcs->op != RCF_RPC_WAIT &&
        out.retval > 0)
    {
        for (i = 0; i < out.retval; i++)
        {
            ids[i] = out.ids.ids_val[i];
        }
    }

    ef_event_h2str_append(event, &str_evt);
    ef_request_ids_rpc2str_append(ids, out.retval, &str_ids);

    TAPI_RPC_LOG(rpcs, ef_vi_transmit_unbundle, RPC_PTR_FMT
                 ", %s", "%d ids=%s", RPC_PTR_VAL(vi), str_evt.ptr,
                 out.retval, str_ids.ptr);

    RETVAL_INT(ef_vi_transmit_unbundle, out.retval);
}

/* See description in efvi_rpc.h */
int
rpc_ef_vi_receive_unbundle(rcf_rpc_server *rpcs, rpc_ef_vi_p vi,
                           ef_event *event, rpc_ef_request_id *ids)
{
    tarpc_ef_vi_receive_unbundle_in     in;
    tarpc_ef_vi_receive_unbundle_out    out;

    te_string str_evt = TE_STRING_INIT_STATIC(256);
    te_string str_ids = TE_STRING_INIT_STATIC(1024);
    int i;

    memset(&in, 0, sizeof(in));
    memset(&out, 0, sizeof(out));

    TAPI_RPC_NAMESPACE_CHECK_JUMP(rpcs, vi, RPC_TYPE_NS_EFVI_VI);
    in.vi = vi;
    ef_events_h2tarpc(event, &in.event, 1);

    rcf_rpc_call(rpcs, "ef_vi_receive_unbundle", &in, &out);

    CHECK_RETVAL_VAR_IS_GTE_MINUS_ONE(ef_vi_receive_unbundle, out.retval);

    if (RPC_IS_CALL_OK(rpcs) && rpcs->op != RCF_RPC_WAIT &&
        out.retval > 0)
    {
        for (i = 0; i < out.retval; i++)
        {
            ids[i] = out.ids.ids_val[i];
        }
    }

    ef_event_h2str_append(event, &str_evt);
    ef_request_ids_rpc2str_append(ids, out.retval, &str_ids);

    TAPI_RPC_LOG(rpcs, ef_vi_receive_unbundle, RPC_PTR_FMT
                 ", %s", "%d ids=%s", RPC_PTR_VAL(vi), str_evt.ptr,
                 out.retval, str_ids.ptr);

    RETVAL_INT(ef_vi_receive_unbundle, out.retval);
}

/* See description in efvi_rpc.h */
int
rpc_ef_vi_receive_get_bytes(rcf_rpc_server *rpcs, rpc_ef_vi_p vi,
                            tarpc_ptr mem, size_t offset, unsigned int *len)
{
    tarpc_ef_vi_receive_get_bytes_in     in;
    tarpc_ef_vi_receive_get_bytes_out    out;

    memset(&in, 0, sizeof(in));
    memset(&out, 0, sizeof(out));

    TAPI_RPC_NAMESPACE_CHECK_JUMP(rpcs, vi, RPC_TYPE_NS_EFVI_VI);
    in.vi = vi;
    in.mem = mem;
    in.offset = offset;

    rcf_rpc_call(rpcs, "ef_vi_receive_get_bytes", &in, &out);

    CHECK_RETVAL_VAR_IS_GTE_MINUS_ONE(ef_vi_receive_get_bytes, out.retval);

    TAPI_RPC_LOG(rpcs, ef_vi_receive_get_bytes, RPC_PTR_FMT ", " RPC_PTR_FMT
                 ", %" TE_PRINTF_SIZE_T "u", "%d len=%u",
                 RPC_PTR_VAL(vi), RPC_PTR_VAL(mem), offset,
                 out.retval, (unsigned int)(out.len));

    *len = out.len;

    RETVAL_INT(ef_vi_receive_get_bytes, out.retval);
}
