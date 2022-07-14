/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2020 - 2022 Xilinx, Inc. All rights reserved. */
/** @file
 * @brief RPC entities definition
 *
 * Definition of RPC structures and functions for EF_VI Test Suite.
 *
 * @author Damir Mansurov <Damir.Mansurov@oktetlabs.ru>
 */

struct tarpc_ef_iovec {
    uint64_t    iov_base;
    tarpc_int   iov_len;
};

typedef struct tarpc_void_in tarpc_ef_driver_open_in;

struct tarpc_ef_driver_open_out {
    struct tarpc_out_arg    common;
    tarpc_int               handle;
    tarpc_int               retval;
};

struct tarpc_ef_driver_close_in {
    struct tarpc_in_arg     common;
    tarpc_int               handle;
};

struct tarpc_ef_driver_close_out {
    struct tarpc_out_arg    common;
    tarpc_int               retval;
};

struct tarpc_ef_pd_alloc_in {
    struct tarpc_in_arg     common;
    tarpc_int               pd_dh;
    tarpc_int               ifindex;
    tarpc_uint              flags;
};

struct tarpc_ef_pd_alloc_out {
    struct tarpc_out_arg    common;
    tarpc_ptr               pd;
    tarpc_int               retval;
};

struct tarpc_ef_pd_free_in {
    struct tarpc_in_arg     common;
    tarpc_ptr               pd;
    tarpc_int               pd_dh;
};

typedef struct tarpc_int_retval_out tarpc_ef_pd_free_out;

struct tarpc_ef_vi_alloc_from_pd_in {
    struct tarpc_in_arg     common;
    tarpc_int               vi_dh;
    tarpc_ptr               pd;
    tarpc_int               pd_dh;
    tarpc_int               evq_capacity;
    tarpc_int               rxq_capacity;
    tarpc_int               txq_capacity;
    tarpc_ptr               evq_opt;
    tarpc_int               evq_dh;
    tarpc_uint              flags;
};

struct tarpc_ef_vi_alloc_from_pd_out {
    struct tarpc_out_arg    common;
    tarpc_ptr               vi;
    tarpc_int               retval;
};

struct tarpc_ef_vi_free_in {
    struct tarpc_in_arg     common;
    tarpc_ptr               vi;
    tarpc_int               nic_dh;
};

typedef struct tarpc_int_retval_out tarpc_ef_vi_free_out;

struct tarpc_ef_filter_spec_alloc_in {
    struct tarpc_in_arg     common;
    tarpc_uint              flags;
};

struct tarpc_ef_filter_spec_alloc_out {
    struct tarpc_out_arg     common;
    tarpc_ptr                fs;
    tarpc_int                retval;
};

struct tarpc_ef_filter_spec_free_in {
    struct tarpc_in_arg     common;
    tarpc_ptr               fs;
};

typedef struct tarpc_int_retval_out tarpc_ef_filter_spec_free_out;

struct tarpc_ef_filter_spec_set_ip4_local_in {
    struct tarpc_in_arg     common;
    tarpc_ptr               fs;
    tarpc_int               protocol;
    struct tarpc_sa         addr;
};

typedef struct tarpc_int_retval_out tarpc_ef_filter_spec_set_ip4_local_out;

struct tarpc_ef_filter_spec_set_ip4_full_in {
    struct tarpc_in_arg     common;
    tarpc_ptr               fs;
    tarpc_int               protocol;
    struct tarpc_sa         laddr;
    struct tarpc_sa         raddr;
};

typedef struct tarpc_int_retval_out tarpc_ef_filter_spec_set_ip4_full_out;

typedef struct tarpc_ef_filter_spec_set_ip4_local_in
                                tarpc_ef_filter_spec_set_ip6_local_in;

typedef struct tarpc_int_retval_out tarpc_ef_filter_spec_set_ip6_local_out;

typedef struct tarpc_ef_filter_spec_set_ip4_full_in
                                tarpc_ef_filter_spec_set_ip6_full_in;

typedef struct tarpc_int_retval_out tarpc_ef_filter_spec_set_ip6_full_out;

struct tarpc_ef_filter_cookie {
    tarpc_int filter_id;
    tarpc_int filter_type;
};

struct tarpc_ef_vi_filter_add_in {
    struct tarpc_in_arg     common;
    tarpc_ptr               vi;
    tarpc_int               vi_dh;
    tarpc_ptr               fs;
    tarpc_bool              get_cookie;
};

struct tarpc_ef_vi_filter_add_out {
    struct tarpc_out_arg    common;
    tarpc_ef_filter_cookie  cookie;
    tarpc_int               retval;
};

struct tarpc_ef_vi_filter_del_in {
    struct tarpc_in_arg     common;
    tarpc_ptr               vi;
    tarpc_int               vi_dh;
    tarpc_ef_filter_cookie  cookie;
};

typedef struct tarpc_int_retval_out tarpc_ef_vi_filter_del_out;

struct tarpc_ef_memreg_alloc_in {
    struct tarpc_in_arg     common;
    tarpc_int               mr_dh;
    tarpc_ptr               pd;
    tarpc_int               pd_dh;
    tarpc_ptr               p_mem;
    tarpc_size_t            len_bytes;
};

struct tarpc_ef_memreg_alloc_out {
    struct tarpc_out_arg    common;
    tarpc_ptr               mr;
    tarpc_int               retval;
};

struct tarpc_ef_memreg_free_in {
    struct tarpc_in_arg     common;
    tarpc_ptr               mr;
    tarpc_int               mr_dh;
};

typedef struct tarpc_int_retval_out tarpc_ef_memreg_free_out;

struct tarpc_ef_memreg_dma_addr_in {
    struct tarpc_in_arg     common;
    tarpc_ptr               mr;
    tarpc_size_t            offset;
};

struct tarpc_ef_memreg_dma_addr_out {
    struct tarpc_out_arg    common;
    uint64_t                addr;
    tarpc_int               retval;
};

struct tarpc_ef_vi_receive_init_rpc_in {
    struct tarpc_in_arg     common;
    tarpc_ptr               vi;
    uint64_t                addr;
    tarpc_int               dma_id;
};

typedef struct tarpc_int_retval_out tarpc_ef_vi_receive_init_rpc_out;

struct tarpc_ef_vi_receive_push_rpc_in {
    struct tarpc_in_arg     common;
    tarpc_ptr               vi;
};

typedef struct tarpc_int_retval_out tarpc_ef_vi_receive_push_rpc_out;

struct tarpc_ef_vi_receive_post_in {
    struct tarpc_in_arg     common;
    tarpc_ptr               vi;
    uint64_t                addr;
    tarpc_int               dma_id;
};

typedef struct tarpc_int_retval_out tarpc_ef_vi_receive_post_out;

struct tarpc_ef_vi_transmit_rpc_in {
    struct tarpc_in_arg     common;
    tarpc_ptr               vi;
    uint64_t                base;
    tarpc_int               len;
    tarpc_int               dma_id;
};

typedef struct tarpc_int_retval_out tarpc_ef_vi_transmit_rpc_out;

struct tarpc_ef_vi_transmitv_rpc_in {
    struct tarpc_in_arg     common;
    tarpc_ptr               vi;
    tarpc_ef_iovec          iov<>;
    tarpc_int               dma_id;
};

typedef struct tarpc_int_retval_out tarpc_ef_vi_transmitv_rpc_out;

struct tarpc_ef_vi_transmit_init_in {
    struct tarpc_in_arg     common;
    tarpc_ptr               vi;
    uint64_t                base;
    tarpc_int               len;
    tarpc_int               dma_id;
};

typedef struct tarpc_int_retval_out tarpc_ef_vi_transmit_init_out;

struct tarpc_ef_vi_transmitv_init_rpc_in {
    struct tarpc_in_arg     common;
    tarpc_ptr               vi;
    tarpc_ef_iovec          iov<>;
    tarpc_int               dma_id;
};

typedef struct tarpc_int_retval_out tarpc_ef_vi_transmitv_init_rpc_out;

struct tarpc_ef_vi_transmit_push_rpc_in {
    struct tarpc_in_arg     common;
    tarpc_ptr               vi;
};

typedef struct tarpc_int_retval_out tarpc_ef_vi_transmit_push_rpc_out;

/* These values should correspond to ef_event_type values */
enum tarpc_ef_event_type {
  TARPC_EF_EVENT_TYPE_RX,
  TARPC_EF_EVENT_TYPE_TX,
  TARPC_EF_EVENT_TYPE_RX_DISCARD,
  TARPC_EF_EVENT_TYPE_TX_ERROR,
  TARPC_EF_EVENT_TYPE_RX_NO_DESC_TRUNC,
  TARPC_EF_EVENT_TYPE_SW,
  TARPC_EF_EVENT_TYPE_OFLOW,
  TARPC_EF_EVENT_TYPE_TX_WITH_TIMESTAMP,
  TARPC_EF_EVENT_TYPE_RX_PACKED_STREAM,
  TARPC_EF_EVENT_TYPE_RX_MULTI,
  TARPC_EF_EVENT_TYPE_TX_ALT,
  TARPC_EF_EVENT_TYPE_RX_MULTI_DISCARD,
  TARPC_EF_EVENT_TYPE_RX_MULTI_PKTS
};

struct tarpc_ef_event_rx {
    tarpc_uint q_id;
    tarpc_uint __reserved;
    tarpc_uint rq_id;
    tarpc_uint len;
    tarpc_uint flags;
    tarpc_uint ofs;
};

struct tarpc_ef_event_rx_discard {
    tarpc_uint q_id;
    tarpc_uint __reserved;
    tarpc_uint rq_id;
    tarpc_uint len;
    tarpc_uint flags;
    tarpc_uint subtype;
};

struct tarpc_ef_event_tx {
    tarpc_uint q_id;
    tarpc_uint flags;
    tarpc_uint desc_id;
};

struct tarpc_ef_event_tx_error {
    tarpc_uint q_id;
    tarpc_uint flags;
    tarpc_uint desc_id;
    tarpc_uint subtype;
};

struct tarpc_ef_event_tx_timestamp {
    tarpc_uint q_id;
    tarpc_uint flags;
    tarpc_uint rq_id;
    tarpc_uint ts_sec;
    tarpc_uint ts_nsec;
};

struct tarpc_ef_event_tx_alt {
    tarpc_uint q_id;
    tarpc_uint __reserved;
    tarpc_uint alt_id;
};

struct tarpc_ef_event_rx_no_desc_trunc {
    tarpc_uint q_id;
};

struct tarpc_ef_event_rx_packed_stream {
    tarpc_uint q_id;
    tarpc_uint __reserved;
    tarpc_uint flags;
    tarpc_uint n_pkts;
    tarpc_uint ps_flags;
};

struct tarpc_ef_event_sw {
    tarpc_uint data;
};

struct tarpc_ef_event_rx_multi {
    tarpc_uint q_id;
    tarpc_uint __reserved;
    tarpc_uint n_descs;
    tarpc_uint flags;
};

struct tarpc_ef_event_rx_multi_discard {
    tarpc_uint q_id;
    tarpc_uint __reserved;
    tarpc_uint n_descs;
    tarpc_uint flags;
    tarpc_uint subtype;
};

struct tarpc_ef_event_rx_multi_pkts {
    tarpc_uint q_id;
    tarpc_uint __reserved;
    tarpc_uint n_pkts;
    tarpc_uint flags;
};

union tarpc_ef_event switch(tarpc_ef_event_type type) {
    case TARPC_EF_EVENT_TYPE_RX:
        struct tarpc_ef_event_rx rx;
    case TARPC_EF_EVENT_TYPE_RX_DISCARD:
        struct tarpc_ef_event_rx_discard rx_discard;
    case TARPC_EF_EVENT_TYPE_TX:
        struct tarpc_ef_event_tx tx;
    case TARPC_EF_EVENT_TYPE_TX_ERROR:
        struct tarpc_ef_event_tx_error tx_error;
    case TARPC_EF_EVENT_TYPE_TX_WITH_TIMESTAMP:
        struct tarpc_ef_event_tx_timestamp tx_timestamp;
    case TARPC_EF_EVENT_TYPE_TX_ALT:
        struct tarpc_ef_event_tx_alt tx_alt;
    case TARPC_EF_EVENT_TYPE_RX_NO_DESC_TRUNC:
        struct tarpc_ef_event_rx_no_desc_trunc rx_no_desc_trunc;
    case TARPC_EF_EVENT_TYPE_RX_PACKED_STREAM:
        struct tarpc_ef_event_rx_packed_stream rx_packed_stream;
    case TARPC_EF_EVENT_TYPE_SW:
        struct tarpc_ef_event_sw sw;
    case TARPC_EF_EVENT_TYPE_RX_MULTI:
        struct tarpc_ef_event_rx_multi rx_multi;
    case TARPC_EF_EVENT_TYPE_RX_MULTI_DISCARD:
        struct tarpc_ef_event_rx_multi_discard rx_multi_discard;
    case TARPC_EF_EVENT_TYPE_RX_MULTI_PKTS:
        struct tarpc_ef_event_rx_multi_pkts rx_multi_pkts;
    default:
        void;
};

struct tarpc_ef_eventq_poll_rpc_in {
    struct tarpc_in_arg     common;

    tarpc_ptr               vi;
    tarpc_ef_event          events<>;
    tarpc_int               events_num;
};

struct tarpc_ef_eventq_poll_rpc_out {
    struct tarpc_out_arg    common;

    tarpc_ef_event          events<>;
    tarpc_int               retval;
};

struct tarpc_efvi_get_pkt_data_in {
    struct tarpc_in_arg     common;

    tarpc_ptr               vi;
    tarpc_ptr               mem;
    tarpc_size_t            offset;
    int                     len;
};

struct tarpc_efvi_get_pkt_data_out {
    struct tarpc_out_arg    common;

    uint8_t                 buf<>;
    tarpc_int               retval;
};

struct tarpc_ef_vi_transmit_unbundle_in {
    struct tarpc_in_arg     common;

    tarpc_ptr               vi;
    tarpc_ef_event          event;
};

struct tarpc_ef_vi_transmit_unbundle_out {
    struct tarpc_out_arg    common;

    tarpc_int               ids<>;
    tarpc_int               retval;
};

struct tarpc_ef_vi_receive_unbundle_in {
    struct tarpc_in_arg     common;

    tarpc_ptr               vi;
    tarpc_ef_event          event;
};

struct tarpc_ef_vi_receive_unbundle_out {
    struct tarpc_out_arg    common;

    tarpc_int               ids<>;
    tarpc_int               retval;
};

struct tarpc_ef_vi_receive_get_bytes_in {
    struct tarpc_out_arg    common;

    tarpc_ptr               vi;
    tarpc_ptr               mem;
    tarpc_size_t            offset;
};

struct tarpc_ef_vi_receive_get_bytes_out {
    struct tarpc_out_arg    common;

    tarpc_uint              len;
    tarpc_int               retval;
};

program efvirpc
{
    version ver0
    {
        RPC_DEF(ef_driver_open)
        RPC_DEF(ef_driver_close)
        RPC_DEF(ef_pd_alloc)
        RPC_DEF(ef_pd_free)
        RPC_DEF(ef_vi_alloc_from_pd)
        RPC_DEF(ef_vi_free)
        RPC_DEF(ef_filter_spec_alloc)
        RPC_DEF(ef_filter_spec_free)
        RPC_DEF(ef_filter_spec_set_ip4_local)
        RPC_DEF(ef_filter_spec_set_ip4_full)
        RPC_DEF(ef_filter_spec_set_ip6_local)
        RPC_DEF(ef_filter_spec_set_ip6_full)
        RPC_DEF(ef_vi_filter_add)
        RPC_DEF(ef_vi_filter_del)
        RPC_DEF(ef_memreg_alloc)
        RPC_DEF(ef_memreg_free)
        RPC_DEF(ef_memreg_dma_addr)
        RPC_DEF(ef_vi_receive_init_rpc)
        RPC_DEF(ef_vi_receive_push_rpc)
        RPC_DEF(ef_vi_receive_post)
        RPC_DEF(ef_vi_transmit_rpc)
        RPC_DEF(ef_vi_transmitv_rpc)
        RPC_DEF(ef_vi_transmit_init)
        RPC_DEF(ef_vi_transmitv_init_rpc)
        RPC_DEF(ef_vi_transmit_push_rpc)
        RPC_DEF(ef_eventq_poll_rpc)
        RPC_DEF(efvi_get_pkt_data)
        RPC_DEF(ef_vi_transmit_unbundle)
        RPC_DEF(ef_vi_receive_unbundle)
        RPC_DEF(ef_vi_receive_get_bytes)
    } = 1;
} = 2;
