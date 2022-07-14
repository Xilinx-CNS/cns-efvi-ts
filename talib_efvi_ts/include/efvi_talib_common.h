/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2020 - 2022 Xilinx, Inc. All rights reserved. */
/** @file
 * @brief Common definitions for agent and test API libraries.
 *
 * Common definitions for agent and test API libraries.
 *
 * @author Dmitry Izbitsky <Dmitry.Izbitsky@oktetlabs.ru>
 */

#ifndef ___EFVI_TALIB_COMMON_H__
#define ___EFVI_TALIB_COMMON_H__

#include "te_rpc_types.h"

#include "etherfabric/ef_vi.h"

/** Namespace for pointers to ef_pd */
#define RPC_TYPE_NS_EFVI_PD           "efvi_pd"
/** Namespace for pointers to ef_vi */
#define RPC_TYPE_NS_EFVI_VI           "efvi_vi"
/** Namespace for pointers to ef_filter_spec */
#define RPC_TYPE_NS_EFVI_FILTER_SPEC  "efvi_filter_spec"
/** Namespace for pointers to ef_memreg */
#define RPC_TYPE_NS_EFVI_MEMREG       "efvi_memreg"

/** Type of RPC pointer to ef_pd */
typedef rpc_ptr rpc_ef_pd_p;
/** Type of RPC pointer to ef_vi */
typedef rpc_ptr rpc_ef_vi_p;
/** Type of RPC pointer to ef_filter_spec */
typedef rpc_ptr rpc_ef_filter_spec_p;
/** Type of RPC pointer to ef_memreg */
typedef rpc_ptr rpc_ef_memreg_p;

/** RPC flags corresponding to flags from ef_pd_flags */
typedef enum rpc_ef_pd_flags {
    RPC_EF_PD_VF               = 0x1,
    RPC_EF_PD_PHYS_MODE        = 0x2,
    RPC_EF_PD_RX_PACKED_STREAM = 0x4,
    RPC_EF_PD_VPORT            = 0x8,
    RPC_EF_PD_MCAST_LOOP       = 0x10,
    RPC_EF_PD_MEMREG_64KiB     = 0x20,
    RPC_EF_PD_IGNORE_BLACKLIST = 0x40,
} rpc_ef_pd_flags;

/** Default protection domain flags */
#define RPC_EF_PD_DEFAULT 0

/** Mapping list for ef_pd_flags_rpc2str() */
#define EF_PD_FLAGS_MAPPING_LIST \
    RPC_BIT_MAP_ENTRY(EF_PD_VF), \
    RPC_BIT_MAP_ENTRY(EF_PD_PHYS_MODE), \
    RPC_BIT_MAP_ENTRY(EF_PD_RX_PACKED_STREAM), \
    RPC_BIT_MAP_ENTRY(EF_PD_VPORT), \
    RPC_BIT_MAP_ENTRY(EF_PD_MCAST_LOOP), \
    RPC_BIT_MAP_ENTRY(EF_PD_MEMREG_64KiB), \
    RPC_BIT_MAP_ENTRY(EF_PD_IGNORE_BLACKLIST)

/**
 * ef_pd_flags_rpc2str()
 */
RPCBITMAP2STR(ef_pd_flags, EF_PD_FLAGS_MAPPING_LIST)

/** RPC flags corresponding to flags from ef_vi_flags */
typedef enum rpc_ef_vi_flags {
    RPC_EF_VI_ISCSI_RX_HDIG     = 0x2,
    RPC_EF_VI_ISCSI_TX_HDIG     = 0x4,
    RPC_EF_VI_ISCSI_RX_DDIG     = 0x8,
    RPC_EF_VI_ISCSI_TX_DDIG     = 0x10,
    RPC_EF_VI_TX_PHYS_ADDR      = 0x20,
    RPC_EF_VI_RX_PHYS_ADDR      = 0x40,
    RPC_EF_VI_TX_IP_CSUM_DIS    = 0x80,
    RPC_EF_VI_TX_TCPUDP_CSUM_DIS = 0x100,
    RPC_EF_VI_TX_TCPUDP_ONLY    = 0x200,
    RPC_EF_VI_TX_FILTER_IP      = 0x400,
    RPC_EF_VI_TX_FILTER_MAC     = 0x800,
    RPC_EF_VI_TX_FILTER_MASK_1  = 0x1000,
    RPC_EF_VI_TX_FILTER_MASK_2  = 0x2000,
    RPC_EF_VI_TX_PUSH_DISABLE   = 0x4000,
    RPC_EF_VI_TX_PUSH_ALWAYS    = 0x8000,
    RPC_EF_VI_RX_TIMESTAMPS     = 0x10000,
    RPC_EF_VI_TX_TIMESTAMPS     = 0x20000,
    RPC_EF_VI_RX_PACKED_STREAM  = 0x80000,
    RPC_EF_VI_RX_PS_BUF_SIZE_64K = 0x100000,
    RPC_EF_VI_RX_EVENT_MERGE = 0x200000,
    RPC_EF_VI_TX_ALT             = 0x400000,
    RPC_EF_VI_ENABLE_EV_TIMER = 0x800000,
    RPC_EF_VI_TX_CTPIO           = 0x1000000,
    RPC_EF_VI_TX_CTPIO_NO_POISON = 0x2000000,
    RPC_EF_VI_RX_ZEROCOPY = 0x4000000,
} rpc_ef_vi_flags;

/** Default RPC flags for virtual interface */
#define RPC_EF_VI_FLAGS_DEFAULT 0

/** RPC define for @c EF_VI_TX_FILTER_MASK_3 */
#define RPC_EF_VI_TX_FILTER_MASK_3 (RPC_EF_VI_TX_FILTER_MASK_1 | \
                                    RPC_EF_VI_TX_FILTER_MASK_2)

/** Mapping list for ef_vi_flags_rpc2str() */
#define EF_VI_FLAGS_MAPPING_LIST \
    RPC_BIT_MAP_ENTRY(EF_VI_ISCSI_RX_HDIG), \
    RPC_BIT_MAP_ENTRY(EF_VI_ISCSI_TX_HDIG), \
    RPC_BIT_MAP_ENTRY(EF_VI_ISCSI_RX_DDIG), \
    RPC_BIT_MAP_ENTRY(EF_VI_ISCSI_TX_DDIG), \
    RPC_BIT_MAP_ENTRY(EF_VI_TX_PHYS_ADDR), \
    RPC_BIT_MAP_ENTRY(EF_VI_RX_PHYS_ADDR), \
    RPC_BIT_MAP_ENTRY(EF_VI_TX_IP_CSUM_DIS), \
    RPC_BIT_MAP_ENTRY(EF_VI_TX_TCPUDP_CSUM_DIS), \
    RPC_BIT_MAP_ENTRY(EF_VI_TX_TCPUDP_ONLY), \
    RPC_BIT_MAP_ENTRY(EF_VI_TX_FILTER_IP), \
    RPC_BIT_MAP_ENTRY(EF_VI_TX_FILTER_MAC), \
    RPC_BIT_MAP_ENTRY(EF_VI_TX_FILTER_MASK_1), \
    RPC_BIT_MAP_ENTRY(EF_VI_TX_FILTER_MASK_2), \
    RPC_BIT_MAP_ENTRY(EF_VI_TX_PUSH_DISABLE), \
    RPC_BIT_MAP_ENTRY(EF_VI_TX_PUSH_ALWAYS), \
    RPC_BIT_MAP_ENTRY(EF_VI_RX_TIMESTAMPS), \
    RPC_BIT_MAP_ENTRY(EF_VI_TX_TIMESTAMPS), \
    RPC_BIT_MAP_ENTRY(EF_VI_RX_PACKED_STREAM), \
    RPC_BIT_MAP_ENTRY(EF_VI_RX_PS_BUF_SIZE_64K), \
    RPC_BIT_MAP_ENTRY(EF_VI_RX_EVENT_MERGE), \
    RPC_BIT_MAP_ENTRY(EF_VI_TX_ALT), \
    RPC_BIT_MAP_ENTRY(EF_VI_ENABLE_EV_TIMER), \
    RPC_BIT_MAP_ENTRY(EF_VI_TX_CTPIO), \
    RPC_BIT_MAP_ENTRY(EF_VI_TX_CTPIO_NO_POISON), \
    RPC_BIT_MAP_ENTRY(EF_VI_RX_ZEROCOPY)

/**
 * ef_vi_flags_rpc2str()
 */
RPCBITMAP2STR(ef_vi_flags, EF_VI_FLAGS_MAPPING_LIST)

/** RPC flags corresponding to flags from ef_filter_flags */
typedef enum rpc_ef_filter_flags {
    RPC_EF_FILTER_FLAG_NONE = 0x0,
    RPC_EF_FILTER_FLAG_MCAST_LOOP_RECEIVE = 0x2,
} rpc_ef_filter_flags;

/** Mapping list for ef_filter_flags_rpc2str() */
#define EF_FILTER_FLAGS_MAPPING_LIST \
    RPC_BIT_MAP_ENTRY(EF_FILTER_FLAG_MCAST_LOOP_RECEIVE)

/**
 * ef_filter_flags_rpc2str()
 */
RPCBITMAP2STR(ef_filter_flags, EF_FILTER_FLAGS_MAPPING_LIST)

/**
 * Copy subfield between two structures (possibly of different types).
 *
 * @param _dst        Destination structure.
 * @param _src        Source structure.
 * @param _field      Field name.
 * @param _subfield   Subfield name.
 */
#define EFVI_COPY_SUBFIELD(_dst, _src, _field, _subfield) \
    _dst._field._subfield = _src._field._subfield

/**
 * Copy all fields of ef_event of type RX (except type).
 *
 * @param _dst    Destination structure.
 * @param _src    Source structure.
 */
#define EFVI_COPY_RX_EVENT(_dst, _src) \
    do {                                                  \
        EFVI_COPY_SUBFIELD(_dst, _src, rx, q_id);         \
        EFVI_COPY_SUBFIELD(_dst, _src, rx, __reserved);   \
        EFVI_COPY_SUBFIELD(_dst, _src, rx, rq_id);        \
        EFVI_COPY_SUBFIELD(_dst, _src, rx, len);          \
        EFVI_COPY_SUBFIELD(_dst, _src, rx, flags);        \
        EFVI_COPY_SUBFIELD(_dst, _src, rx, ofs);          \
    } while (0)

/**
 * Copy all fields ef_event of type RX_DISCARD (except type).
 *
 * @param _dst    Destination structure.
 * @param _src    Source structure.
 */
#define EFVI_COPY_RX_DISCARD_EVENT(_dst, _src) \
    do {                                                          \
        EFVI_COPY_SUBFIELD(_dst, _src, rx_discard, q_id);         \
        EFVI_COPY_SUBFIELD(_dst, _src, rx_discard, __reserved);   \
        EFVI_COPY_SUBFIELD(_dst, _src, rx_discard, rq_id);        \
        EFVI_COPY_SUBFIELD(_dst, _src, rx_discard, len);          \
        EFVI_COPY_SUBFIELD(_dst, _src, rx_discard, flags);        \
        EFVI_COPY_SUBFIELD(_dst, _src, rx_discard, subtype);      \
    } while (0)

/**
 * Copy all fields of ef_event of type TX (except type).
 *
 * @param _dst    Destination structure.
 * @param _src    Source structure.
 */
#define EFVI_COPY_TX_EVENT(_dst, _src) \
    do {                                                  \
        EFVI_COPY_SUBFIELD(_dst, _src, tx, q_id);         \
        EFVI_COPY_SUBFIELD(_dst, _src, tx, flags);        \
        EFVI_COPY_SUBFIELD(_dst, _src, tx, desc_id);      \
    } while (0)

/**
 * Copy all fields of ef_event of type TX_ERROR (except type).
 *
 * @param _dst    Destination structure.
 * @param _src    Source structure.
 */
#define EFVI_COPY_TX_ERROR_EVENT(_dst, _src) \
    do {                                                        \
        EFVI_COPY_SUBFIELD(_dst, _src, tx_error, q_id);         \
        EFVI_COPY_SUBFIELD(_dst, _src, tx_error, flags);        \
        EFVI_COPY_SUBFIELD(_dst, _src, tx_error, desc_id);      \
        EFVI_COPY_SUBFIELD(_dst, _src, tx_error, subtype);      \
    } while (0)

/**
 * Copy all fields of ef_event of type TX_WITH_TIMESTAMP (except type).
 *
 * @param _dst    Destination structure.
 * @param _src    Source structure.
 */
#define EFVI_COPY_TX_WITH_TIMESTAMP_EVENT(_dst, _src) \
    do {                                                            \
        EFVI_COPY_SUBFIELD(_dst, _src, tx_timestamp, q_id);         \
        EFVI_COPY_SUBFIELD(_dst, _src, tx_timestamp, flags);        \
        EFVI_COPY_SUBFIELD(_dst, _src, tx_timestamp, rq_id);        \
        EFVI_COPY_SUBFIELD(_dst, _src, tx_timestamp, ts_sec);       \
        EFVI_COPY_SUBFIELD(_dst, _src, tx_timestamp, ts_nsec);      \
    } while (0)

/**
 * Copy all fields of ef_event of type TX_ALT (except type).
 *
 * @param _dst    Destination structure.
 * @param _src    Source structure.
 */
#define EFVI_COPY_TX_ALT_EVENT(_dst, _src) \
    do {                                                      \
        EFVI_COPY_SUBFIELD(_dst, _src, tx_alt, q_id);         \
        EFVI_COPY_SUBFIELD(_dst, _src, tx_alt, __reserved);   \
        EFVI_COPY_SUBFIELD(_dst, _src, tx_alt, alt_id);       \
    } while (0)

/**
 * Copy all fields of ef_event of type NO_DESC_TRUNC (except type).
 *
 * @param _dst    Destination structure.
 * @param _src    Source structure.
 */
#define EFVI_COPY_RX_NO_DESC_TRUNC_EVENT(_dst, _src) \
    do {                                                          \
        EFVI_COPY_SUBFIELD(_dst, _src, rx_no_desc_trunc, q_id);   \
    } while (0)

/**
 * Copy all fields of ef_event of type RX_PACKED_STREAM (except type).
 *
 * @param _dst    Destination structure.
 * @param _src    Source structure.
 */
#define EFVI_COPY_RX_PACKED_STREAM_EVENT(_dst, _src) \
    do {                                                                \
        EFVI_COPY_SUBFIELD(_dst, _src, rx_packed_stream, q_id);         \
        EFVI_COPY_SUBFIELD(_dst, _src, rx_packed_stream, __reserved);   \
        EFVI_COPY_SUBFIELD(_dst, _src, rx_packed_stream, flags);        \
        EFVI_COPY_SUBFIELD(_dst, _src, rx_packed_stream, n_pkts);       \
        EFVI_COPY_SUBFIELD(_dst, _src, rx_packed_stream, ps_flags);     \
    } while (0)

/**
 * Copy all fields of ef_event of type SW (except type).
 *
 * @param _dst    Destination structure.
 * @param _src    Source structure.
 */
#define EFVI_COPY_SW_EVENT(_dst, _src) \
    do {                                                  \
        EFVI_COPY_SUBFIELD(_dst, _src, sw, data);         \
    } while (0)

/**
 * Copy all fields of ef_event of type RX_MULTI (except type).
 *
 * @param _dst    Destination structure.
 * @param _src    Source structure.
 */
#define EFVI_COPY_RX_MULTI_EVENT(_dst, _src) \
    do {                                                        \
        EFVI_COPY_SUBFIELD(_dst, _src, rx_multi, q_id);         \
        EFVI_COPY_SUBFIELD(_dst, _src, rx_multi, __reserved);   \
        EFVI_COPY_SUBFIELD(_dst, _src, rx_multi, n_descs);      \
        EFVI_COPY_SUBFIELD(_dst, _src, rx_multi, flags);        \
    } while (0)

/**
 * Copy all fields of ef_event of type RX_MULTI_DISCARD (except type).
 *
 * @param _dst    Destination structure.
 * @param _src    Source structure.
 */
#define EFVI_COPY_RX_MULTI_DISCARD_EVENT(_dst, _src) \
    do {                                                                \
        EFVI_COPY_SUBFIELD(_dst, _src, rx_multi_discard, q_id);         \
        EFVI_COPY_SUBFIELD(_dst, _src, rx_multi_discard, __reserved);   \
        EFVI_COPY_SUBFIELD(_dst, _src, rx_multi_discard, n_descs);      \
        EFVI_COPY_SUBFIELD(_dst, _src, rx_multi_discard, flags);        \
        EFVI_COPY_SUBFIELD(_dst, _src, rx_multi_discard, subtype);      \
    } while (0)

/**
 * Copy all fields of ef_event of type RX_MULTI_PKTS (except type).
 *
 * @param _dst    Destination structure.
 * @param _src    Source structure.
 */
#define EFVI_COPY_RX_MULTI_PKTS_EVENT(_dst, _src) \
    do {                                                             \
        EFVI_COPY_SUBFIELD(_dst, _src, rx_multi_pkts, q_id);         \
        EFVI_COPY_SUBFIELD(_dst, _src, rx_multi_pkts, __reserved);   \
        EFVI_COPY_SUBFIELD(_dst, _src, rx_multi_pkts, n_pkts);       \
        EFVI_COPY_SUBFIELD(_dst, _src, rx_multi_pkts, flags);        \
    } while (0)

/**
 * Handle the single event type in a switch when copying event fields.
 *
 * @param _dst    Destination structure.
 * @param _src    Source structure.
 * @param _evt    Event type (RX, TX, RX_DISCARD, etc.).
 */
#define EFVI_COPY_EVENT_CASE(_dst, _src, _evt) \
      case EF_EVENT_TYPE_ ## _evt:                      \
          EFVI_COPY_ ## _evt ## _EVENT(_dst, _src);     \
          break

/**
 * Copy all fields of ef_event of a given type (except type field itself)
 * between two structures.
 *
 * @param _dst      Destination structure.
 * @param _src      Source structure.
 * @param _type     Event type.
 */
#define EFVI_COPY_EVENT(_dst, _src, _type) \
    do {                                                          \
        switch (_type)                                            \
        {                                                         \
            EFVI_COPY_EVENT_CASE(_dst, _src, RX);                 \
            EFVI_COPY_EVENT_CASE(_dst, _src, TX);                 \
            EFVI_COPY_EVENT_CASE(_dst, _src, RX_DISCARD);         \
            EFVI_COPY_EVENT_CASE(_dst, _src, TX_ERROR);           \
            EFVI_COPY_EVENT_CASE(_dst, _src, RX_NO_DESC_TRUNC);   \
            EFVI_COPY_EVENT_CASE(_dst, _src, SW);                 \
            EFVI_COPY_EVENT_CASE(_dst, _src, TX_WITH_TIMESTAMP);  \
            EFVI_COPY_EVENT_CASE(_dst, _src, RX_PACKED_STREAM);   \
            EFVI_COPY_EVENT_CASE(_dst, _src, RX_MULTI);           \
            EFVI_COPY_EVENT_CASE(_dst, _src, TX_ALT);             \
            EFVI_COPY_EVENT_CASE(_dst, _src, RX_MULTI_DISCARD);   \
            EFVI_COPY_EVENT_CASE(_dst, _src, RX_MULTI_PKTS);      \
                                                                  \
            default:                                              \
                break;                                            \
        }                                                         \
    } while (0)

/**
 * Copy data from array of ef_event structures to array of
 * tarpc_ef_event structures.
 *
 * @param evs         Array of ef_event structures.
 * @param tarpc_evs   Array of tarpc_ef_event structures.
 * @param num         Number of elements in the arrays.
 */
static inline void
ef_events_h2tarpc(ef_event *evs, tarpc_ef_event *tarpc_evs, int num)
{
    int i;

    for (i = 0; i < num; i++)
    {
        tarpc_evs[i].type = evs[i].generic.type;
        EFVI_COPY_EVENT(tarpc_evs[i].tarpc_ef_event_u, evs[i],
                        tarpc_evs[i].type);
    }
}

/**
 * Copy data from array of tarpc_ef_event structures to array of
 * ef_event structures.
 *
 * @param tarpc_evs   Array of tarpc_ef_event structures.
 * @param evs         Array of ef_event structures.
 * @param num         Number of elements in the arrays.
 */
static inline void
ef_events_tarpc2h(tarpc_ef_event *tarpc_evs, ef_event *evs, int num)
{
    int i;

    for (i = 0; i < num; i++)
    {
        evs[i].generic.type = tarpc_evs[i].type;
        EFVI_COPY_EVENT(evs[i], tarpc_evs[i].tarpc_ef_event_u,
                        tarpc_evs[i].type);
    }
}

#endif /* !___EFVI_TALIB_COMMON_H__ */
