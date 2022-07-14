/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2020 - 2022 Xilinx, Inc. All rights reserved. */
/** @file
 * @brief Common test API definition
 *
 * Definition of common test API.
 *
 * @author Damir Mansurov <Damir.Mansurov@oktetlabs.ru>
 */

#ifndef ___EFVI_TS_H__
#define ___EFVI_TS_H__

#include "te_config.h"

#include "tapi_test.h"
#include "tapi_env.h"
#include "tapi_mem.h"
#include "tapi_tcp.h"
#include "tapi_rpcsock_macros.h"
#include "te_sockaddr.h"
#include "tapi_sockaddr.h"
#include "tapi_cfg_base.h"

#include "efvi_rpc.h"

/** Serial logs parser agent name */
#define SERIAL_LOG_PARSER_AGENT "LogListener"

/** Serial logs parser console name */
#define SERIAL_LOG_PARSER_CONSOLE_NAME "serial_console"

/** Ethernet header length (if no VLAN is present) */
#define EFVI_ETH_HLEN 14
/** Minimum length of Ethernet frame */
#define EFVI_ETH_MIN_LEN 60
/** IPv4 header length (without options) */
#define EFVI_IP4_HLEN 20
/** IPv6 header length (without extension headers) */
#define EFVI_IP6_HLEN 40
/** UDP header length */
#define EFVI_UDP_HLEN 8
/** TCP header length (without options) */
#define EFVI_TCP_HLEN 20

/** List of IP protocol values for EFVI_GET_IP_PROTO */
#define EFVI_IP_PROTOS \
    { "IPPROTO_UDP", RPC_IPPROTO_UDP }, \
    { "IPPROTO_TCP", RPC_IPPROTO_TCP }

/**
 * Get IP protocol test parameter.
 *
 * @param _proto    Test parameter to obtain
 */
#define EFVI_GET_IP_PROTO(_proto) \
    TEST_GET_ENUM_PARAM(_proto, EFVI_IP_PROTOS)

/**
 * Options for a packet checksum.
 */
typedef enum efvi_csum {
    EFVI_CSUM_OK,       /**< Correct value */
    EFVI_CSUM_ZERO,     /**< Zero value */
    EFVI_CSUM_WRONG,    /**< Incorrect value */
} efvi_csum;

/**
 * Fill Ethernet header.
 *
 * @param buf         Packet buffer.
 * @param len         Length of the buffer.
 * @param pos         Current position in the buffer (updated by
 *                    this function).
 * @param src_addr    Source Ethernet address.
 * @param dst_addr    Destination Ethernet address.
 * @param vlan_id     VLAN ID (if negative, no VLAN).
 * @param ether_type  EtherType value (if negative, payload length
 *                    will be set in the related field).
 *
 * @return Status code.
 */
extern te_errno efvi_fill_eth(uint8_t *buf, int len, int *pos,
                              const void *src_addr,
                              const void *dst_addr,
                              int vlan_id, int ether_type);

/**
 * Fill IPv4 header.
 *
 * @note IPv4 options are not supported in this function.
 *
 * @param buf             Packet buffer.
 * @param len             Length of the buffer.
 * @param pos             Current position in the buffer (updated by
 *                        this function).
 * @param src_addr        Source address.
 * @param dst_addr        Destination address.
 * @param ttl             Time to live.
 * @param protocol        Protocol (@c IPPROTO_TCP, @c IPPROTO_UDP).
 * @param ip_csum         How to set checksum.
 *
 * @return Status code.
 */
extern te_errno efvi_fill_ipv4(uint8_t *buf, int len, int *pos,
                               const struct sockaddr *src_addr,
                               const struct sockaddr *dst_addr,
                               int ttl, int protocol, efvi_csum ip_csum);

/**
 * Fill IPv6 header.
 *
 * @param buf             Packet buffer.
 * @param len             Length of the buffer.
 * @param pos             Current position in the buffer (updated by
 *                        this function).
 * @param src_addr        Source address.
 * @param dst_addr        Destination address.
 * @param next_header     Next header (usually @c IPPROTO_TCP or
 *                        @c IPPROTO_UDP).
 * @param hop_limit       Hop limit (similar to TTL for IPv4).
 *
 * @return Status code.
 */
extern te_errno efvi_fill_ipv6(uint8_t *buf, int len, int *pos,
                               const struct sockaddr *src_addr,
                               const struct sockaddr *dst_addr,
                               uint8_t next_header, uint8_t hop_limit);

/**
 * Fill UDP header.
 *
 * @param buf             Packet buffer.
 * @param len             Length of the buffer.
 * @param pos             Current position in the buffer (updated by
 *                        this function).
 * @param src_addr        Source address/port.
 * @param dst_addr        Destination address/port.
 * @param udp_csum        How to set checksum.
 *
 * @return Status code.
 */
extern te_errno efvi_fill_udp(uint8_t *buf, int len, int *pos,
                              const struct sockaddr *src_addr,
                              const struct sockaddr *dst_addr,
                              efvi_csum udp_csum);

/**
 * Fill TCP header.
 *
 * @param buf             Packet buffer.
 * @param len             Length of the buffer.
 * @param pos             Current position in the buffer (updated by
 *                        this function).
 * @param src_addr        Source address/port.
 * @param dst_addr        Destination address/port.
 * @param seqn            TCP SEQ number.
 * @param ackn            TCP ACK number.
 * @param flags           TCP flags (@c TCP_ACK_FLAG, @c TCP_FIN_FLAG, etc.)
 * @param win             TCP window size.
 * @param tcp_csum        How to set checksum.
 *
 * @return Status code.
 */
extern te_errno efvi_fill_tcp(uint8_t *buf, int len, int *pos,
                              const struct sockaddr *src_addr,
                              const struct sockaddr *dst_addr,
                              uint32_t seqn, uint32_t ackn,
                              uint16_t flags, uint16_t win,
                              efvi_csum tcp_csum);

/**
 * Construct Ethernet + IPv4/IPv6 + TCP/UDP packet in a provided buffer.
 *
 * @note This function chooses packet length randomly and may use less
 *       bytes than there are in the provided buffer.
 *
 * @param buf           Buffer.
 * @param len           Length of the buffer.
 * @param vlan_id       VLAN ID (if negative, no VLAN).
 * @param ip_proto      IP protocol (@c RPC_IPPROTO_TCP or
 *                      @c RPC_IPPROTO_UDP).
 * @param src_ll_addr   Source Ethernet address.
 * @param dst_ll_addr   Destination Ethernet address.
 * @param src_addr      Source IP address and port.
 * @param dst_addr      Destination IP address and port.
 * @param out_len       Where to save length of the constructed packet.
 *
 * @return Status code.
 */
extern te_errno efvi_fill_eth_ip_tcp_udp(
                                  uint8_t *buf, int len, int vlan_id,
                                  rpc_socket_proto ip_proto,
                                  const void *src_ll_addr,
                                  const void *dst_ll_addr,
                                  const struct sockaddr *src_addr,
                                  const struct sockaddr *dst_addr,
                                  int *out_len);

#endif /* !___EFVI_TS_H__ */
