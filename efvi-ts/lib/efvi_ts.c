/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2020 - 2022 Xilinx, Inc. All rights reserved. */
/** @file
 * @brief Common test API
 *
 * Implementation of common test API.
 *
 * @author Dmitry Izbitsky <Dmitry.Izbitsky@oktetlabs.ru>
 */

/** Log user name of EF_VI API test suite library */
#define TE_LGR_USER     "Library"

#include "efvi_test.h"

#if HAVE_NETINET_IN_H
#include <netinet/in.h>
#endif
#ifdef HAVE_NETINET_IP_H
#include <netinet/ip.h>
#endif
#ifdef HAVE_NETINET_TCP_H
#include <netinet/tcp.h>
#endif
#ifdef HAVE_NETINET_UDP_H
#include <netinet/udp.h>
#endif
#ifdef HAVE_NET_ETHERNET_H
#include <net/ethernet.h>
#endif
#ifdef HAVE_NETPACKET_PACKET_H
#include <netpacket/packet.h>
#endif
#ifdef HAVE_LINUX_IF_ETHER_H
#include <linux/if_ether.h>
#endif

#include <netinet/ip6.h>

#include "tapi_tcp.h"

/**
 * Check return value of a given expression, if it is non-zero,
 * return it from the current function.
 *
 * @param _expr     Expression to check.
 */
#define CHECK_RETURN(_expr) \
    do {                                                                \
        te_errno _rc;                                                   \
                                                                        \
        _rc = (_expr);                                                  \
        if (_rc != 0)                                                   \
        {                                                               \
            ERROR("%s(): %s returned %r", __FUNCTION__, #_expr, _rc);   \
            return _rc;                                                 \
        }                                                               \
    } while (0)

/**
 * Append data to a given packet buffer.
 *
 * @param buf       Pointer to the buffer.
 * @param len       Length of the buffer.
 * @param pos       Current position in the buffer (updated by this
 *                  function).
 * @param data      Pointer to data to append.
 * @param data_len  Length of the data.
 *
 * @return Status code.
 */
static te_errno
push_data(uint8_t *buf, int len, int *pos, const void *data, int data_len)
{
    if (*pos + data_len > len)
    {
        ERROR("%s(): not enough space in the buffer", __FUNCTION__);
        return TE_RC(TE_TAPI, TE_ESMALLBUF);
    }

    memcpy(buf + *pos, data, data_len);
    *pos += data_len;
    return 0;
}

/**
 * Append 16bit number to a given packet buffer.
 *
 * @param buf         Pointer to the buffer.
 * @param len         Length of the buffer.
 * @param pos         Current position in the buffer (updated by this
 *                    function).
 * @param data        16bit number to append.
 * @param net_order   If @c TRUE, convert number to network byte order.
 *
 * @return Status code.
 */
static te_errno
push16(uint8_t *buf, int len, int *pos, uint16_t data, te_bool net_order)
{
    if (*pos + 2 > len)
    {
        ERROR("%s(): not enough space in the buffer", __FUNCTION__);
        return TE_RC(TE_TAPI, TE_ESMALLBUF);
    }

    if (net_order)
        data = htons(data);
    *(uint16_t *)(buf + *pos) = data;
    *pos += 2;
    return 0;
}

/* See description in efvi_ts.h */
te_errno
efvi_fill_eth(uint8_t *buf, int len, int *pos,
              const void *src_addr, const void *dst_addr,
              int vlan_id, int ether_type)
{
    CHECK_RETURN(push_data(buf, len, pos, dst_addr, ETH_ALEN));
    CHECK_RETURN(push_data(buf, len, pos, src_addr, ETH_ALEN));

    if (vlan_id >= 0)
    {
        CHECK_RETURN(push16(buf, len, pos, ETHERTYPE_VLAN, TRUE));
        CHECK_RETURN(push16(buf, len, pos, vlan_id, TRUE));
    }

    if (ether_type < 0)
    {
        ether_type = len - *pos;
        if (ether_type > 1500)
        {
            ERROR("%s(): buffer is too big to pass payload length in "
                  "EtherType field", __FUNCTION__);
            return TE_RC(TE_TAPI, TE_EINVAL);
        }
    }

    CHECK_RETURN(push16(buf, len, pos, ether_type, TRUE));

    return 0;
}

/**
 * Add values to a computed IP/UDP/TCP checksum.
 *
 * @note It adds 16bit at a time, if only the single byte remains,
 *       it appends @c 0 to it as the second byte.
 *
 * @param csum        Current checksum value.
 * @param p           Pointer to values to add.
 * @param len         Number of bytes to add.
 *
 * @return Updated checksum value.
 */
static uint16_t
add_to_csum(uint16_t csum, void *p, int len)
{
    int i;
    uint32_t val = csum;

    for (i = 0; i < (len + 1) / 2; i++)
    {
        if (i * 2 + 1 == len)
        {
            uint8_t x[2];

            x[0] = *((uint8_t *)p + i * 2);
            x[1] = 0;
            val += ntohs(*((uint16_t *)x));
        }
        else
        {
            val += ntohs(*((uint16_t *)p + i));
        }

        while (val > 0xffff)
        {
            val = val & 0xffff;
            val++;
        }
    }

    return val;
}

/**
 * Compute IPv4 packet header checksum.
 *
 * @param iph     Pointer to IPv4 header.
 * @param len     Length of the header.
 *
 * @return Checksum value.
 */
static uint16_t
ipv4_hdr_csum(void *iph, int len)
{
    return ~(add_to_csum(0, iph, len));
}

/* See description in efvi_ts.h */
te_errno
efvi_fill_ipv4(uint8_t *buf, int len, int *pos,
               const struct sockaddr *src_addr,
               const struct sockaddr *dst_addr,
               int ttl, int protocol, efvi_csum ip_csum)
{
    struct iphdr *iph;
    int payload_len;

    if (*pos + (int)sizeof(*iph) > len)
    {
        ERROR("%s(): not enough space in the provided buffer",
              __FUNCTION__);
        return TE_RC(TE_TAPI, TE_ESMALLBUF);
    }

    iph = (struct iphdr *)(buf + *pos);
    payload_len = len - *pos - sizeof(*iph);

    memset(iph, 0, sizeof(*iph));
    iph->version = IPVERSION;
    iph->ihl = 5;
    iph->tot_len = htons(payload_len + sizeof(*iph));
    iph->ttl = ttl;
    iph->protocol = protocol;
    iph->saddr = SIN(src_addr)->sin_addr.s_addr;
    iph->daddr = SIN(dst_addr)->sin_addr.s_addr;

    if (ip_csum != EFVI_CSUM_ZERO)
    {
        iph->check = htons(ipv4_hdr_csum(iph, sizeof(*iph)));
        if (ip_csum == EFVI_CSUM_WRONG)
            iph->check += rand_range(1, 0xffff);
    }

    *pos += sizeof(*iph);
    return 0;
}

/* See description in efvi_ts.h */
te_errno
efvi_fill_ipv6(uint8_t *buf, int len, int *pos,
               const struct sockaddr *src_addr,
               const struct sockaddr *dst_addr,
               uint8_t next_header, uint8_t hop_limit)
{
    struct ip6_hdr *iph;
    int payload_len;

    if (*pos + (int)sizeof(*iph) > len)
    {
        ERROR("%s(): not enough space in the provided buffer",
              __FUNCTION__);
        return TE_RC(TE_TAPI, TE_ESMALLBUF);
    }

    iph = (struct ip6_hdr *)(buf + *pos);
    payload_len = len - *pos - sizeof(*iph);

    memset(iph, 0, sizeof(*iph));

    /* This is IPv6 version written to the lower bits */
    iph->ip6_flow = htonl(6);

    iph->ip6_plen = htons(payload_len);
    iph->ip6_nxt = next_header;
    iph->ip6_hlim = hop_limit;

    memcpy(&iph->ip6_src, &SIN6(src_addr)->sin6_addr,
           sizeof(struct in6_addr));
    memcpy(&iph->ip6_dst, &SIN6(dst_addr)->sin6_addr,
           sizeof(struct in6_addr));

    *pos += sizeof(*iph);
    return 0;
}

/**
 * Compute TCP or UDP checksum for IPv4 packet.
 *
 * @param src_addr        Source address/port.
 * @param dst_addr        Destination address/port.
 * @param ip_proto        @c IPPROTO_UDP or @c IPPROTO_TCP.
 * @param p               Pointer to UDP or TCP header.
 * @param len             Length of the TCP/UDP header and
 *                        payload.
 *
 * @return Checksum value.
 */
static uint16_t
tcp_udp_ipv4_csum(const struct sockaddr *src_addr,
                  const struct sockaddr *dst_addr,
                  int ip_proto, void *p, int len)
{
    uint16_t csum = 0;
    uint8_t proto[2];
    uint16_t len_field;

    csum = add_to_csum(csum, &SIN(src_addr)->sin_addr,
                       sizeof(struct in_addr));
    csum = add_to_csum(csum, &SIN(dst_addr)->sin_addr,
                       sizeof(struct in_addr));

    proto[0] = 0;
    proto[1] = ip_proto;
    csum = add_to_csum(csum, proto, sizeof(proto));

    len_field = htons(len);
    csum = add_to_csum(csum, &len_field, sizeof(len_field));

    csum = add_to_csum(csum, p, len);
    return ~csum;
}

/**
 * Compute TCP or UDP checksum for IPv6 packet.
 *
 * @param src_addr        Source address/port.
 * @param dst_addr        Destination address/port.
 * @param ip_proto        @c IPPROTO_UDP or @c IPPROTO_TCP.
 * @param p               Pointer to UDP or TCP header.
 * @param len             Length of the TCP/UDP header and
 *                        payload.
 *
 * @return Checksum value.
 */
static uint16_t
tcp_udp_ipv6_csum(const struct sockaddr *src_addr,
                  const struct sockaddr *dst_addr,
                  int ip_proto, void *p, int len)
{
    uint16_t csum = 0;
    uint8_t proto[2];
    uint32_t len_field;

    csum = add_to_csum(csum, &SIN6(src_addr)->sin6_addr,
                       sizeof(struct in6_addr));
    csum = add_to_csum(csum, &SIN6(dst_addr)->sin6_addr,
                       sizeof(struct in6_addr));

    len_field = htonl(len);
    csum = add_to_csum(csum, &len_field, sizeof(len_field));

    proto[0] = 0;
    proto[1] = ip_proto;
    csum = add_to_csum(csum, proto, sizeof(proto));

    csum = add_to_csum(csum, p, len);
    return ~csum;
}

/**
 * Compute TCP or UDP checksum for IPv4 or IPv6 packet.
 *
 * @param src_addr        Source address/port.
 * @param dst_addr        Destination address/port.
 * @param ip_proto        @c IPPROTO_UDP or @c IPPROTO_TCP.
 * @param p               Pointer to UDP or TCP header.
 * @param len             Length of the TCP/UDP header and
 *                        payload.
 *
 * @return Checksum value.
 */
static uint16_t
tcp_udp_ip_csum(const struct sockaddr *src_addr,
                const struct sockaddr *dst_addr,
                int ip_proto, void *p, int len)
{
    if (src_addr->sa_family == AF_INET)
        return tcp_udp_ipv4_csum(src_addr, dst_addr, ip_proto, p, len);
    else
        return tcp_udp_ipv6_csum(src_addr, dst_addr, ip_proto, p, len);
}

/**
 * Choose non-zero value not equal to the correct checksum.
 *
 * @param correct_csum      Correct checksum value.
 *
 * @return A non-zero value not matching the correct checksum.
 */
static uint16_t
choose_wrong_csum(uint16_t correct_csum)
{
    uint16_t new_val;

    do {
        new_val = rand_range(1, 0xffff);
    } while (new_val == correct_csum);

    return new_val;
}

/* See description in efvi_ts.h */
te_errno
efvi_fill_udp(uint8_t *buf, int len, int *pos,
              const struct sockaddr *src_addr,
              const struct sockaddr *dst_addr,
              efvi_csum udp_csum)
{
    struct udphdr *udph;
    uint16_t udp_len;
    uint16_t src_port;
    uint16_t dst_port;

    if (*pos + (int)sizeof(*udph) > len)
    {
        ERROR("%s(): not enough space in the provided buffer",
              __FUNCTION__);
        return TE_RC(TE_TAPI, TE_ESMALLBUF);
    }

    udph = (struct udphdr *)(buf + *pos);

    if (src_addr->sa_family == AF_INET)
    {
        src_port = SIN(src_addr)->sin_port;
        dst_port = SIN(dst_addr)->sin_port;
    }
    else
    {
        src_port = SIN6(src_addr)->sin6_port;
        dst_port = SIN6(dst_addr)->sin6_port;
    }

    udp_len = len - *pos;

    memset(udph, 0, sizeof(*udph));
    udph->source = src_port;
    udph->dest = dst_port;
    udph->len = htons(udp_len);

    if (udp_csum != EFVI_CSUM_ZERO)
    {
        uint16_t csum;

        csum = tcp_udp_ip_csum(src_addr, dst_addr, IPPROTO_UDP,
                               udph, udp_len);

        udph->check = htons(csum);

        /*
         * See RFC 768: "If the computed checksum is zero, it is
         * transmitted as all ones".
         */
        if (udph->check == 0)
            udph->check = 0xffff;

        if (udp_csum == EFVI_CSUM_WRONG)
            udph->check = choose_wrong_csum(udph->check);
    }

    *pos += udp_len;
    return 0;
}

/* See description in efvi_ts.h */
te_errno
efvi_fill_tcp(uint8_t *buf, int len, int *pos,
              const struct sockaddr *src_addr,
              const struct sockaddr *dst_addr,
              uint32_t seqn, uint32_t ackn,
              uint16_t flags, uint16_t win,
              efvi_csum tcp_csum)
{
#define SET_FLAG(_flg, _field) \
    if (flags & TCP_ ## _flg ## _FLAG) \
        tcph->_field = 1

    struct tcphdr *tcph;
    uint16_t tcp_len;
    uint16_t src_port;
    uint16_t dst_port;

    if (*pos + (int)sizeof(*tcph) > len)
    {
        ERROR("%s(): not enough space in the provided buffer",
              __FUNCTION__);
        return TE_RC(TE_TAPI, TE_ESMALLBUF);
    }

    tcph = (struct tcphdr *)(buf + *pos);

    if (src_addr->sa_family == AF_INET)
    {
        src_port = SIN(src_addr)->sin_port;
        dst_port = SIN(dst_addr)->sin_port;
    }
    else
    {
        src_port = SIN6(src_addr)->sin6_port;
        dst_port = SIN6(dst_addr)->sin6_port;
    }

    tcp_len = len - *pos;

    memset(tcph, 0, sizeof(*tcph));

    tcph->source = src_port;
    tcph->dest = dst_port;
    tcph->doff = 5;

    SET_FLAG(FIN, fin);
    SET_FLAG(SYN, syn);
    SET_FLAG(RST, rst);
    SET_FLAG(PSH, psh);
    SET_FLAG(ACK, ack);
    SET_FLAG(URG, urg);

    tcph->window = htons(win);

    tcph->seq = htonl(seqn);
    tcph->ack_seq = htonl(ackn);

    if (tcp_csum != EFVI_CSUM_ZERO)
    {
        uint16_t csum;

        csum = tcp_udp_ip_csum(src_addr, dst_addr, IPPROTO_TCP,
                               tcph, tcp_len);

        tcph->check = htons(csum);
        if (tcp_csum == EFVI_CSUM_WRONG)
            tcph->check = choose_wrong_csum(tcph->check);
    }

    *pos += tcp_len;
    return 0;
#undef SET_FLAG
}

/* See description in efvi_ts.h */
te_errno
efvi_fill_eth_ip_tcp_udp(uint8_t *buf, int len, int vlan_id,
                         rpc_socket_proto ip_proto,
                         const void *src_ll_addr, const void *dst_ll_addr,
                         const struct sockaddr *src_addr,
                         const struct sockaddr *dst_addr,
                         int *out_len)
{
    int pos = 0;
    int min_len;
    int real_len;
    te_bool ipv4 = (src_addr->sa_family == AF_INET);

    min_len = EFVI_ETH_HLEN + (vlan_id >= 0 ? 4 : 0) +
              (src_addr->sa_family == AF_INET ? EFVI_IP4_HLEN :
                                                EFVI_IP6_HLEN) +
              (ip_proto == RPC_IPPROTO_UDP ? EFVI_UDP_HLEN :
                                             EFVI_TCP_HLEN);
    min_len = MAX(min_len, EFVI_ETH_MIN_LEN);

    if (len < min_len)
    {
        ERROR("%s(): not enough space for the requested packet type",
              __FUNCTION__);
        return TE_RC(TE_TAPI, TE_ESMALLBUF);
    }

    real_len = rand_range(min_len, len);
    te_fill_buf(buf, real_len);

    CHECK_RETURN(efvi_fill_eth(buf, real_len, &pos, src_ll_addr,
                               dst_ll_addr, vlan_id,
                               (ipv4 ? ETH_P_IP : ETH_P_IPV6)));

    if (ipv4)
    {
        CHECK_RETURN(efvi_fill_ipv4(buf, real_len, &pos, src_addr, dst_addr,
                                    0xff, proto_rpc2h(ip_proto),
                                    EFVI_CSUM_OK));
    }
    else
    {
        CHECK_RETURN(efvi_fill_ipv6(buf, real_len, &pos, src_addr, dst_addr,
                                    proto_rpc2h(ip_proto), 0xff));
    }

    if (ip_proto == RPC_IPPROTO_UDP)
    {
        CHECK_RETURN(efvi_fill_udp(buf, real_len, &pos, src_addr, dst_addr,
                                   EFVI_CSUM_OK));
    }
    else
    {
        CHECK_RETURN(efvi_fill_tcp(buf, real_len, &pos, src_addr, dst_addr,
                                   rand_range(0, 0xffffffff),
                                   rand_range(0, 0xffffffff),
                                   rand_range(0, 0xffff),
                                   rand_range(0, 0xffff),
                                   EFVI_CSUM_OK));
    }

    *out_len = real_len;
    return 0;
}
