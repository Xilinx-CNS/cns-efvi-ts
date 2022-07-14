/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2020 - 2022 Xilinx, Inc. All rights reserved. */
/*
 * EF_VI API Test Suite
 * Reliability of EF_VI API in Normal Use
 */

/** @page usecases-simple_send Sending data with EF_VI
 *
 * @objective Check that data can be sent with EF_VI API
 *
 * @type use case
 *
 * @param env             Testing environment:
 *                        - @ref arg_types_env_peer2peer
 *                        - @ref arg_types_env_peer2peer_ipv6
 * @param protocol        Protocol to use:
 *                        - @c IPPROTO_TCP
 *                        - @c IPPROTO_UDP
 * @param transmit_push   If @c TRUE, use @b ef_vi_transmit_init() and
 *                        @b ef_vi_transmit_push() instead of
 *                        @b ef_vi_transmit().
 * @param transmitv       If @c TRUE, use @b ef_vi_transmitv() or
 *                        @b ef_vi_transmitv_init() instead of
 *                        @b ef_vi_transmit() / @b ef_vi_transmit_init().
 *
 * @par Scenario:
 *
 * @author Dmitry Izbitsky <Dmitry.Izbitsky@oktetlabs.ru>
 */

#define TE_TEST_NAME  "usecases/simple_send"

#include "efvi_test.h"

#ifdef HAVE_LINUX_IF_ETHER_H
#include <linux/if_ether.h>
#endif
#ifdef HAVE_NET_IF_ARP_H
#include <net/if_arp.h>
#endif
#ifdef HAVE_NETPACKET_PACKET_H
#include <netpacket/packet.h>
#endif

/**
 * Memory alignment for a memory region used to store sent
 * data. The region should be page-aligned and on a 4K boundary.
 */
#define MEM_ALIGN (4 << 10)

/** Length of a memory region. Should be multiple of 2K. */
#define MEM_SIZE (1 << 20)

/** Maximum size of a packet */
#define MAX_PKT_SIZE 1024

/** Maximum number of packets to send */
#define MAX_PKTS 5

/**
 * Number of elements in events array passed to
 * ef_eventq_poll().
 */
#define MAX_EVTS (MAX_PKTS * 2)

/** Maximum number of iovs per packet */
#define MAX_IOVS 5

/** Sent packet */
typedef struct sent_packet {
    uint8_t buf[MAX_PKT_SIZE];    /**< Packet headers and data */
    int len;                      /**< Length of the packet */
    rpc_ef_request_id id;         /**< ID of the buffer associated with
                                       this packet */
} sent_packet;

/**
 * Process a packet passed to NIC in a single buffer.
 *
 * @param rpcs            RPC server handle.
 * @param mr              RPC pointer to registered memory.
 * @param vi              RPC pointer to virtual interface.
 * @param offset          Offset within registered memory.
 * @param pkt             Packet to send.
 * @param transmit_push   If TRUE, use ef_vi_transmit_init() instead of
 *                        ef_vi_transmit().
 */
static void
process_single_buf(rcf_rpc_server *rpcs, rpc_ef_memreg_p mr, rpc_ef_vi_p vi,
                   size_t offset, sent_packet *pkt, te_bool transmit_push)
{
    rpc_ef_addr dma_addr;

    rpc_ef_memreg_dma_addr(rpcs, mr, offset, &dma_addr);
    if (transmit_push)
        rpc_ef_vi_transmit_init(rpcs, vi, dma_addr, pkt->len, pkt->id);
    else
        rpc_ef_vi_transmit(rpcs, vi, dma_addr, pkt->len, pkt->id);
}

/**
 * Process a packet passed to NIC in a few buffers.
 *
 * @param rpcs            RPC server handle.
 * @param mr              RPC pointer to registered memory.
 * @param vi              RPC pointer to virtual interface.
 * @param offset          Offset within registered memory.
 * @param pkt             Packet to send.
 * @param transmit_push   If TRUE, use ef_vi_transmitv_init() instead of
 *                        ef_vi_transmitv().
 */
static void
process_iovs(rcf_rpc_server *rpcs, rpc_ef_memreg_p mr, rpc_ef_vi_p vi,
             size_t offset, sent_packet *pkt, te_bool transmit_push)
{
    tarpc_ef_iovec iovs[MAX_IOVS];
    rpc_ef_addr dma_addr;

    int i;
    int buf_len;
    int cur_off;

    cur_off = 0;
    rpc_ef_memreg_dma_addr(rpcs, mr, offset, &dma_addr);

    for (i = 0; i < MAX_IOVS && cur_off < pkt->len; i++)
    {
        if (i == MAX_IOVS - 1)
        {
            buf_len = pkt->len - cur_off;
        }
        else
        {
            buf_len = rand_range(1, MAX(1, pkt->len / 2));
            buf_len = MIN(buf_len, pkt->len - cur_off);
        }

        iovs[i].iov_base = dma_addr + cur_off;
        iovs[i].iov_len = buf_len;
        cur_off += buf_len;
    }

    if (transmit_push)
        rpc_ef_vi_transmitv_init(rpcs, vi, iovs, i, pkt->id);
    else
        rpc_ef_vi_transmitv(rpcs, vi, iovs, i, pkt->id);
}

int
main(int argc, char *argv[])
{
    rcf_rpc_server *pco_iut = NULL;
    rcf_rpc_server *pco_tst = NULL;
    const struct if_nameindex *iut_if = NULL;
    const struct if_nameindex *tst_if = NULL;

    const struct sockaddr *iut_lladdr = NULL;
    const struct sockaddr *alien_link_addr = NULL;
    struct sockaddr_ll dst_lladdr;

    const struct sockaddr *iut_addr;
    const struct sockaddr *tst_addr;

    rpc_ef_driver_handle dh = -1;
    rpc_ef_pd_p pd = RPC_NULL;
    rpc_ef_vi_p vi = RPC_NULL;
    rpc_ef_memreg_p mr = RPC_NULL;

    rpc_ptr mem = RPC_NULL;
    rpc_ef_request_id ids[EF_VI_TRANSMIT_BATCH];

    ef_event evts[MAX_EVTS];
    int evts_num;
    uint8_t rx_buf[MAX_PKT_SIZE * 2];
    sent_packet pkts[MAX_PKTS];
    int pkts_num;
    int tst_s = -1;

    int i;
    int j;
    int k;

    rpc_socket_proto protocol;
    te_bool transmit_push;
    te_bool transmitv;

    /*
     * Test preambule.
     */
    TEST_START;
    TEST_GET_PCO(pco_iut);
    TEST_GET_PCO(pco_tst);
    TEST_GET_IF(iut_if);
    TEST_GET_IF(tst_if);
    TEST_GET_LINK_ADDR(iut_lladdr);
    TEST_GET_LINK_ADDR(alien_link_addr);
    TEST_GET_ADDR(pco_iut, iut_addr);
    TEST_GET_ADDR(pco_tst, tst_addr);
    EFVI_GET_IP_PROTO(protocol);
    TEST_GET_BOOL_PARAM(transmit_push);
    TEST_GET_BOOL_PARAM(transmitv);

    TEST_STEP("Create raw @c AF_PACKET socket on Tester.");
    tst_s = rpc_socket(pco_tst, RPC_AF_PACKET, RPC_SOCK_RAW,
                       RPC_IPPROTO_RAW);

    memset(&dst_lladdr, 0, sizeof(dst_lladdr));
    dst_lladdr.sll_family = AF_PACKET;
    dst_lladdr.sll_ifindex = tst_if->if_index;

    /*
     * These two are filled just to make converting functions
     * happy.
     */
    dst_lladdr.sll_hatype = ARPHRD_ETHER;
    dst_lladdr.sll_pkttype = PACKET_HOST;

    if (iut_addr->sa_family == AF_INET)
        dst_lladdr.sll_protocol = htons(ETH_P_IP);
    else
        dst_lladdr.sll_protocol = htons(ETH_P_IPV6);

    TEST_STEP("Bind the Tester socket to @p tst_if interface to "
              "receive IP protocol matching address family of "
              "@p iut_addr.");
    rpc_bind(pco_tst, tst_s, SA(&dst_lladdr));

    TEST_STEP("Enable promiscuous mode on @p tst_if interface, so that "
              "Tester socket can capture packets sent to an alien "
              "Ethernet address from IUT.");
    CHECK_RC(tapi_cfg_base_if_set_promisc(pco_tst->ta, tst_if->if_name,
                                          TRUE));
    CFG_WAIT_CHANGES;

    TEST_STEP("Open ef_driver handle on IUT.");
    rpc_ef_driver_open(pco_iut, &dh);

    TEST_STEP("Allocate a protection domain on IUT.");
    rpc_ef_pd_alloc(pco_iut, &pd, dh, iut_if->if_index,
                    RPC_EF_PD_DEFAULT);

    TEST_STEP("Allocate a virtual interface from the protection domain "
              "on IUT.");
    rpc_ef_vi_alloc_from_pd(pco_iut, &vi, dh, pd, dh, -1, -1, -1,
                            RPC_NULL, dh, RPC_EF_VI_FLAGS_DEFAULT);

    TEST_STEP("Allocate a memory region to be used with "
              "the virtual interface.");

    mem = rpc_memalign(pco_iut, MEM_ALIGN, MEM_SIZE);

    TEST_STEP("Call @b ef_memreg_alloc() to register the memory "
              "region for use with the virtual interface.");
    rpc_ef_memreg_alloc(pco_iut, &mr, dh, pd, dh, mem, MEM_SIZE);

    TEST_STEP("Send a few packets via the virtual interface from IUT.");
    TEST_SUBSTEP("Construct every packet choosing its protocols "
                 "according to address family of @p iut_addr and "
                 "@p protocol. Use @p alien_link_addr as destination "
                 "Ethernet address to make it easier to ignore "
                 "packets unrelated to this test.");
    TEST_SUBSTEP("Save packet's contents in a buffer within the "
                 "memory region registered before.");
    TEST_SUBSTEP("Use @b ef_vi_transmit* function chosen according to "
                 "@p transmit_push and @p transmitv to initialize TX "
                 "descriptor for a packet (and submit it to NIC if "
                 "@p transmit_push is @c TRUE). Use "
                 "@b ef_memreg_dma_addr() for getting packet buffer(s) "
                 "address(es). Use arbitrary integer number as DMA "
                 "ID associated with TX descriptor.");

    pkts_num = rand_range(1, MAX_PKTS);
    for (i = 0; i < pkts_num; i++)
    {
        CHECK_RC(efvi_fill_eth_ip_tcp_udp(pkts[i].buf, MAX_PKT_SIZE,
                                          -1, protocol,
                                          iut_lladdr->sa_data,
                                          alien_link_addr->sa_data,
                                          iut_addr, tst_addr,
                                          &pkts[i].len));

        rpc_set_buf_gen(pco_iut, pkts[i].buf, pkts[i].len, mem,
                        i * MAX_PKT_SIZE);

        pkts[i].id = (i << 16) + rand_range(1, 0xffff);

        if (transmitv)
        {
            process_iovs(pco_iut, mr, vi, i * MAX_PKT_SIZE, &pkts[i],
                         transmit_push);
        }
        else
        {
            process_single_buf(pco_iut, mr, vi, i * MAX_PKT_SIZE, &pkts[i],
                               transmit_push);
        }
    }

    if (transmit_push)
    {
        TEST_STEP("If @p transmit_push is @c TRUE, call "
                  "@b ef_vi_transmit_push() on the virtual interface.");
        rpc_ef_vi_transmit_push(pco_iut, vi);
    }

    TAPI_WAIT_NETWORK;

    TEST_STEP("After waiting for a while, call @b ef_eventq_poll() on "
              "IUT and check that it returns some events.");

    evts_num = rpc_ef_eventq_poll(pco_iut, vi, evts, MAX_EVTS);
    if (evts_num == 0)
        TEST_VERDICT("No events after sending data from IUT");

    TEST_STEP("Check that all the events are of @c EF_EVENT_TYPE_TX "
              "type, and they contain IDs of all the sent packets "
              "in order of their sending, as reported by "
              "@b ef_vi_transmit_unbundle() called on every event.");

    for (i = 0, k = 0; i < evts_num; i++)
    {
        if (evts[i].generic.type != EF_EVENT_TYPE_TX)
        {
            TEST_VERDICT("Event of unexpected type %s was received",
                         ef_event_type_h2str(evts[i].generic.type));
        }

        rc = rpc_ef_vi_transmit_unbundle(pco_iut, vi, &evts[i], ids);
        for (j = 0; j < rc; j++)
        {
            if (k >= pkts_num)
            {
                TEST_VERDICT("Too many buffer IDs were reported in "
                             "TX events");
            }

            if (ids[j] != pkts[k].id)
            {
                ERROR("Unexpected buffer ID: %d instead of %d", ids[j],
                      pkts[k].id);
                TEST_VERDICT("ef_vi_transmit_unbundle() returned "
                             "unexpected buffer ID");
            }
            k++;
        }
    }

    if (k < pkts_num)
    {
        TEST_VERDICT("Not all the expected buffer IDs were reported in TX "
                     "events");
    }

    TEST_STEP("Capture and check all the sent packets on Tester.");

    i = 0;
    k = 0;
    while (TRUE)
    {
        RPC_AWAIT_ERROR(pco_tst);
        rc = rpc_recv(pco_tst, tst_s, rx_buf, sizeof(rx_buf),
                      RPC_MSG_DONTWAIT);
        if (rc < 0)
        {
            if (RPC_ERRNO(pco_tst) != RPC_EAGAIN)
            {
                TEST_VERDICT("recv() on Tester failed with unexpected "
                             "errno %r", RPC_ERRNO(pco_tst));
            }
            break;
        }

        if (rc < ETH_ALEN ||
            memcmp(rx_buf, alien_link_addr->sa_data, ETH_ALEN) != 0)
        {
            WARN("Encountered a packet to unexpected Ethernet address %Tm"
                 "skipping it", alien_link_addr->sa_data, ETH_ALEN);

            k++;
            if (k > MAX_PKTS * 1000)
            {
                WARN("Too many unrelated packets were captured, probably "
                     "there is some unexpected network traffic on "
                     "the interface");
                break;
            }

            continue;
        }

        if (i >= pkts_num)
            TEST_VERDICT("Too many packets were captured on Tester");

        if (rc != pkts[i].len)
        {
            ERROR("Packet %d: length mismatch, %d instead of %d", i,
                  rc, pkts[i].len);
            TEST_VERDICT("Packet length did not match");
        }
        else if (memcmp(pkts[i].buf, rx_buf, rc) != 0)
        {
            ERROR("Packet %d: data mismatch", i);
            TEST_VERDICT("Packet data did not match");
        }
        i++;
    }

    if (i < pkts_num)
    {
        TEST_VERDICT("Not all the expected packets were captured "
                     "on Tester");
    }

    TEST_SUCCESS;

cleanup:

    CLEANUP_RPC_CLOSE(pco_tst, tst_s);

    if (mr != RPC_NULL)
        rpc_ef_memreg_free(pco_iut, mr, dh);

    if (mem != RPC_NULL)
        rpc_free(pco_iut, mem);

    if (vi != RPC_NULL)
        rpc_ef_vi_free(pco_iut, vi, dh);

    if (pd != RPC_NULL)
        rpc_ef_pd_free(pco_iut, pd, dh);

    if (dh >= 0)
        rpc_ef_driver_close(pco_iut, dh);

    TEST_END;
}
