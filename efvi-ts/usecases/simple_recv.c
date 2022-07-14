/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2020 - 2022 Xilinx, Inc. All rights reserved. */
/*
 * EF_VI API Test Suite
 * Reliability EF_VI API in Normal Use
 */

/** @page usecases-simple_recv Receiving data with EF_VI
 *
 * @objective Check that data can be received with EF_VI API
 *
 * @type use case
 *
 * @param env             Testing environment:
 *                        - @ref arg_types_env_peer2peer
 *                        - @ref arg_types_env_peer2peer_ipv6
 * @param protocol        Protocol to use:
 *                        - @c IPPROTO_TCP
 *                        - @c IPPROTO_UDP
 * @param merge_events    If @c TRUE, check merged RX events mode.
 * @param receive_push    If @c TRUE, use @b ef_vi_receive_init() and
 *                        @b ef_vi_receive_push() instead of
 *                        @b ef_vi_receive_post().
 *
 * @par Scenario:
 *
 * @author Dmitry Izbitsky <Dmitry.Izbitsky@oktetlabs.ru>
 */

#define TE_TEST_NAME  "usecases/simple_recv"

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
 * Memory alignment for a memory region used to store received
 * data. The region should be page-aligned and on a 4K boundary.
 */
#define MEM_ALIGN (4 << 10)

/** Length of a memory region. Should be multiple of 2K. */
#define MEM_SIZE (1 << 20)

/** Buffer size used for a single received packet. */
#define BUF_SIZE (4 << 10)

/** Number of buffers to pass to ef_vi_receive_post(). */
#define BUFS_COUNT 32

/** Maximum size of a packet */
#define MAX_PKT_SIZE 1024

/** Maximum number of packets to send */
#define MAX_PKTS BUFS_COUNT

/**
 * Number of elements in events array passed to
 * ef_eventq_poll().
 */
#define MAX_EVTS (MAX_PKTS * 2)

/** Sent packet */
typedef struct sent_packet {
    uint8_t buf[MAX_PKT_SIZE];    /**< Packet headers and data */
    int len;                      /**< Length of the packet */
} sent_packet;

int
main(int argc, char *argv[])
{
    rcf_rpc_server *pco_iut = NULL;
    rcf_rpc_server *pco_tst = NULL;
    const struct if_nameindex *iut_if = NULL;
    const struct if_nameindex *tst_if = NULL;

    const struct sockaddr *iut_lladdr = NULL;
    const struct sockaddr *tst_lladdr = NULL;
    struct sockaddr_ll dst_lladdr;

    const struct sockaddr *iut_addr;
    const struct sockaddr *tst_addr;

    rpc_ef_driver_handle dh = -1;
    rpc_ef_pd_p pd = RPC_NULL;
    rpc_ef_vi_p vi = RPC_NULL;
    rpc_ef_memreg_p mr = RPC_NULL;
    rpc_ef_filter_spec_p fs = RPC_NULL;
    tarpc_ef_filter_cookie fs_cookie;
    te_bool filter_added = FALSE;
    unsigned int vi_flags;

    rpc_ptr mem = RPC_NULL;
    rpc_ef_addr dma_addr;
    int dma_ids[BUFS_COUNT] = { 0, };

    ef_event evts[MAX_EVTS];
    uint8_t rx_buf[MAX_PKT_SIZE];
    sent_packet pkts[MAX_PKTS];
    int pkts_num;
    int evts_num;

    unsigned int exp_evt_type;
    rpc_ef_request_id ids[EF_VI_RECEIVE_BATCH];
    int ids_num;
    unsigned int pkt_len;

    int tst_s = -1;

    int evt_idx;
    int id_idx;
    int pkt_idx;
    int buf_idx;

    rpc_socket_proto protocol;
    te_bool merge_events;
    te_bool receive_push;

    rpc_msghdr *msg;
    struct rpc_mmsghdr mmsgs[MAX_PKTS];
    rpc_iovec iovs[MAX_PKTS];

    te_string pkts_str = TE_STRING_INIT_STATIC(4096);

    /*
     * Test preambule.
     */
    TEST_START;
    TEST_GET_PCO(pco_iut);
    TEST_GET_PCO(pco_tst);
    TEST_GET_IF(iut_if);
    TEST_GET_IF(tst_if);
    TEST_GET_LINK_ADDR(iut_lladdr);
    TEST_GET_LINK_ADDR(tst_lladdr);
    TEST_GET_ADDR(pco_iut, iut_addr);
    TEST_GET_ADDR(pco_tst, tst_addr);
    EFVI_GET_IP_PROTO(protocol);
    TEST_GET_BOOL_PARAM(merge_events);
    TEST_GET_BOOL_PARAM(receive_push);

    TEST_STEP("Create raw @c AF_PACKET socket on Tester.");
    tst_s = rpc_socket(pco_tst, RPC_AF_PACKET, RPC_SOCK_RAW,
                       RPC_IPPROTO_RAW);

    TEST_STEP("Open ef_driver handle on IUT.");
    rpc_ef_driver_open(pco_iut, &dh);

    TEST_STEP("Allocate a protection domain on IUT.");
    rpc_ef_pd_alloc(pco_iut, &pd, dh, iut_if->if_index,
                    RPC_EF_PD_DEFAULT);

    vi_flags = RPC_EF_VI_FLAGS_DEFAULT;
    if (merge_events)
        vi_flags |= RPC_EF_VI_RX_EVENT_MERGE;

    TEST_STEP("Allocate a virtual interface from the protection domain "
              "on IUT.");
    TEST_SUBSTEP("If @p merge_events is @c TRUE, set flag "
                 "@c EF_VI_RX_EVENT_MERGE when allocating VI.");
    rpc_ef_vi_alloc_from_pd(pco_iut, &vi, dh, pd, dh, -1, -1, -1,
                            RPC_NULL, dh, vi_flags);

    TEST_STEP("Add a filter on the virtual interface on IUT for packets "
              "sent from @p tst_addr to @p iut_addr and with protocol "
              "matching @p protocol.");

    rpc_ef_filter_spec_alloc(pco_iut, &fs, RPC_EF_FILTER_FLAG_NONE);

    rpc_ef_filter_spec_set_ip(pco_iut, fs, protocol,
                              iut_addr, tst_addr);

    rpc_ef_vi_filter_add(pco_iut, vi, dh, fs, &fs_cookie);
    filter_added = TRUE;

    TEST_STEP("Allocate a memory region to be used with "
              "the virtual interface on IUT.");

    mem = rpc_memalign(pco_iut, MEM_ALIGN, MEM_SIZE);

    TEST_STEP("Call @b ef_memreg_alloc() to register the memory "
              "region for use with the virtual interface on IUT.");
    rpc_ef_memreg_alloc(pco_iut, &mr, dh, pd, dh, mem, MEM_SIZE);

    TEST_STEP("Initialize a few RX descriptors with "
              "@b ef_vi_receive_post() or @b ef_vi_receive_init() "
              "(choosing function according to @p receive_push).");
    TEST_SUBSTEP("For each descriptor use DMA address obtained with "
                 "@b ef_memreg_dma_addr() to specify a buffer in the "
                 "registered memory region, and pass an unique random "
                 "number as its DMA ID.");

    for (buf_idx = 0; buf_idx < BUFS_COUNT; buf_idx++)
    {
        while (TRUE)
        {
            dma_ids[buf_idx] = rand_range(0, INT_MAX);
            for (id_idx = 0; id_idx < buf_idx; id_idx++)
            {
                if (dma_ids[id_idx] == dma_ids[buf_idx])
                    break;
            }

            if (id_idx >= buf_idx)
                break;
        }

        rpc_ef_memreg_dma_addr(pco_iut, mr, buf_idx * BUF_SIZE, &dma_addr);

        if (receive_push)
            rpc_ef_vi_receive_init(pco_iut, vi, dma_addr, dma_ids[buf_idx]);
        else
            rpc_ef_vi_receive_post(pco_iut, vi, dma_addr, dma_ids[buf_idx]);
    }

    if (receive_push)
    {
        TEST_STEP("If @p receive_push is @c TRUE, call "
                  "@b ef_vi_receive_push() on the IUT virtual interface "
                  "to submit initialized descriptors to NIC (when "
                  "@p receive_push is @c FALSE, @b ef_vi_receive_post() "
                  "itself immediately submits initialized descriptor).");

        rpc_ef_vi_receive_push(pco_iut, vi);
    }

    TEST_STEP("Send a few packets from the Tester socket over @p tst_if "
              "interface.");
    TEST_SUBSTEP("Use Ethernet address of @p tst_if as source Ethernet "
                 "address and Ethernet address of @p iut_if as "
                 "destination Ethernet address.");
    TEST_SUBSTEP("Choose IPv4 or IPv6 according to family of @p tst_addr.");
    TEST_SUBSTEP("Choose TCP or UDP according to @p protocol.");
    TEST_SUBSTEP("Use @p tst_addr as source network address/port and "
                 "@p iut_addr as destination network address/port.");

    memset(&dst_lladdr, 0, sizeof(dst_lladdr));
    dst_lladdr.sll_family = AF_PACKET;
    dst_lladdr.sll_ifindex = tst_if->if_index;
    dst_lladdr.sll_protocol = htons(ETH_P_ALL);
    dst_lladdr.sll_hatype = ARPHRD_ETHER;
    dst_lladdr.sll_pkttype = PACKET_HOST;
    rpc_bind(pco_tst, tst_s, SA(&dst_lladdr));

    memset(&mmsgs, 0, sizeof(mmsgs));
    pkts_num = rand_range(1, MAX_PKTS);
    for (pkt_idx = 0; pkt_idx < pkts_num; pkt_idx++)
    {
        CHECK_RC(efvi_fill_eth_ip_tcp_udp(pkts[pkt_idx].buf, MAX_PKT_SIZE,
                                          -1, protocol,
                                          tst_lladdr->sa_data,
                                          iut_lladdr->sa_data,
                                          tst_addr, iut_addr,
                                          &pkts[pkt_idx].len));

        iovs[pkt_idx].iov_base = pkts[pkt_idx].buf;
        iovs[pkt_idx].iov_len = iovs[pkt_idx].iov_rlen = pkts[pkt_idx].len;
        msg = &mmsgs[pkt_idx].msg_hdr;
        msg->msg_iov = &iovs[pkt_idx];
        msg->msg_iovlen = msg->msg_riovlen = 1;

        te_string_append(&pkts_str, "Sent packet %d of %d bytes\n",
                         pkt_idx, pkts[pkt_idx].len);
    }

    /*
     * Send all packets with a single sendmmsg() call to increase
     * probability that some RX events are merged.
     */
    pco_tst->silent = TRUE;
    RPC_AWAIT_ERROR(pco_tst);
    rc = rpc_sendmmsg_alt(pco_tst, tst_s, mmsgs, pkts_num, 0);
    if (rc < 0)
    {
        TEST_VERDICT("sendmmsg() on Tester failed returning %r",
                     RPC_ERRNO(pco_tst));
    }

    RING("Sent packets from Tester via the RAW socket:\n%s", pkts_str.ptr);

    TAPI_WAIT_NETWORK;

    TEST_STEP("On IUT call @b ef_eventq_poll() on the virtual interface. "
              "Check that it returns events.");

    evts_num = rpc_ef_eventq_poll(pco_iut, vi, evts, MAX_EVTS);
    if (evts_num == 0)
        TEST_VERDICT("No events after sending data from Tester");
    else if (!merge_events && evts_num != pkts_num)
        TEST_VERDICT("Unexpected number of events was received");

    TEST_STEP("Check every received event.");

    if (merge_events)
    {
        TEST_STEP("If @p merge_events is @c TRUE:");
        TEST_SUBSTEP("Check that event's type is "
                     "@c EF_EVENT_TYPE_RX_MULTI.");
        TEST_SUBSTEP("Obtain IDs of associated packet buffers with "
                     "@b ef_vi_receive_unbundle(); for every ID check that "
                     "it matches one of DMA IDs previously passed to "
                     "@b ef_vi_receive_post().");
        TEST_SUBSTEP("For every packet buffer get received data length "
                     "with @b ef_vi_receive_get_bytes(), then check that "
                     "length and data matches corresponding sent "
                     "packet.");
    }
    else
    {
        TEST_STEP("If @p merge_events is @c FALSE:");
        TEST_SUBSTEP("Check that event's type is @c EF_EVENT_TYPE_RX.");
        TEST_SUBSTEP("Check that @b rx.len field of the event matches "
                     "length of the corresponding sent packet.");
        TEST_SUBSTEP("Check that @b rx.rq_id field is set to one of the "
                     "DMA IDs previously passed to "
                     "@b ef_vi_receive_post(), and that the buffer "
                     "corresponding to that DMA ID holds the same data "
                     "as the corresponding sent packet.");
    }

    if (merge_events)
        exp_evt_type = EF_EVENT_TYPE_RX_MULTI;
    else
        exp_evt_type = EF_EVENT_TYPE_RX;

    pkt_idx = 0;
    for (evt_idx = 0; evt_idx < evts_num; evt_idx++)
    {
        if (evts[evt_idx].generic.type != exp_evt_type)
        {
            TEST_VERDICT("Event of unexpected type %s was received",
                         ef_event_type_h2str(evts[evt_idx].generic.type));
        }

        if (merge_events)
        {
            ids_num = rpc_ef_vi_receive_unbundle(pco_iut, vi,
                                                 &evts[evt_idx],
                                                 ids);
            if (ids_num == 0)
            {
                ERROR("RX event %d has no associated DMA IDs", evt_idx);
                TEST_VERDICT("RX_MULTI event has no associated DMA IDs");
            }
        }
        else
        {
            ids_num = 1;
            ids[0] = evts[evt_idx].rx.rq_id;
            pkt_len = evts[evt_idx].rx.len;
        }

        for (id_idx = 0; id_idx < ids_num; id_idx++)
        {
            if (pkt_idx >= pkts_num)
            {
                TEST_VERDICT("Events contain more buffer IDs than "
                             "there were sent packets");
            }

            for (buf_idx = 0; buf_idx < BUFS_COUNT; buf_idx++)
            {
                if (dma_ids[buf_idx] == (int)(ids[id_idx]))
                {
                    dma_ids[buf_idx] = -1;
                    break;
                }
            }
            if (buf_idx >= BUFS_COUNT)
            {
                ERROR("RX event %d contains unexpected buffer ID %d",
                      evt_idx, ids[id_idx]);
                TEST_VERDICT("RX event contains incorrect buffer ID");
            }

            if (merge_events)
            {
                rpc_ef_vi_receive_get_bytes(pco_iut, vi, mem,
                                            BUF_SIZE * buf_idx,
                                            &pkt_len);
            }

            if (pkt_len > MAX_PKT_SIZE)
            {
                TEST_VERDICT("Reported length of received packet is "
                             "too big");
            }

            rpc_efvi_get_pkt_data(
                              pco_iut, vi, mem,
                              BUF_SIZE * buf_idx, pkt_len,
                              rx_buf, sizeof(rx_buf));

            if ((int)(pkt_len) != pkts[pkt_idx].len)
            {
                ERROR("Packet %d: sent data has length %d, received "
                      "data has length %u", pkt_idx, pkts[pkt_idx].len,
                      pkt_len);

                TEST_VERDICT("Received data length does not match sent "
                             "data length");
            }
            else if (memcmp(rx_buf, pkts[pkt_idx].buf,
                            pkts[pkt_idx].len) != 0)
            {
                ERROR("Packet %d does not match. Sent packet is %Tm"
                      "Received packet is %Tm", pkt_idx, pkts[pkt_idx].buf,
                      pkts[pkt_idx].len, rx_buf, pkt_len);

                TEST_VERDICT("Received data does not match sent data");
            }

            pkt_idx++;
        }
    }

    TEST_STEP("Check that all the expected packets were received "
              "after processing all the events.");
    if (pkt_idx < pkts_num)
        TEST_VERDICT("Not all the expected packets were received");

    TEST_SUCCESS;

cleanup:

    CLEANUP_RPC_CLOSE(pco_tst, tst_s);

    if (mr != RPC_NULL)
        rpc_ef_memreg_free(pco_iut, mr, dh);

    if (mem != RPC_NULL)
        rpc_free(pco_iut, mem);

    if (filter_added)
        rpc_ef_vi_filter_del(pco_iut, vi, dh, &fs_cookie);

    if (fs != RPC_NULL)
        rpc_ef_filter_spec_free(pco_iut, fs);

    if (vi != RPC_NULL)
        rpc_ef_vi_free(pco_iut, vi, dh);

    if (pd != RPC_NULL)
        rpc_ef_pd_free(pco_iut, pd, dh);

    if (dh >= 0)
        rpc_ef_driver_close(pco_iut, dh);

    TEST_END;
}
