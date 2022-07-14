/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2020 - 2022 Xilinx, Inc. All rights reserved. */
/** @file
 * @brief Test API - EF_VI API RPC functions definition
 *
 * Definition of TAPI for AMD EF_VI API remote calls.
 *
 * @author Damir Mansurov <Damir.Mansurov@oktetlabs.ru>
 */

#ifndef __EFVI_RPC_H__
#define __EFVI_RPC_H__

#include "rcf_rpc.h"
#include "efvi_talib_common.h"

typedef tarpc_int rpc_ef_driver_handle;
typedef uint64_t rpc_ef_addr;
typedef tarpc_int rpc_ef_request_id;

/**
 * Obtain a driver handle
 *
 * @param rpcs      RPC server handle.
 * @param handle    Pointer to an rpc_ef_driver_handle, that is updated on
 *                  return with the new driver handle.
 *
 * @return @c 0 on success or @c -1 in the case of failure
 */
extern int rpc_ef_driver_open(rcf_rpc_server *rpcs, rpc_ef_driver_handle *handle);

/**
 * Close a driver handle
 *
 * @param rpcs      RPC server handle.
 * @param handle    Handle rpc_ef_driver_handle to close.
 *
 * @return @c 0 on success or @c -1 in the case of failure
 */
extern int rpc_ef_driver_close(rcf_rpc_server *rpcs, rpc_ef_driver_handle handle);

/**
 * Allocate a protection domain.
 *
 * @param rpcs      RPC server handle.
 * @param pd        Where to save RPC pointer to the allocated PD.
 * @param pd_dh     Driver handle.
 * @param ifindex   Index of the interface to use.
 * @param flags     See @ref rpc_ef_pd_flags.
 *
 * Return @c 0 on success, @c -1 on failure.
 */
extern int rpc_ef_pd_alloc(rcf_rpc_server *rpcs, rpc_ef_pd_p *pd,
                           rpc_ef_driver_handle pd_dh, int ifindex,
                           unsigned int flags);

/**
 * Free a protection domain.
 *
 * @param rpcs      RPC server handle.
 * @param pd        RPC pointer to the previously allocated PD.
 * @param pd_dh     Driver handle.
 *
 * Return @c 0 on success, @c -1 on failure.
 */
extern int rpc_ef_pd_free(rcf_rpc_server *rpcs, rpc_ef_pd_p pd,
                          rpc_ef_driver_handle pd_dh);

/**
 * Allocate a virtual interface from a protection domain.
 *
 * @param rpcs          RPC server handle.
 * @param vi            Where to save RPC pointer for the allocated VI.
 * @param vi_dh         The driver handle to associate with the allocated
 *                      VI.
 * @param pd            RPC pointer to the previously allocated PD.
 * @param pd_dh         The driver handle to associate with the PD.
 * @param evq_capacity  The capacity of the event queue, or @c 0 (no
 *                      event queue), or @c -1 (default size).
 * @param rxq_capacity  The number of slots in the RX descriptor ring,
 *                      or @c 0 (no RX descriptor ring), or
 *                      @c -1 (default size).
 * @param txq_capacity  The number of slots in the TX descriptor ring,
 *                      or @c 0 (no TX descriptor ring), or
 *                      @c -1 (default size).
 * @param evq_opt       Event queue to use if @p evq_capacity is @c 0.
 * @param evq_dh        The driver handle of @p evq_opt.
 * @param flags         Flags to select hardware attributes of the VI
 *                      (see @ref rpc_ef_vi_flags).
 *
 * Return @c 0 on success, @c -1 on failure.
 */
extern int rpc_ef_vi_alloc_from_pd(rcf_rpc_server *rpcs, rpc_ef_vi_p *vi,
                                   rpc_ef_driver_handle vi_dh,
                                   rpc_ef_pd_p pd,
                                   rpc_ef_driver_handle pd_dh,
                                   int evq_capacity, int rxq_capacity,
                                   int txq_capacity,
                                   rpc_ef_vi_p evq_opt,
                                   rpc_ef_driver_handle evq_dh,
                                   unsigned int flags);

/**
 * Free a virtual interface.
 *
 * @param rpcs          RPC server handle.
 * @param vi            RPC pointer for the previously allocated VI.
 * @param nic_dh        The driver handle for the NIC hosting the interface.
 *
 * Return @c 0 on success, @c -1 on failure.
 */
extern int rpc_ef_vi_free(rcf_rpc_server *rpcs, rpc_ef_vi_p vi,
                          rpc_ef_driver_handle nic_dh);

/**
 * Allocate a filter specification, initialize it with
 * @b ef_filter_spec_init().
 *
 * @param rpcs          RPC server handle.
 * @param fs            Where to save RPC pointer to the allocated
 *                      specification.
 * @param flags         See @ref rpc_ef_filter_flags.
 *
 * @return @c 0 on success, @c -1 on failure.
 */
extern int rpc_ef_filter_spec_alloc(rcf_rpc_server *rpcs,
                                    rpc_ef_filter_spec_p *fs,
                                    unsigned int flags);

/**
 * Free a filter specification.
 *
 * @param rpcs          RPC server handle.
 * @param fs            RPC pointer to the filter specification.
 *
 * @return @c 0 on success, @c -1 on failure.
 */
extern int rpc_ef_filter_spec_free(rcf_rpc_server *rpcs,
                                   rpc_ef_filter_spec_p fs);

/**
 * Set an IPv4 local filter on a filter specification.
 *
 * @param rpcs            RPC server handle.
 * @param fs              RPC pointer to the filter specification.
 * @param protocol        @c RPC_IPPROTO_TCP or @c RPC_IPPROTO_UDP.
 * @param addr            Local address/port.
 *
 * @return @c 0 on success, @c -1 on failure.
 */
extern int rpc_ef_filter_spec_set_ip4_local(rcf_rpc_server *rpcs,
                                            rpc_ef_filter_spec_p fs,
                                            rpc_socket_proto protocol,
                                            const struct sockaddr *addr);

/**
 * Set an IPv4 full filter on a filter specification.
 *
 * @param rpcs            RPC server handle.
 * @param fs              RPC pointer to the filter specification.
 * @param protocol        @c RPC_IPPROTO_TCP or @c RPC_IPPROTO_UDP.
 * @param laddr           Local address/port.
 * @param raddr           Remote address/port.
 *
 * @return @c 0 on success, @c -1 on failure.
 */
extern int rpc_ef_filter_spec_set_ip4_full(rcf_rpc_server *rpcs,
                                           rpc_ef_filter_spec_p fs,
                                           rpc_socket_proto protocol,
                                           const struct sockaddr *laddr,
                                           const struct sockaddr *raddr);

/**
 * Set an IPv6 local filter on a filter specification.
 *
 * @param rpcs            RPC server handle.
 * @param fs              RPC pointer to the filter specification.
 * @param protocol        @c RPC_IPPROTO_TCP or @c RPC_IPPROTO_UDP.
 * @param addr            Local address/port.
 *
 * @return @c 0 on success, @c -1 on failure.
 */
extern int rpc_ef_filter_spec_set_ip6_local(rcf_rpc_server *rpcs,
                                            rpc_ef_filter_spec_p fs,
                                            rpc_socket_proto protocol,
                                            const struct sockaddr *addr);

/**
 * Set an IPv6 full filter on a filter specification.
 *
 * @param rpcs            RPC server handle.
 * @param fs              RPC pointer to the filter specification.
 * @param protocol        @c RPC_IPPROTO_TCP or @c RPC_IPPROTO_UDP.
 * @param laddr           Local address/port.
 * @param raddr           Remote address/port.
 *
 * @return @c 0 on success, @c -1 on failure.
 */
extern int rpc_ef_filter_spec_set_ip6_full(rcf_rpc_server *rpcs,
                                           rpc_ef_filter_spec_p fs,
                                           rpc_socket_proto protocol,
                                           const struct sockaddr *laddr,
                                           const struct sockaddr *raddr);

/**
 * Generic function to set local or full IPv4 or IPv6 filter on a filter
 * specification.
 *
 * @param rpcs            RPC server handle.
 * @param fs              RPC pointer to the filter specification.
 * @param protocol        @c RPC_IPPROTO_TCP or @c RPC_IPPROTO_UDP.
 * @param laddr           Local address/port.
 * @param raddr           Remote address/port (if @c NULL, local filter
 *                        will be set).
 *
 * @return @c 0 on success, @c -1 on failure.
 */
extern int rpc_ef_filter_spec_set_ip(rcf_rpc_server *rpcs,
                                     rpc_ef_filter_spec_p fs,
                                     rpc_socket_proto protocol,
                                     const struct sockaddr *laddr,
                                     const struct sockaddr *raddr);

/**
 * Add a filter to a virtual interface.
 *
 * @param rpcs        RPC server handle.
 * @param vi          Virtual interface on which to add the filter.
 * @param vi_dh       Driver handle for the virtual interface.
 * @param fs          RPC pointer to the filter specification.
 * @param cookie      If not @c NULL, a filter cookie will be saved
 *                    here which can be used to remove a filter.
 *
 * @return @c 0 on success, @c -1 on failure.
 */
extern int rpc_ef_vi_filter_add(rcf_rpc_server *rpcs,
                                rpc_ef_vi_p vi,
                                rpc_ef_driver_handle vi_dh,
                                rpc_ef_filter_spec_p fs,
                                tarpc_ef_filter_cookie *cookie);

/**
 * Delete a filter from a virtual interface.
 *
 * @param rpcs        RPC server handle.
 * @param vi          Virtual interface.
 * @param vi_dh       Driver handle for the virtual interface.
 * @param cookie      Cookie obtained from @b rpc_ef_vi_filter_add().
 *
 * @return @c 0 on success, @c -1 on failure.
 */
extern int rpc_ef_vi_filter_del(rcf_rpc_server *rpcs,
                                rpc_ef_vi_p vi,
                                rpc_ef_driver_handle vi_dh,
                                tarpc_ef_filter_cookie *cookie);

/**
 * Register memory to use with the virtual interface.
 *
 * @param rpcs            RPC server handle.
 * @param mr              Where to save RPC pointer to ef_memreg object.
 * @param mr_dh           Driver handle for the ef_memreg object.
 * @param pd              RPC pointer to the protection domain in which
 *                        to register memory.
 * @param pd_dh           Driver handle for the protection domain.
 * @param p_mem           RPC pointer to memory to be registered
 *                        (must be page-aligned and on a 4K boundary).
 * @param len_bytes       Length of memory region to be registered
 *                        (should be a multiple of the packet buffer
 *                        size, currently 2048 bytes).
 *
 * @return @c 0 on success, @c -1 on failure.
 */
extern int rpc_ef_memreg_alloc(rcf_rpc_server *rpcs, rpc_ef_memreg_p *mr,
                               rpc_ef_driver_handle mr_dh, rpc_ef_pd_p pd,
                               rpc_ef_driver_handle pd_dh, rpc_ptr p_mem,
                               size_t len_bytes);

/**
 * Unregister a memory region.
 *
 * @param rpcs        RPC server handle.
 * @param mr          RPC pointer to ef_memreg object to be released.
 * @param mr_dh       Driver handle for @p mr.
 *
 * @return @c 0 on success, @c -1 on failure.
 */
extern int rpc_ef_memreg_free(rcf_rpc_server *rpcs, rpc_ef_memreg_p mr,
                              rpc_ef_driver_handle mr_dh);

/**
 * Return the DMA address for the given offset within a registered memory
 * region.
 *
 * @note DMA addresses are only contiguous within each 4K block of a memory
 *       region.
 *
 * @param rpcs          RPC server handle.
 * @param mr            RPC pointer to ef_memreg object.
 * @param offset        Offset within the ef_memreg object.
 * @param addr          Where to save DMA address.
 *
 * @return @c 0 on success, @c -1 on failure.
 */
extern int rpc_ef_memreg_dma_addr(rcf_rpc_server *rpcs,
                                  rpc_ef_memreg_p mr,
                                  size_t offset,
                                  rpc_ef_addr *addr);

/**
 * Initialize an RX descriptor on the RX descriptor ring.
 *
 * @note After using this function a few times, @b rpc_ef_vi_receive_push()
 *       should be called to submit descriptors to NIC.
 *
 * @param rpcs        RPC server handle.
 * @param vi          Virtual interface.
 * @param addr        DMA address of the associated packet buffer
 *                    obtained with @b rpc_ef_memreg_dma_addr().
 * @param dma_id      DMA ID to associate with the descriptor
 *                    (arbitrary number which can be used for subsequent
 *                     tracking of buffers).
 *
 * @return @c 0 on success, @c -1 on failure.
 */
extern int rpc_ef_vi_receive_init(rcf_rpc_server *rpcs, rpc_ef_vi_p vi,
                                  rpc_ef_addr addr,
                                  rpc_ef_request_id dma_id);

/**
 * Submit newly initialized RX descriptors to the NIC so that it will
 * be able to receive data into associated packet buffers.
 *
 * @note At least one RX descriptor should be initialized before calling
 *       this function.
 *
 * @param rpcs        RPC server handle.
 * @param vi          Virtual interface.
 *
 * @return @c 0 on success, @c -1 on failure.
 */
extern int rpc_ef_vi_receive_push(rcf_rpc_server *rpcs, rpc_ef_vi_p vi);

/**
 * Initialize an RX descriptor on the RX descriptor ring, and
 * submit it to the NIC. NIC can then receive a packet into
 * the associated packet buffer.
 *
 * @param rpcs        RPC server handle.
 * @param vi          Virtual interface.
 * @param addr        DMA address of the associated packet buffer
 *                    obtained with @b rpc_ef_memreg_dma_addr().
 * @param dma_id      DMA ID to associate with the descriptor
 *                    (arbitrary number which can be used for subsequent
 *                     tracking of buffers).
 *
 * @return @c 0 on success, @c -1 on failure.
 */
extern int rpc_ef_vi_receive_post(rcf_rpc_server *rpcs, rpc_ef_vi_p vi,
                                  rpc_ef_addr addr,
                                  rpc_ef_request_id dma_id);

/**
 * Transmit a packet from a single buffer, initializing a TX descriptor
 * on the TX descriptor ring and submitting it to the NIC.
 *
 * @param rpcs        RPC server handle.
 * @param vi          Virtual interface.
 * @param base        DMA address of the associated packet buffer
 *                    obtained with @b rpc_ef_memreg_dma_addr().
 * @param len         Length of the packet to send.
 * @param dma_id      DMA ID to associate with the descriptor
 *                    (arbitrary number which can be used for subsequent
 *                     tracking of buffers).
 *
 * @return @c 0 on success, @c -1 on failure.
 */
extern int rpc_ef_vi_transmit(rcf_rpc_server *rpcs, rpc_ef_vi_p vi,
                              rpc_ef_addr base, int len,
                              rpc_ef_request_id dma_id);

/**
 * Transmit a packet from a vector of packet buffers.
 *
 * @param rpcs        RPC server handle.
 * @param vi          Virtual interface.
 * @param iov         Pointer to array of tarpc_ef_iovec.
 * @param iov_len     Number of elements in the array.
 * @param dma_id      DMA ID to associate with the descriptor
 *                    (arbitrary number which can be used for subsequent
 *                     tracking of buffers).
 *
 * @return @c 0 on success, @c -1 on failure.
 */
extern int rpc_ef_vi_transmitv(rcf_rpc_server *rpcs, rpc_ef_vi_p vi,
                               tarpc_ef_iovec *iov, int iov_len,
                               rpc_ef_request_id dma_id);

/**
 * Initialize a TX descriptor on the TX descriptor ring for a single
 * packet buffer.
 *
 * @note After initializing descriptor(s) with this function, use
 *       @b rpc_ef_vi_transmit_push() to submit descriptors to NIC.
 *
 * @param rpcs        RPC server handle.
 * @param vi          Virtual interface.
 * @param base        DMA address of the associated packet buffer
 *                    obtained with @b rpc_ef_memreg_dma_addr().
 * @param len         Length of the packet to send.
 * @param dma_id      DMA ID to associate with the descriptor
 *                    (arbitrary number which can be used for subsequent
 *                     tracking of buffers).
 *
 * @return @c 0 on success, @c -1 on failure.
 */
extern int rpc_ef_vi_transmit_init(rcf_rpc_server *rpcs, rpc_ef_vi_p vi,
                                   rpc_ef_addr base, int len,
                                   rpc_ef_request_id dma_id);

/**
 * Initialize a TX descriptor on the TX descriptor ring for a vector
 * of packet buffers.
 *
 * @note After initializing descriptor(s) with this function, use
 *       @b rpc_ef_vi_transmit_push() to submit descriptors to NIC.
 *
 * @param rpcs        RPC server handle.
 * @param vi          Virtual interface.
 * @param iov         Pointer to array of tarpc_ef_iovec.
 * @param iov_len     Number of elements in the array.
 * @param dma_id      DMA ID to associate with the descriptor
 *                    (arbitrary number which can be used for subsequent
 *                     tracking of buffers).
 *
 * @return @c 0 on success, @c -1 on failure.
 */
extern int rpc_ef_vi_transmitv_init(rcf_rpc_server *rpcs, rpc_ef_vi_p vi,
                                    tarpc_ef_iovec *iov, int iov_len,
                                    rpc_ef_request_id dma_id);

/**
 * Submit newly initialized TX descriptors to the NIC so that it will
 * be able to transmit associated packet buffers.
 *
 * @note At least one TX descriptor should be initialized before calling
 *       this function.
 *
 * @param rpcs        RPC server handle.
 * @param vi          Virtual interface.
 *
 * @return @c 0 on success, @c -1 on failure.
 */
extern int rpc_ef_vi_transmit_push(rcf_rpc_server *rpcs, rpc_ef_vi_p vi);

/**
 * Poll an event queue.
 *
 * @param rpcs          RPC server handle.
 * @param vi            Virtual interface to poll.
 * @param evts          Array where to save events.
 * @param evts_num      Length of the array (must be at least
 *                      @c EF_VI_EVENT_POLL_MIN_EVS).
 *
 * @return Number of retrieved events on success, @c -1 on failure.
 */
extern int rpc_ef_eventq_poll(rcf_rpc_server *rpcs, rpc_ef_vi_p vi,
                              ef_event *evts, int evts_num);

/**
 * Retrieve packet data from a given buffer.
 *
 * @param rpcs      RPC server handle.
 * @param vi        Virtual interface on which packet was received.
 * @param mem       Pointer to the memory region registered for that
 *                  interface.
 * @param offset    Offset of the packet buffer inside the memory region.
 * @param len       Length of the packet data.
 * @param buf       Where to save retrieved data.
 * @param buf_len   Length of the buffer where to save data.
 *
 * @return Length of retrieved data on success, @c -1 on failure.
 */
extern int rpc_efvi_get_pkt_data(rcf_rpc_server *rpcs, rpc_ef_vi_p vi,
                                 tarpc_ptr mem, size_t offset, int len,
                                 uint8_t *buf, int buf_len);

/**
 * Get string representation of ef_event type.
 *
 * @param type    @c EF_EVENT_TYPE_RX, @c EF_EVENT_TYPE_TX, etc.
 *
 * @return String representation.
 */
extern const char *ef_event_type_h2str(int type);

/**
 * Unbundle an event of type @c EF_EVENT_TYPE_TX or
 * @c EF_EVENT_TYPE_TX_ERROR.
 *
 * @note NIC may coalesce multiple transmissions into a single TX
 *       event, this function allows to retrieve DMA IDs of descriptors
 *       whose transmission was completed.
 *
 * @param rpcs        RPC server handle.
 * @param vi          Virtual interface.
 * @param event       TX event to unbundle.
 * @param ids         Array where to save DMA IDs (should have
 *                    @c EF_VI_TRANSMIT_BATCH elements).
 *
 * @return Number of retrieved IDs on success, @c -1 on failure.
 */
extern int rpc_ef_vi_transmit_unbundle(rcf_rpc_server *rpcs,
                                       rpc_ef_vi_p vi,
                                       ef_event *event,
                                       rpc_ef_request_id *ids);

/**
 * Unbundle an event of type @c EF_EVENT_TYPE_RX_MULTI or
 * @c EF_EVENT_TYPE_RX_MULTI_DISCARD.
 *
 * @note When virtual interface is allocated with @c EF_VI_RX_EVENT_MERGE
 *       flag, multiple received buffers may be reported in a single RX
 *       event. This function allows to get IDs of individual buffers
 *       in that case.
 *
 * @param rpcs        RPC server handle.
 * @param vi          Virtual interface.
 * @param event       Event to unbundle.
 * @param ids         Array where to save DMA IDs (should have
 *                    @c EF_VI_RECEIVE_BATCH elements).
 *
 * @return Number of retrieved IDs on success, @c -1 on failure.
 */
extern int rpc_ef_vi_receive_unbundle(rcf_rpc_server *rpcs,
                                      rpc_ef_vi_p vi,
                                      ef_event *event,
                                      rpc_ef_request_id *ids);

/**
 * Retrieve the number of bytes in a received packet in RX event
 * merge mode.
 *
 * @param rpcs      RPC server.
 * @param vi        Virtual interface.
 * @param mem       Pointer to the memory region registered for that
 *                  interface.
 * @param offset    Offset of the packet buffer inside the memory region.
 * @param len       Where to save retrieved length.
 *
 * @return @c 0 on success, @c -1 on failure.
 */
extern int rpc_ef_vi_receive_get_bytes(rcf_rpc_server *rpcs, rpc_ef_vi_p vi,
                                       tarpc_ptr mem, size_t offset,
                                       unsigned int *len);

#endif /* !__EFVI_RPC_H__ */
