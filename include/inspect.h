#ifndef INSPECT_H
#define INSPECT_H

#include <stdint.h>
#include "coke.h"

/* =============================================================================
 * INSPECT MODULE
 * 
 * Provides packet buffer management and interactive inspection:
 * - Ring buffer for captured packets
 * - Navigation commands (next, prev, goto)
 * - Detailed packet dissection
 * - Layer-by-layer protocol breakdown
 * ============================================================================= */

/**
 * Initialize the packet buffer
 * Allocates memory for packet storage
 */
void inspect_init(void);

/**
 * Cleanup and free all packet buffer memory
 */
void inspect_cleanup(void);

/**
 * Add a packet to the buffer
 * If buffer is full, oldest packet is removed
 * 
 * @param packet Packet to add (takes ownership)
 */
void inspect_add_packet(packet_entry_t *packet);

/**
 * Get a packet by ID
 * 
 * @param id Packet ID
 * @return Pointer to packet, or NULL if not found
 */
packet_entry_t* inspect_get_packet(uint32_t id);

/**
 * Enter interactive inspect mode
 * Provides commands: next, prev, goto, detail, list, quit
 */
void inspect_enter(void);

/**
 * Display detailed packet information
 * Shows Ethernet, IP, TCP/UDP headers and payload
 * 
 * @param id Packet ID to display
 */
void inspect_show_packet(uint32_t id);

/**
 * List packet summaries
 * 
 * @param start Starting packet ID (0 for first)
 * @param count Number of packets to list
 */
void inspect_list(uint32_t start, uint32_t count);

/**
 * Get total number of packets in buffer
 * 
 * @return Packet count
 */
uint32_t inspect_get_count(void);

/**
 * Get first packet in buffer
 * 
 * @return Pointer to first packet, or NULL if empty
 */
packet_entry_t* inspect_get_first(void);

/**
 * Get last packet in buffer
 * 
 * @return Pointer to last packet, or NULL if empty
 */
packet_entry_t* inspect_get_last(void);

/**
 * Display Ethernet header information
 * 
 * @param data Raw packet data
 * @param length Packet length
 */
void inspect_show_ethernet(const uint8_t *data, uint16_t length);

/**
 * Display IP header information
 * 
 * @param data Raw packet data (starting at IP header)
 * @param length Remaining packet length
 */
void inspect_show_ip(const uint8_t *data, uint16_t length);

/**
 * Display TCP header information
 * 
 * @param data Raw packet data (starting at TCP header)
 * @param length Remaining packet length
 */
void inspect_show_tcp(const uint8_t *data, uint16_t length);

/**
 * Display UDP header information
 * 
 * @param data Raw packet data (starting at UDP header)
 * @param length Remaining packet length
 */
void inspect_show_udp(const uint8_t *data, uint16_t length);

#endif /* INSPECT_H */
