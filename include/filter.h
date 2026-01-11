#ifndef FILTER_H
#define FILTER_H

#include <stdbool.h>
#include "coke.h"

/* =============================================================================
 * FILTER MODULE
 * 
 * Multi-protocol filtering system using bitmasks
 * Supports filtering by:
 * - Network layer protocols (IP, ARP, ICMP)
 * - Transport layer protocols (TCP, UDP)
 * - Application layer protocols (HTTP, DNS, TLS, SSH)
 * ============================================================================= */

/**
 * Parse a comma-separated protocol string into a bitmask
 * Example: "tcp,udp,icmp" -> PROTO_TCP | PROTO_UDP | PROTO_ICMP
 * 
 * @param str Protocol string (e.g., "tcp,udp,http")
 * @return Protocol bitmask, or PROTO_NONE on error
 */
protocol_mask_t filter_parse_protocols(const char *str);

/**
 * Check if a packet matches the current filter
 * 
 * @param packet Packet to check
 * @param mask Protocol bitmask to match against
 * @return true if packet matches filter, false otherwise
 */
bool filter_match(const packet_entry_t *packet, protocol_mask_t mask);

/**
 * Get human-readable name for a protocol
 * 
 * @param proto Single protocol bit
 * @return Protocol name string (e.g., "TCP", "UDP")
 */
const char* filter_get_protocol_name(protocol_mask_t proto);

/**
 * Detect application-layer protocol from packet contents
 * Uses port numbers and deep packet inspection
 * 
 * @param packet Packet to analyze
 * @return Detected application protocol mask
 */
protocol_mask_t filter_detect_app_protocol(const packet_entry_t *packet);

/**
 * Display current filter configuration
 */
void filter_show(void);

/**
 * Clear all filters (set to PROTO_ALL)
 */
void filter_clear(void);

/**
 * Get a descriptive string of active filters
 * 
 * @param mask Protocol bitmask
 * @param buffer Output buffer
 * @param size Buffer size
 */
void filter_describe(protocol_mask_t mask, char *buffer, size_t size);

#endif /* FILTER_H */
