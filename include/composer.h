#ifndef COMPOSER_H
#define COMPOSER_H

#include <stdint.h>
#include "coke.h"

/* =============================================================================
 * COMPOSER MODULE
 * 
 * Conversation tracking and composition:
 * - Groups packets into bidirectional flows
 * - Uses 5-tuple for flow identification
 * - Tracks statistics per conversation
 * - Provides conversation timeline view
 * ============================================================================= */

/**
 * Initialize the conversation tracking subsystem
 * Allocates hash table for flow tracking
 */
void composer_init(void);

/**
 * Cleanup all conversation data
 */
void composer_cleanup(void);

/**
 * Track a packet and associate it with a conversation
 * Creates new conversation if needed
 * 
 * @param packet Packet to track
 */
void composer_track_packet(packet_entry_t *packet);

/**
 * List all active conversations
 * Shows summary: endpoints, protocol, packet count, bytes
 */
void composer_list(void);

/**
 * Show detailed view of a specific conversation
 * Displays packet sequence with timestamps
 * 
 * @param id Conversation ID
 */
void composer_show(uint32_t id);

/**
 * Display conversation statistics
 * Total conversations, packets, bytes, etc.
 */
void composer_stats(void);

/**
 * Find a conversation by flow key
 * 
 * @param key 5-tuple flow identifier
 * @return Pointer to conversation, or NULL if not found
 */
conversation_t* composer_find_conversation(const flow_key_t *key);

/**
 * Export a conversation to file
 * 
 * @param id Conversation ID
 * @param filename Output filename
 * @param format Export format (0=text, 1=json)
 * @return true on success, false on failure
 */
bool composer_export(uint32_t id, const char *filename, int format);

/**
 * Get conversation by ID
 * 
 * @param id Conversation ID
 * @return Pointer to conversation, or NULL if not found
 */
conversation_t* composer_get_by_id(uint32_t id);

/**
 * Compute hash for flow key
 * Used for hash table bucket selection
 * 
 * @param key Flow key
 * @return Hash value
 */
uint32_t composer_flow_hash(const flow_key_t *key);

/**
 * Check if two flow keys represent the same conversation
 * Handles bidirectional matching (A->B == B->A)
 * 
 * @param a First flow key
 * @param b Second flow key
 * @return true if same conversation, false otherwise
 */
bool composer_flow_equal(const flow_key_t *a, const flow_key_t *b);

#endif /* COMPOSER_H */
