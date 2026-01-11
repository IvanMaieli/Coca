#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <sys/time.h>

#include "composer.h"
#include "filter.h"
#include "coke.h"

/* =============================================================================
 * COMPOSER MODULE IMPLEMENTATION
 * ============================================================================= */

// Hash table for conversations
static conversation_t *conv_table[CONV_HASH_SIZE];
static uint32_t next_conv_id = 1;
uint32_t total_conversations = 0;

/**
 * Compute hash for flow key (simple FNV-1a variant)
 */
uint32_t composer_flow_hash(const flow_key_t *key) {
    if (!key) return 0;
    
    uint32_t hash = 2166136261u;
    
    // Mix src and dst to ensure bidirectional matching hashes the same
    uint32_t ip_low = key->src_ip < key->dst_ip ? key->src_ip : key->dst_ip;
    uint32_t ip_high = key->src_ip >= key->dst_ip ? key->src_ip : key->dst_ip;
    uint16_t port_low = key->src_port < key->dst_port ? key->src_port : key->dst_port;
    uint16_t port_high = key->src_port >= key->dst_port ? key->src_port : key->dst_port;
    
    hash ^= ip_low;
    hash *= 16777619u;
    hash ^= ip_high;
    hash *= 16777619u;
    hash ^= port_low;
    hash *= 16777619u;
    hash ^= port_high;
    hash *= 16777619u;
    hash ^= key->protocol;
    hash *= 16777619u;
    
    return hash % CONV_HASH_SIZE;
}

/**
 * Check if two flow keys represent the same conversation (bidirectional)
 */
bool composer_flow_equal(const flow_key_t *a, const flow_key_t *b) {
    if (!a || !b) return false;
    
    if (a->protocol != b->protocol) return false;
    
    // Check forward direction
    bool forward = (a->src_ip == b->src_ip && a->dst_ip == b->dst_ip &&
                    a->src_port == b->src_port && a->dst_port == b->dst_port);
    
    // Check reverse direction
    bool reverse = (a->src_ip == b->dst_ip && a->dst_ip == b->src_ip &&
                    a->src_port == b->dst_port && a->dst_port == b->src_port);
    
    return forward || reverse;
}

/**
 * Initialize composer
 */
void composer_init(void) {
    memset(conv_table, 0, sizeof(conv_table));
    next_conv_id = 1;
    total_conversations = 0;
}

/**
 * Free a conversation and its resources
 */
static void free_conversation(conversation_t *conv) {
    if (conv) {
        // Note: packets are owned by the inspect module, don't free them here
        free(conv);
    }
}

/**
 * Cleanup all conversations
 */
void composer_cleanup(void) {
    for (int i = 0; i < CONV_HASH_SIZE; i++) {
        conversation_t *conv = conv_table[i];
        while (conv) {
            conversation_t *next = conv->next;
            free_conversation(conv);
            conv = next;
        }
        conv_table[i] = NULL;
    }
    next_conv_id = 1;
    total_conversations = 0;
}

/**
 * Find or create a conversation for a packet
 */
conversation_t* composer_find_conversation(const flow_key_t *key) {
    if (!key) return NULL;
    
    uint32_t hash = composer_flow_hash(key);
    
    pthread_mutex_lock(&conv_mutex);
    
    // Search in bucket
    conversation_t *conv = conv_table[hash];
    while (conv) {
        if (composer_flow_equal(&conv->flow, key)) {
            pthread_mutex_unlock(&conv_mutex);
            return conv;
        }
        conv = conv->next;
    }
    
    pthread_mutex_unlock(&conv_mutex);
    return NULL;
}

/**
 * Track a packet in the conversation table
 */
void composer_track_packet(packet_entry_t *packet) {
    if (!packet) return;
    
    // Only track TCP and UDP
    if (packet->ip_protocol != IP_PROTO_TCP && packet->ip_protocol != IP_PROTO_UDP) {
        return;
    }
    
    flow_key_t key = {
        .src_ip = packet->src_ip,
        .dst_ip = packet->dst_ip,
        .src_port = packet->src_port,
        .dst_port = packet->dst_port,
        .protocol = packet->ip_protocol
    };
    
    pthread_mutex_lock(&conv_mutex);
    
    uint32_t hash = composer_flow_hash(&key);
    
    // Find existing conversation
    conversation_t *conv = conv_table[hash];
    conversation_t *found = NULL;
    
    while (conv) {
        if (composer_flow_equal(&conv->flow, &key)) {
            found = conv;
            break;
        }
        conv = conv->next;
    }
    
    if (!found) {
        // Create new conversation
        found = (conversation_t *)calloc(1, sizeof(conversation_t));
        if (!found) {
            pthread_mutex_unlock(&conv_mutex);
            return;
        }
        
        found->id = next_conv_id++;
        found->flow = key;
        found->start_time = packet->timestamp;
        found->first_packet = packet;
        
        // Insert at head of bucket
        found->next = conv_table[hash];
        conv_table[hash] = found;
        total_conversations++;
    }
    
    // Update conversation stats
    found->last_time = packet->timestamp;
    found->last_packet = packet;
    
    // Determine direction (is this packet forward or reverse?)
    bool is_forward = (packet->src_ip == found->flow.src_ip &&
                       packet->src_port == found->flow.src_port);
    
    if (is_forward) {
        found->packet_count_fwd++;
        found->bytes_fwd += packet->length;
    } else {
        found->packet_count_rev++;
        found->bytes_rev += packet->length;
    }
    
    pthread_mutex_unlock(&conv_mutex);
}

/**
 * Get conversation by ID
 */
conversation_t* composer_get_by_id(uint32_t id) {
    pthread_mutex_lock(&conv_mutex);
    
    for (int i = 0; i < CONV_HASH_SIZE; i++) {
        conversation_t *conv = conv_table[i];
        while (conv) {
            if (conv->id == id) {
                pthread_mutex_unlock(&conv_mutex);
                return conv;
            }
            conv = conv->next;
        }
    }
    
    pthread_mutex_unlock(&conv_mutex);
    return NULL;
}

/**
 * List all conversations
 */
void composer_list(void) {
    printf("\n\033[1;36m╔═══════════════════════════════════════════════════════════════════════════════════════════╗\033[0m\n");
    printf("\033[1;36m║  ID  │ PROTO │      ENDPOINT A       ↔       ENDPOINT B       │   A→B   │   B→A   ║\033[0m\n");
    printf("\033[1;36m╠═══════════════════════════════════════════════════════════════════════════════════════════╣\033[0m\n");
    
    pthread_mutex_lock(&conv_mutex);
    
    uint32_t shown = 0;
    
    for (int i = 0; i < CONV_HASH_SIZE && shown < 50; i++) {
        conversation_t *conv = conv_table[i];
        while (conv && shown < 50) {
            struct in_addr src, dst;
            src.s_addr = conv->flow.src_ip;
            dst.s_addr = conv->flow.dst_ip;
            
            const char *proto_str = (conv->flow.protocol == IP_PROTO_TCP) ? "TCP" :
                                    (conv->flow.protocol == IP_PROTO_UDP) ? "UDP" : "???";
            
            char *color = (conv->flow.protocol == IP_PROTO_TCP) ? "\033[1;32m" : "\033[1;34m";
            
            char src_str[24], dst_str[24];
            snprintf(src_str, sizeof(src_str), "%s:%d", inet_ntoa(src), conv->flow.src_port);
            snprintf(dst_str, sizeof(dst_str), "%s:%d", inet_ntoa(dst), conv->flow.dst_port);
            
            printf("%s║ %4u │ %-5s │ %-21s ↔ %-21s │ %4u/%4luKB │ %4u/%4luKB ║\033[0m\n",
                   color, conv->id, proto_str, src_str, dst_str,
                   conv->packet_count_fwd, (unsigned long)(conv->bytes_fwd / 1024),
                   conv->packet_count_rev, (unsigned long)(conv->bytes_rev / 1024));
            
            conv = conv->next;
            shown++;
        }
    }
    
    pthread_mutex_unlock(&conv_mutex);
    
    if (shown == 0) {
        printf("\033[1;36m║                         (no conversations tracked)                                       ║\033[0m\n");
    }
    
    printf("\033[1;36m╚═══════════════════════════════════════════════════════════════════════════════════════════╝\033[0m\n");
    printf("  Total: %u conversations\n\n", total_conversations);
}

/**
 * Show detailed conversation view
 */
void composer_show(uint32_t id) {
    conversation_t *conv = composer_get_by_id(id);
    
    if (!conv) {
        printf("\033[1;31m[COMPOSE] Conversation #%u not found\033[0m\n", id);
        return;
    }
    
    struct in_addr src, dst;
    src.s_addr = conv->flow.src_ip;
    dst.s_addr = conv->flow.dst_ip;
    
    printf("\n\033[1;36m╔══════════════════════════════════════════════════════════════╗\033[0m\n");
    printf("\033[1;36m║                   CONVERSATION #%-6u                       ║\033[0m\n", conv->id);
    printf("\033[1;36m╚══════════════════════════════════════════════════════════════╝\033[0m\n");
    
    const char *proto_str = (conv->flow.protocol == IP_PROTO_TCP) ? "TCP" :
                            (conv->flow.protocol == IP_PROTO_UDP) ? "UDP" : "???";
    
    printf("\n  \033[1;37m═══ FLOW INFO ═══\033[0m\n");
    printf("    Protocol:        %s\n", proto_str);
    printf("    Endpoint A:      %s:%d\n", inet_ntoa(src), conv->flow.src_port);
    printf("    Endpoint B:      %s:%d\n", inet_ntoa(dst), conv->flow.dst_port);
    
    printf("\n  \033[1;37m═══ STATISTICS ═══\033[0m\n");
    printf("    Duration:        %ld.%03ld seconds\n",
           conv->last_time.tv_sec - conv->start_time.tv_sec,
           (conv->last_time.tv_usec - conv->start_time.tv_usec) / 1000);
    printf("    A → B:           %u packets, %llu bytes\n", 
           conv->packet_count_fwd, (unsigned long long)conv->bytes_fwd);
    printf("    B → A:           %u packets, %llu bytes\n", 
           conv->packet_count_rev, (unsigned long long)conv->bytes_rev);
    printf("    Total:           %u packets, %llu bytes\n",
           conv->packet_count_fwd + conv->packet_count_rev,
           (unsigned long long)(conv->bytes_fwd + conv->bytes_rev));
    
    printf("\n  \033[1;37m═══ PACKET REFERENCES ═══\033[0m\n");
    if (conv->first_packet) {
        printf("    First packet:    #%u\n", conv->first_packet->id);
    }
    if (conv->last_packet) {
        printf("    Last packet:     #%u\n", conv->last_packet->id);
    }
    
    printf("\n");
}

/**
 * Display conversation statistics
 */
void composer_stats(void) {
    printf("\n\033[1;36m╔══════════════════════════════════════════════════════════════╗\033[0m\n");
    printf("\033[1;36m║                 CONVERSATION STATISTICS                       ║\033[0m\n");
    printf("\033[1;36m╚══════════════════════════════════════════════════════════════╝\033[0m\n");
    
    pthread_mutex_lock(&conv_mutex);
    
    uint32_t tcp_count = 0, udp_count = 0;
    uint64_t total_bytes_fwd = 0, total_bytes_rev = 0;
    uint32_t total_packets_fwd = 0, total_packets_rev = 0;
    
    for (int i = 0; i < CONV_HASH_SIZE; i++) {
        conversation_t *conv = conv_table[i];
        while (conv) {
            if (conv->flow.protocol == IP_PROTO_TCP) tcp_count++;
            else if (conv->flow.protocol == IP_PROTO_UDP) udp_count++;
            
            total_bytes_fwd += conv->bytes_fwd;
            total_bytes_rev += conv->bytes_rev;
            total_packets_fwd += conv->packet_count_fwd;
            total_packets_rev += conv->packet_count_rev;
            
            conv = conv->next;
        }
    }
    
    pthread_mutex_unlock(&conv_mutex);
    
    printf("\n  Total Conversations:  %u\n", total_conversations);
    printf("    TCP:                %u\n", tcp_count);
    printf("    UDP:                %u\n", udp_count);
    printf("\n  Total Traffic:\n");
    printf("    Forward (A→B):      %u packets, %.2f MB\n", 
           total_packets_fwd, (double)total_bytes_fwd / (1024 * 1024));
    printf("    Reverse (B→A):      %u packets, %.2f MB\n", 
           total_packets_rev, (double)total_bytes_rev / (1024 * 1024));
    printf("    Combined:           %u packets, %.2f MB\n",
           total_packets_fwd + total_packets_rev,
           (double)(total_bytes_fwd + total_bytes_rev) / (1024 * 1024));
    printf("\n");
}

/**
 * Export conversation to file
 */
bool composer_export(uint32_t id, const char *filename, int format) {
    conversation_t *conv = composer_get_by_id(id);
    
    if (!conv) {
        printf("\033[1;31m[COMPOSE] Conversation #%u not found\033[0m\n", id);
        return false;
    }
    
    FILE *f = fopen(filename, "w");
    if (!f) {
        printf("\033[1;31m[COMPOSE] Could not open file: %s\033[0m\n", filename);
        return false;
    }
    
    struct in_addr src, dst;
    src.s_addr = conv->flow.src_ip;
    dst.s_addr = conv->flow.dst_ip;
    
    if (format == 1) {
        // JSON format
        fprintf(f, "{\n");
        fprintf(f, "  \"id\": %u,\n", conv->id);
        fprintf(f, "  \"protocol\": \"%s\",\n", 
                conv->flow.protocol == IP_PROTO_TCP ? "TCP" : "UDP");
        fprintf(f, "  \"endpoint_a\": \"%s:%d\",\n", inet_ntoa(src), conv->flow.src_port);
        fprintf(f, "  \"endpoint_b\": \"%s:%d\",\n", inet_ntoa(dst), conv->flow.dst_port);
        fprintf(f, "  \"packets_a_to_b\": %u,\n", conv->packet_count_fwd);
        fprintf(f, "  \"packets_b_to_a\": %u,\n", conv->packet_count_rev);
        fprintf(f, "  \"bytes_a_to_b\": %llu,\n", (unsigned long long)conv->bytes_fwd);
        fprintf(f, "  \"bytes_b_to_a\": %llu\n", (unsigned long long)conv->bytes_rev);
        fprintf(f, "}\n");
    } else {
        // Text format
        fprintf(f, "Conversation #%u\n", conv->id);
        fprintf(f, "================\n\n");
        fprintf(f, "Protocol:     %s\n", 
                conv->flow.protocol == IP_PROTO_TCP ? "TCP" : "UDP");
        fprintf(f, "Endpoint A:   %s:%d\n", inet_ntoa(src), conv->flow.src_port);
        fprintf(f, "Endpoint B:   %s:%d\n", inet_ntoa(dst), conv->flow.dst_port);
        fprintf(f, "\nTraffic:\n");
        fprintf(f, "  A → B: %u packets, %llu bytes\n", 
                conv->packet_count_fwd, (unsigned long long)conv->bytes_fwd);
        fprintf(f, "  B → A: %u packets, %llu bytes\n", 
                conv->packet_count_rev, (unsigned long long)conv->bytes_rev);
    }
    
    fclose(f);
    printf("\033[1;32m[COMPOSE] Exported to %s\033[0m\n", filename);
    return true;
}
