#ifndef COKE_H
#define COKE_H

#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>
#include <signal.h>
#include <sys/time.h>
#include <pthread.h>

/* =============================================================================
 * PROTOCOL DEFINITIONS
 * ============================================================================= */

// Protocol bitmask for multi-protocol filtering
typedef enum {
    PROTO_NONE = 0,
    PROTO_TCP  = (1 << 0),   // 0x0001
    PROTO_UDP  = (1 << 1),   // 0x0002
    PROTO_ICMP = (1 << 2),   // 0x0004
    PROTO_ARP  = (1 << 3),   // 0x0008
    PROTO_DNS  = (1 << 4),   // 0x0010
    PROTO_HTTP = (1 << 5),   // 0x0020
    PROTO_TLS  = (1 << 6),   // 0x0040
    PROTO_SSH  = (1 << 7),   // 0x0080
    PROTO_OTHER = (1 << 15), // 0x8000
    PROTO_ALL  = 0xFFFF
} protocol_mask_t;

// IP protocol numbers (from IANA)
#define IP_PROTO_ICMP  1
#define IP_PROTO_TCP   6
#define IP_PROTO_UDP   17

// Well-known ports for application protocol detection
#define PORT_DNS   53
#define PORT_HTTP  80
#define PORT_HTTPS 443
#define PORT_SSH   22

/* =============================================================================
 * PACKET STRUCTURES
 * ============================================================================= */

// Captured packet structure for inspect mode
typedef struct packet_entry {
    uint32_t id;                    // Unique packet ID
    struct timeval timestamp;       // Capture timestamp
    uint16_t length;                // Total packet length
    uint16_t captured_length;       // Actually captured length
    uint8_t ip_protocol;            // IP protocol number (TCP=6, UDP=17, etc.)
    protocol_mask_t app_protocol;   // Application protocol (HTTP, DNS, etc.)
    uint32_t src_ip;                // Source IP address
    uint32_t dst_ip;                // Destination IP address
    uint16_t src_port;              // Source port (if TCP/UDP)
    uint16_t dst_port;              // Destination port (if TCP/UDP)
    uint8_t *data;                  // Raw packet data
    struct packet_entry *next;      // Next packet in list
    struct packet_entry *prev;      // Previous packet in list
} packet_entry_t;

/* =============================================================================
 * CONVERSATION STRUCTURES
 * ============================================================================= */

// 5-tuple flow identifier
typedef struct {
    uint32_t src_ip;
    uint32_t dst_ip;
    uint16_t src_port;
    uint16_t dst_port;
    uint8_t protocol;
} flow_key_t;

// Conversation tracking structure
typedef struct conversation {
    uint32_t id;                    // Unique conversation ID
    flow_key_t flow;                // Flow identifier
    struct timeval start_time;      // First packet timestamp
    struct timeval last_time;       // Last packet timestamp
    uint32_t packet_count_fwd;      // Packets A -> B
    uint32_t packet_count_rev;      // Packets B -> A
    uint64_t bytes_fwd;             // Bytes A -> B
    uint64_t bytes_rev;             // Bytes B -> A
    packet_entry_t *first_packet;   // First packet reference
    packet_entry_t *last_packet;    // Last packet reference
    struct conversation *next;      // Next conversation in hash bucket
} conversation_t;

/* =============================================================================
 * CONFIGURATION
 * ============================================================================= */

// Application configuration
typedef struct {
    char *output_file;              // PCAP output file path
    protocol_mask_t filter_mask;    // Multi-protocol filter bitmask
    bool verbose;                   // Verbose output
    bool hex_view;                  // Show hex dump
    uint32_t max_packets;           // Maximum packets to buffer (0 = unlimited)
    uint32_t max_packet_size;       // Maximum bytes to capture per packet
    char *interface;                // Network interface to sniff
} coke_config_t;

// Application state
typedef struct {
    uint32_t packets_captured;      // Total packets captured
    uint32_t packets_filtered;      // Packets filtered out
    uint32_t conversations_count;   // Active conversations
    uint32_t current_packet_id;     // Current packet ID in inspect mode
    bool in_inspect_mode;           // Currently in inspect mode
} coke_state_t;

/* =============================================================================
 * GLOBAL VARIABLES
 * ============================================================================= */

extern volatile sig_atomic_t is_sniffing;  // Sniffer active flag
extern coke_config_t config;               // Global configuration
extern coke_state_t state;                 // Global state
extern pthread_mutex_t packet_mutex;       // Mutex for packet buffer
extern pthread_mutex_t conv_mutex;         // Mutex for conversation table

/* =============================================================================
 * BUFFER CONSTANTS
 * ============================================================================= */

#define MAX_PACKET_SIZE     65536
#define DEFAULT_MAX_PACKETS 10000
#define MAX_INPUT_LENGTH    256
#define CONV_HASH_SIZE      1024

/* =============================================================================
 * UI FUNCTIONS
 * ============================================================================= */

void print_banner(void);
void hex_dump(const unsigned char *data, int size);
void print_help(void);
void print_status(void);

/* =============================================================================
 * SNIFFER FUNCTIONS
 * ============================================================================= */

void* sniffer_loop(void* arg);
void setup_signals(void);

/* =============================================================================
 * LOGGER FUNCTIONS
 * ============================================================================= */

FILE* pcap_init(const char* filename);
void pcap_write_packet(FILE *f, const uint8_t *data, uint32_t length, 
                       struct timeval *ts);

/* =============================================================================
 * FORWARD DECLARATIONS FOR NEW MODULES
 * ============================================================================= */

// Filter functions (filter.c)
protocol_mask_t filter_parse_protocols(const char *str);
bool filter_match(const packet_entry_t *packet, protocol_mask_t mask);
const char* filter_get_protocol_name(protocol_mask_t proto);
protocol_mask_t filter_detect_app_protocol(const packet_entry_t *packet);
void filter_show(void);

// Inspect functions (inspect.c)
void inspect_init(void);
void inspect_cleanup(void);
void inspect_add_packet(packet_entry_t *packet);
packet_entry_t* inspect_get_packet(uint32_t id);
void inspect_enter(void);
void inspect_show_packet(uint32_t id);
void inspect_list(uint32_t start, uint32_t count);
uint32_t inspect_get_count(void);
packet_entry_t* inspect_get_first(void);
packet_entry_t* inspect_get_last(void);

// Composer functions (composer.c)
void composer_init(void);
void composer_cleanup(void);
void composer_track_packet(packet_entry_t *packet);
void composer_list(void);
void composer_show(uint32_t id);
void composer_stats(void);
conversation_t* composer_find_conversation(const flow_key_t *key);

// Security functions (security.c)
bool security_init(void);
bool security_drop_privileges(void);
bool security_validate_input(const char *str, size_t max_len);
void security_secure_free(void *ptr, size_t size);
bool security_check_capabilities(void);

#endif /* COKE_H */
