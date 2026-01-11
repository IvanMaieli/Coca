#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

#include "filter.h"
#include "coke.h"

/* =============================================================================
 * FILTER MODULE IMPLEMENTATION
 * ============================================================================= */

// Protocol name mapping
typedef struct {
    const char *name;
    protocol_mask_t mask;
} protocol_entry_t;

static const protocol_entry_t protocol_table[] = {
    {"tcp",   PROTO_TCP},
    {"udp",   PROTO_UDP},
    {"icmp",  PROTO_ICMP},
    {"arp",   PROTO_ARP},
    {"dns",   PROTO_DNS},
    {"http",  PROTO_HTTP},
    {"https", PROTO_TLS},
    {"tls",   PROTO_TLS},
    {"ssh",   PROTO_SSH},
    {"all",   PROTO_ALL},
    {NULL,    PROTO_NONE}
};

/**
 * Parse comma-separated protocol string into bitmask
 */
protocol_mask_t filter_parse_protocols(const char *str) {
    if (!str || strlen(str) == 0) {
        return PROTO_ALL;
    }
    
    // Handle "all" or "clear"
    if (strcasecmp(str, "all") == 0 || strcasecmp(str, "clear") == 0) {
        return PROTO_ALL;
    }
    
    protocol_mask_t result = PROTO_NONE;
    
    // Work with a copy
    char *copy = strdup(str);
    if (!copy) {
        return PROTO_ALL;
    }
    
    // Tokenize by comma
    char *saveptr;
    char *token = strtok_r(copy, ",", &saveptr);
    
    while (token) {
        // Trim whitespace
        while (isspace((unsigned char)*token)) token++;
        char *end = token + strlen(token) - 1;
        while (end > token && isspace((unsigned char)*end)) *end-- = '\0';
        
        // Convert to lowercase for comparison
        for (char *p = token; *p; p++) {
            *p = tolower((unsigned char)*p);
        }
        
        // Look up protocol
        bool found = false;
        for (const protocol_entry_t *entry = protocol_table; entry->name; entry++) {
            if (strcmp(token, entry->name) == 0) {
                result |= entry->mask;
                found = true;
                break;
            }
        }
        
        if (!found) {
            printf("\033[1;33m[FILTER] Unknown protocol: %s\033[0m\n", token);
        }
        
        token = strtok_r(NULL, ",", &saveptr);
    }
    
    free(copy);
    
    // If nothing matched, return ALL
    return (result == PROTO_NONE) ? PROTO_ALL : result;
}

/**
 * Check if packet matches filter mask
 */
bool filter_match(const packet_entry_t *packet, protocol_mask_t mask) {
    if (!packet || mask == PROTO_ALL) {
        return true;  // No filter or accept all
    }
    
    // Check transport layer protocol
    protocol_mask_t packet_proto = PROTO_NONE;
    
    switch (packet->ip_protocol) {
        case IP_PROTO_TCP:
            packet_proto |= PROTO_TCP;
            break;
        case IP_PROTO_UDP:
            packet_proto |= PROTO_UDP;
            break;
        case IP_PROTO_ICMP:
            packet_proto |= PROTO_ICMP;
            break;
    }
    
    // Include detected application protocol
    packet_proto |= packet->app_protocol;
    
    // If packet has no recognized protocol, classify as OTHER
    if (packet_proto == PROTO_NONE) {
        packet_proto = PROTO_OTHER;
    }
    
    // Check if any of the packet's protocols match the filter
    return (packet_proto & mask) != 0;
}

/**
 * Get human-readable protocol name
 */
const char* filter_get_protocol_name(protocol_mask_t proto) {
    switch (proto) {
        case PROTO_TCP:   return "TCP";
        case PROTO_UDP:   return "UDP";
        case PROTO_ICMP:  return "ICMP";
        case PROTO_ARP:   return "ARP";
        case PROTO_DNS:   return "DNS";
        case PROTO_HTTP:  return "HTTP";
        case PROTO_TLS:   return "TLS";
        case PROTO_SSH:   return "SSH";
        case PROTO_ALL:   return "ALL";
        case PROTO_OTHER: return "OTHER";
        default:          return "UNK";
    }
}

/**
 * Detect application protocol from packet
 */
protocol_mask_t filter_detect_app_protocol(const packet_entry_t *packet) {
    if (!packet) {
        return PROTO_NONE;
    }
    
    protocol_mask_t result = PROTO_NONE;
    
    // Only detect for TCP/UDP
    if (packet->ip_protocol != IP_PROTO_TCP && packet->ip_protocol != IP_PROTO_UDP) {
        return PROTO_NONE;
    }
    
    // Check by port numbers
    uint16_t sport = packet->src_port;
    uint16_t dport = packet->dst_port;
    
    // DNS (port 53)
    if (sport == PORT_DNS || dport == PORT_DNS) {
        result |= PROTO_DNS;
    }
    
    // HTTP (port 80)
    if (sport == PORT_HTTP || dport == PORT_HTTP) {
        result |= PROTO_HTTP;
    }
    
    // HTTPS/TLS (port 443)
    if (sport == PORT_HTTPS || dport == PORT_HTTPS) {
        result |= PROTO_TLS;
    }
    
    // SSH (port 22)
    if (sport == PORT_SSH || dport == PORT_SSH) {
        result |= PROTO_SSH;
    }
    
    return result;
}

/**
 * Display current filter configuration
 */
void filter_show(void) {
    printf("\n\033[1;36m=== FILTER CONFIGURATION ===\033[0m\n");
    
    if (config.filter_mask == PROTO_ALL) {
        printf("  Status: \033[1;32mACCEPT ALL\033[0m\n");
    } else {
        printf("  Status: \033[1;33mFILTERING\033[0m\n");
        printf("  Active protocols:\n");
        
        for (const protocol_entry_t *entry = protocol_table; entry->name; entry++) {
            if (entry->mask != PROTO_ALL && entry->mask != PROTO_NONE) {
                bool active = (config.filter_mask & entry->mask) != 0;
                printf("    [%s] %s\n", 
                       active ? "\033[1;32m✓\033[0m" : " ", 
                       entry->name);
            }
        }
    }
    printf("\n");
}

/**
 * Clear all filters
 */
void filter_clear(void) {
    config.filter_mask = PROTO_ALL;
    printf("\033[1;32m[FILTER] All filters cleared\033[0m\n");
}

/**
 * Get descriptive string of active filters
 */
void filter_describe(protocol_mask_t mask, char *buffer, size_t size) {
    if (!buffer || size == 0) {
        return;
    }
    
    buffer[0] = '\0';
    
    if (mask == PROTO_ALL) {
        snprintf(buffer, size, "ALL");
        return;
    }
    
    size_t pos = 0;
    bool first = true;
    
    for (const protocol_entry_t *entry = protocol_table; entry->name && pos < size - 1; entry++) {
        if (entry->mask != PROTO_ALL && entry->mask != PROTO_NONE) {
            if (mask & entry->mask) {
                if (!first && pos < size - 2) {
                    buffer[pos++] = ',';
                }
                size_t name_len = strlen(entry->name);
                if (pos + name_len < size) {
                    memcpy(buffer + pos, entry->name, name_len);
                    pos += name_len;
                    first = false;
                }
            }
        }
    }
    
    buffer[pos] = '\0';
}
