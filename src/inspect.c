#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>
#include <ctype.h>

#include "inspect.h"
#include "filter.h"
#include "coke.h"

/* =============================================================================
 * INSPECT MODULE IMPLEMENTATION
 * ============================================================================= */

// Packet buffer (doubly-linked list with count limit)
static packet_entry_t *packet_head = NULL;
static packet_entry_t *packet_tail = NULL;
static uint32_t packet_count = 0;
static uint32_t next_packet_id = 1;

/**
 * Initialize the packet buffer
 */
void inspect_init(void) {
    packet_head = NULL;
    packet_tail = NULL;
    packet_count = 0;
    next_packet_id = 1;
}

/**
 * Free a single packet entry
 */
static void free_packet(packet_entry_t *pkt) {
    if (pkt) {
        if (pkt->data) {
            free(pkt->data);
        }
        free(pkt);
    }
}

/**
 * Remove oldest packet from buffer
 */
static void remove_oldest_packet(void) {
    if (!packet_head) {
        return;
    }
    
    packet_entry_t *old = packet_head;
    packet_head = old->next;
    
    if (packet_head) {
        packet_head->prev = NULL;
    } else {
        packet_tail = NULL;
    }
    
    free_packet(old);
    packet_count--;
}

/**
 * Cleanup and free all packet buffer memory
 */
void inspect_cleanup(void) {
    while (packet_head) {
        remove_oldest_packet();
    }
    next_packet_id = 1;
}

/**
 * Add a packet to the buffer
 */
void inspect_add_packet(packet_entry_t *packet) {
    if (!packet) {
        return;
    }
    
    pthread_mutex_lock(&packet_mutex);
    
    // Assign ID
    packet->id = next_packet_id++;
    packet->next = NULL;
    packet->prev = packet_tail;
    
    // Remove oldest if at capacity
    uint32_t max = config.max_packets > 0 ? config.max_packets : DEFAULT_MAX_PACKETS;
    while (packet_count >= max) {
        remove_oldest_packet();
    }
    
    // Add to end
    if (packet_tail) {
        packet_tail->next = packet;
    }
    packet_tail = packet;
    
    if (!packet_head) {
        packet_head = packet;
    }
    
    packet_count++;
    
    pthread_mutex_unlock(&packet_mutex);
}

/**
 * Get a packet by ID
 */
packet_entry_t* inspect_get_packet(uint32_t id) {
    pthread_mutex_lock(&packet_mutex);
    
    packet_entry_t *pkt = packet_head;
    while (pkt) {
        if (pkt->id == id) {
            pthread_mutex_unlock(&packet_mutex);
            return pkt;
        }
        pkt = pkt->next;
    }
    
    pthread_mutex_unlock(&packet_mutex);
    return NULL;
}

/**
 * Get packet count
 */
uint32_t inspect_get_count(void) {
    return packet_count;
}

/**
 * Get first packet
 */
packet_entry_t* inspect_get_first(void) {
    return packet_head;
}

/**
 * Get last packet
 */
packet_entry_t* inspect_get_last(void) {
    return packet_tail;
}

/**
 * Display Ethernet header
 */
void inspect_show_ethernet(const uint8_t *data, uint16_t length) {
    if (length < sizeof(struct ethhdr)) {
        printf("  \033[1;31m[ETHERNET] Truncated\033[0m\n");
        return;
    }
    
    struct ethhdr *eth = (struct ethhdr *)data;
    
    printf("\n  \033[1;35m═══ ETHERNET HEADER ═══\033[0m\n");
    printf("    Destination MAC: %02x:%02x:%02x:%02x:%02x:%02x\n",
           eth->h_dest[0], eth->h_dest[1], eth->h_dest[2],
           eth->h_dest[3], eth->h_dest[4], eth->h_dest[5]);
    printf("    Source MAC:      %02x:%02x:%02x:%02x:%02x:%02x\n",
           eth->h_source[0], eth->h_source[1], eth->h_source[2],
           eth->h_source[3], eth->h_source[4], eth->h_source[5]);
    printf("    EtherType:       0x%04x", ntohs(eth->h_proto));
    
    switch (ntohs(eth->h_proto)) {
        case ETH_P_IP:    printf(" (IPv4)\n"); break;
        case ETH_P_IPV6:  printf(" (IPv6)\n"); break;
        case ETH_P_ARP:   printf(" (ARP)\n"); break;
        default:          printf("\n"); break;
    }
}

/**
 * Display IP header
 */
void inspect_show_ip(const uint8_t *data, uint16_t length) {
    if (length < sizeof(struct iphdr)) {
        printf("  \033[1;31m[IP] Truncated\033[0m\n");
        return;
    }
    
    struct iphdr *ip = (struct iphdr *)data;
    struct in_addr src, dst;
    src.s_addr = ip->saddr;
    dst.s_addr = ip->daddr;
    
    printf("\n  \033[1;34m═══ IP HEADER ═══\033[0m\n");
    printf("    Version:         %d\n", ip->version);
    printf("    Header Length:   %d bytes\n", ip->ihl * 4);
    printf("    Total Length:    %d bytes\n", ntohs(ip->tot_len));
    printf("    TTL:             %d\n", ip->ttl);
    printf("    Protocol:        %d", ip->protocol);
    
    switch (ip->protocol) {
        case IP_PROTO_TCP:  printf(" (TCP)\n"); break;
        case IP_PROTO_UDP:  printf(" (UDP)\n"); break;
        case IP_PROTO_ICMP: printf(" (ICMP)\n"); break;
        default:            printf("\n"); break;
    }
    
    printf("    Source IP:       %s\n", inet_ntoa(src));
    printf("    Destination IP:  %s\n", inet_ntoa(dst));
}

/**
 * Display TCP header
 */
void inspect_show_tcp(const uint8_t *data, uint16_t length) {
    if (length < sizeof(struct tcphdr)) {
        printf("  \033[1;31m[TCP] Truncated\033[0m\n");
        return;
    }
    
    struct tcphdr *tcp = (struct tcphdr *)data;
    
    printf("\n  \033[1;32m═══ TCP HEADER ═══\033[0m\n");
    printf("    Source Port:     %d\n", ntohs(tcp->source));
    printf("    Dest Port:       %d\n", ntohs(tcp->dest));
    printf("    Sequence:        %u\n", ntohl(tcp->seq));
    printf("    Acknowledgment:  %u\n", ntohl(tcp->ack_seq));
    printf("    Data Offset:     %d bytes\n", tcp->doff * 4);
    printf("    Flags:           ");
    
    if (tcp->syn) printf("SYN ");
    if (tcp->ack) printf("ACK ");
    if (tcp->fin) printf("FIN ");
    if (tcp->rst) printf("RST ");
    if (tcp->psh) printf("PSH ");
    if (tcp->urg) printf("URG ");
    printf("\n");
    
    printf("    Window:          %d\n", ntohs(tcp->window));
}

/**
 * Display UDP header
 */
void inspect_show_udp(const uint8_t *data, uint16_t length) {
    if (length < sizeof(struct udphdr)) {
        printf("  \033[1;31m[UDP] Truncated\033[0m\n");
        return;
    }
    
    struct udphdr *udp = (struct udphdr *)data;
    
    printf("\n  \033[1;33m═══ UDP HEADER ═══\033[0m\n");
    printf("    Source Port:     %d\n", ntohs(udp->source));
    printf("    Dest Port:       %d\n", ntohs(udp->dest));
    printf("    Length:          %d\n", ntohs(udp->len));
}

/**
 * Display detailed packet information
 */
void inspect_show_packet(uint32_t id) {
    packet_entry_t *pkt = inspect_get_packet(id);
    
    if (!pkt) {
        printf("\033[1;31m[INSPECT] Packet #%u not found\033[0m\n", id);
        return;
    }
    
    printf("\n\033[1;36m╔══════════════════════════════════════════════════════════════╗\033[0m\n");
    printf("\033[1;36m║                      PACKET #%-6u                          ║\033[0m\n", pkt->id);
    printf("\033[1;36m╚══════════════════════════════════════════════════════════════╝\033[0m\n");
    
    // Basic info
    printf("\n  \033[1;37m═══ SUMMARY ═══\033[0m\n");
    printf("    Timestamp:       %ld.%06ld\n", pkt->timestamp.tv_sec, pkt->timestamp.tv_usec);
    printf("    Length:          %d bytes (captured: %d)\n", pkt->length, pkt->captured_length);
    
    struct in_addr src, dst;
    src.s_addr = pkt->src_ip;
    dst.s_addr = pkt->dst_ip;
    printf("    Flow:            %s:%d -> %s:%d\n", 
           inet_ntoa(src), pkt->src_port,
           inet_ntoa(dst), pkt->dst_port);
    printf("    Protocol:        %s", filter_get_protocol_name(
        pkt->ip_protocol == IP_PROTO_TCP ? PROTO_TCP :
        pkt->ip_protocol == IP_PROTO_UDP ? PROTO_UDP :
        pkt->ip_protocol == IP_PROTO_ICMP ? PROTO_ICMP : PROTO_OTHER));
    
    if (pkt->app_protocol != PROTO_NONE) {
        printf(" / %s", filter_get_protocol_name(pkt->app_protocol));
    }
    printf("\n");
    
    // Layer breakdown
    if (pkt->data && pkt->captured_length > 0) {
        inspect_show_ethernet(pkt->data, pkt->captured_length);
        
        if (pkt->captured_length > sizeof(struct ethhdr)) {
            const uint8_t *ip_data = pkt->data + sizeof(struct ethhdr);
            uint16_t ip_len = pkt->captured_length - sizeof(struct ethhdr);
            
            inspect_show_ip(ip_data, ip_len);
            
            struct iphdr *ip = (struct iphdr *)ip_data;
            uint16_t ip_hdr_len = ip->ihl * 4;
            
            if (ip_len > ip_hdr_len) {
                const uint8_t *trans_data = ip_data + ip_hdr_len;
                uint16_t trans_len = ip_len - ip_hdr_len;
                
                if (ip->protocol == IP_PROTO_TCP) {
                    inspect_show_tcp(trans_data, trans_len);
                } else if (ip->protocol == IP_PROTO_UDP) {
                    inspect_show_udp(trans_data, trans_len);
                }
            }
        }
        
        // Hex dump of first 128 bytes
        printf("\n  \033[1;37m═══ HEX DUMP ═══\033[0m\n");
        int dump_size = pkt->captured_length > 128 ? 128 : pkt->captured_length;
        hex_dump(pkt->data, dump_size);
    }
    
    printf("\n");
}

/**
 * List packet summaries
 */
void inspect_list(uint32_t start, uint32_t count) {
    printf("\n\033[1;36m╔══════════════════════════════════════════════════════════════════════════╗\033[0m\n");
    printf("\033[1;36m║  ID    │ PROTO │    SOURCE         →      DESTINATION    │  LEN  ║\033[0m\n");
    printf("\033[1;36m╠══════════════════════════════════════════════════════════════════════════╣\033[0m\n");
    
    pthread_mutex_lock(&packet_mutex);
    
    packet_entry_t *pkt = packet_head;
    uint32_t shown = 0;
    
    // Skip to start
    while (pkt && pkt->id < start) {
        pkt = pkt->next;
    }
    
    while (pkt && shown < count) {
        struct in_addr src, dst;
        src.s_addr = pkt->src_ip;
        dst.s_addr = pkt->dst_ip;
        
        const char *proto_str = filter_get_protocol_name(
            pkt->ip_protocol == IP_PROTO_TCP ? PROTO_TCP :
            pkt->ip_protocol == IP_PROTO_UDP ? PROTO_UDP :
            pkt->ip_protocol == IP_PROTO_ICMP ? PROTO_ICMP : PROTO_OTHER);
        
        char *color = "\033[0m";
        if (pkt->ip_protocol == IP_PROTO_TCP) color = "\033[1;32m";
        else if (pkt->ip_protocol == IP_PROTO_UDP) color = "\033[1;34m";
        else if (pkt->ip_protocol == IP_PROTO_ICMP) color = "\033[1;33m";
        
        char src_str[24], dst_str[24];
        snprintf(src_str, sizeof(src_str), "%s:%d", inet_ntoa(src), pkt->src_port);
        snprintf(dst_str, sizeof(dst_str), "%s:%d", inet_ntoa(dst), pkt->dst_port);
        
        printf("%s║ %5u │ %-5s │ %-17s → %-17s │ %5d ║\033[0m\n",
               color, pkt->id, proto_str, src_str, dst_str, pkt->length);
        
        pkt = pkt->next;
        shown++;
    }
    
    pthread_mutex_unlock(&packet_mutex);
    
    printf("\033[1;36m╚══════════════════════════════════════════════════════════════════════════╝\033[0m\n");
    printf("  Showing %u of %u packets\n\n", shown, packet_count);
}

/**
 * Enter interactive inspect mode
 */
void inspect_enter(void) {
    if (packet_count == 0) {
        printf("\033[1;33m[INSPECT] No packets captured yet\033[0m\n");
        return;
    }
    
    state.in_inspect_mode = true;
    state.current_packet_id = packet_head ? packet_head->id : 0;
    
    printf("\n\033[1;36m╔══════════════════════════════════════════════════════════════╗\033[0m\n");
    printf("\033[1;36m║                    INSPECT MODE                              ║\033[0m\n");
    printf("\033[1;36m║  Commands: n(ext) p(rev) g(oto) d(etail) l(ist) q(uit)       ║\033[0m\n");
    printf("\033[1;36m╚══════════════════════════════════════════════════════════════╝\033[0m\n\n");
    
    char cmd[64];
    
    while (state.in_inspect_mode) {
        printf("\n\033[1;35m[inspect]\033[0m\033[1;37m::\033[0m\033[0;90m#%u\033[0m ", state.current_packet_id);
        
        if (fgets(cmd, sizeof(cmd), stdin) == NULL) {
            break;
        }
        cmd[strcspn(cmd, "\n")] = 0;
        
        // Trim whitespace
        char *trimmed = cmd;
        while (isspace((unsigned char)*trimmed)) trimmed++;
        
        if (strlen(trimmed) == 0) {
            continue;
        }
        
        if (strcmp(trimmed, "q") == 0 || strcmp(trimmed, "quit") == 0) {
            state.in_inspect_mode = false;
            printf("\033[1;32m[INSPECT] Exiting inspect mode\033[0m\n");
        }
        else if (strcmp(trimmed, "n") == 0 || strcmp(trimmed, "next") == 0) {
            packet_entry_t *pkt = inspect_get_packet(state.current_packet_id);
            if (pkt && pkt->next) {
                state.current_packet_id = pkt->next->id;
                inspect_show_packet(state.current_packet_id);
            } else {
                printf("\033[1;33m[INSPECT] Already at last packet\033[0m\n");
            }
        }
        else if (strcmp(trimmed, "p") == 0 || strcmp(trimmed, "prev") == 0) {
            packet_entry_t *pkt = inspect_get_packet(state.current_packet_id);
            if (pkt && pkt->prev) {
                state.current_packet_id = pkt->prev->id;
                inspect_show_packet(state.current_packet_id);
            } else {
                printf("\033[1;33m[INSPECT] Already at first packet\033[0m\n");
            }
        }
        else if (strcmp(trimmed, "d") == 0 || strcmp(trimmed, "detail") == 0) {
            inspect_show_packet(state.current_packet_id);
        }
        else if (strcmp(trimmed, "l") == 0 || strcmp(trimmed, "list") == 0) {
            inspect_list(state.current_packet_id, 20);
        }
        else if (strncmp(trimmed, "l ", 2) == 0 || strncmp(trimmed, "list ", 5) == 0) {
            uint32_t count = 20;
            char *arg = strchr(trimmed, ' ');
            if (arg) {
                count = (uint32_t)atoi(arg + 1);
                if (count == 0 || count > 100) count = 20;
            }
            inspect_list(state.current_packet_id, count);
        }
        else if (strncmp(trimmed, "g ", 2) == 0 || strncmp(trimmed, "goto ", 5) == 0) {
            char *arg = strchr(trimmed, ' ');
            if (arg) {
                uint32_t id = (uint32_t)atoi(arg + 1);
                packet_entry_t *pkt = inspect_get_packet(id);
                if (pkt) {
                    state.current_packet_id = id;
                    inspect_show_packet(state.current_packet_id);
                } else {
                    printf("\033[1;31m[INSPECT] Packet #%u not found\033[0m\n", id);
                }
            }
        }
        else if (strcmp(trimmed, "first") == 0) {
            if (packet_head) {
                state.current_packet_id = packet_head->id;
                inspect_show_packet(state.current_packet_id);
            }
        }
        else if (strcmp(trimmed, "last") == 0) {
            if (packet_tail) {
                state.current_packet_id = packet_tail->id;
                inspect_show_packet(state.current_packet_id);
            }
        }
        else if (strcmp(trimmed, "help") == 0 || strcmp(trimmed, "?") == 0) {
            printf("\n  \033[1;36mInspect Mode Commands:\033[0m\n");
            printf("    n, next      - Show next packet\n");
            printf("    p, prev      - Show previous packet\n");
            printf("    g, goto <id> - Jump to packet ID\n");
            printf("    d, detail    - Show current packet details\n");
            printf("    l, list [n]  - List n packets (default 20)\n");
            printf("    first        - Jump to first packet\n");
            printf("    last         - Jump to last packet\n");
            printf("    q, quit      - Exit inspect mode\n\n");
        }
        else {
            printf("\033[1;33m[INSPECT] Unknown command: %s (try 'help')\033[0m\n", trimmed);
        }
    }
}
