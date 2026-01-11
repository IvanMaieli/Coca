#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <linux/if_packet.h>
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <arpa/inet.h>
#include <pthread.h>
#include <sys/time.h>
#include <errno.h>

#include "coke.h"
#include "filter.h"
#include "inspect.h"
#include "composer.h"
#include "security.h"

// External conversation counter (from composer.c)
extern uint32_t total_conversations;

/* =============================================================================
 * SNIFFER MODULE
 * ============================================================================= */

/**
 * Create a packet entry from raw data
 */
static packet_entry_t* create_packet_entry(const uint8_t *buffer, int data_size) {
    if (!buffer || data_size <= 0) {
        return NULL;
    }
    
    packet_entry_t *pkt = (packet_entry_t *)calloc(1, sizeof(packet_entry_t));
    if (!pkt) {
        return NULL;
    }
    
    // Timestamp
    gettimeofday(&pkt->timestamp, NULL);
    
    // Length
    pkt->length = (uint16_t)data_size;
    
    // Determine how much to capture
    uint32_t max_capture = config.max_packet_size > 0 ? config.max_packet_size : MAX_PACKET_SIZE;
    uint32_t udata_size = (uint32_t)data_size;
    pkt->captured_length = (uint16_t)(udata_size > max_capture ? max_capture : udata_size);
    
    // Copy raw data
    pkt->data = (uint8_t *)malloc(pkt->captured_length);
    if (!pkt->data) {
        free(pkt);
        return NULL;
    }
    memcpy(pkt->data, buffer, pkt->captured_length);
    
    // Parse Ethernet header
    if (pkt->captured_length < sizeof(struct ethhdr)) {
        return pkt;  // Return with minimal data
    }
    
    struct ethhdr *eth = (struct ethhdr *)buffer;
    
    // Only process IP packets for now
    if (ntohs(eth->h_proto) != ETH_P_IP) {
        // ARP detection
        if (ntohs(eth->h_proto) == ETH_P_ARP) {
            pkt->app_protocol = PROTO_ARP;
        }
        return pkt;
    }
    
    // Parse IP header
    if (pkt->captured_length < sizeof(struct ethhdr) + sizeof(struct iphdr)) {
        return pkt;
    }
    
    struct iphdr *ip = (struct iphdr *)(buffer + sizeof(struct ethhdr));
    
    pkt->src_ip = ip->saddr;
    pkt->dst_ip = ip->daddr;
    pkt->ip_protocol = ip->protocol;
    
    // Parse transport header
    uint16_t ip_hdr_len = ip->ihl * 4;
    const uint8_t *transport = buffer + sizeof(struct ethhdr) + ip_hdr_len;
    
    if (ip->protocol == IP_PROTO_TCP) {
        if (pkt->captured_length >= sizeof(struct ethhdr) + ip_hdr_len + sizeof(struct tcphdr)) {
            struct tcphdr *tcp = (struct tcphdr *)transport;
            pkt->src_port = ntohs(tcp->source);
            pkt->dst_port = ntohs(tcp->dest);
        }
    } else if (ip->protocol == IP_PROTO_UDP) {
        if (pkt->captured_length >= sizeof(struct ethhdr) + ip_hdr_len + sizeof(struct udphdr)) {
            struct udphdr *udp = (struct udphdr *)transport;
            pkt->src_port = ntohs(udp->source);
            pkt->dst_port = ntohs(udp->dest);
        }
    }
    
    // Detect application protocol
    pkt->app_protocol = filter_detect_app_protocol(pkt);
    
    return pkt;
}

/**
 * Main sniffer loop
 */
void* sniffer_loop(void* arg) {
    (void)arg;
    
    int sock_raw;
    unsigned char *buffer = NULL;
    struct sockaddr_storage saddr;
    socklen_t saddr_size = sizeof(saddr);
    
    // Allocate receive buffer
    buffer = (unsigned char *)malloc(MAX_PACKET_SIZE);
    if (!buffer) {
        fprintf(stderr, "\033[1;31m[ERROR] Memory allocation failed\033[0m\n");
        is_sniffing = 0;
        pthread_exit(NULL);
    }
    
    // Create raw socket
    sock_raw = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (sock_raw < 0) {
        fprintf(stderr, "\033[1;31m[ERROR] Socket access denied: %s\033[0m\n", strerror(errno));
        fprintf(stderr, "\033[1;33m[HINT] Try running with sudo or set CAP_NET_RAW capability\033[0m\n");
        free(buffer);
        is_sniffing = 0;
        pthread_exit(NULL);
    }
    
    // Drop privileges after socket creation
    if (!security_drop_privileges()) {
        fprintf(stderr, "\033[1;33m[SECURITY] Warning: Could not drop privileges\033[0m\n");
    }
    
    printf("\033[1;32m[*] GATEWAY OPENED. LISTENING...\033[0m\n");
    
    // Show filter status
    if (config.filter_mask != PROTO_ALL) {
        char filter_desc[128];
        filter_describe(config.filter_mask, filter_desc, sizeof(filter_desc));
        printf("\033[1;33m[*] Filter active: %s\033[0m\n", filter_desc);
    }
    
    printf("\n");
    
    while (is_sniffing) {
        int data_size = recvfrom(sock_raw, buffer, MAX_PACKET_SIZE, 0, 
                                  (struct sockaddr *)&saddr, &saddr_size);
        
        if (data_size < 0) {
            if (errno == EINTR) {
                continue;  // Interrupted by signal
            }
            continue;
        }
        
        if (data_size < (int)sizeof(struct ethhdr)) {
            continue;  // Too small
        }
        
        // Create packet entry
        packet_entry_t *pkt = create_packet_entry(buffer, data_size);
        if (!pkt) {
            continue;
        }
        
        // Apply filter
        if (!filter_match(pkt, config.filter_mask)) {
            state.packets_filtered++;
            free(pkt->data);
            free(pkt);
            continue;
        }
        
        // Update stats
        state.packets_captured++;
        
        // Track in composer
        composer_track_packet(pkt);
        
        // Add to inspect buffer
        inspect_add_packet(pkt);
        
        // Display packet (if not in inspect mode)
        if (!state.in_inspect_mode) {
            const char *color = "\033[0m";
            const char *proto_str = "???";
            
            if (pkt->ip_protocol == IP_PROTO_TCP) {
                color = "\033[1;32m";
                proto_str = "TCP";
            } else if (pkt->ip_protocol == IP_PROTO_UDP) {
                color = "\033[1;34m";
                proto_str = "UDP";
            } else if (pkt->ip_protocol == IP_PROTO_ICMP) {
                color = "\033[1;33m";
                proto_str = "ICMP";
            } else if (pkt->app_protocol == PROTO_ARP) {
                color = "\033[1;35m";
                proto_str = "ARP";
            }
            
            // Add app protocol indicator
            char proto_full[16];
            if (pkt->app_protocol != PROTO_NONE && pkt->app_protocol != PROTO_ARP) {
                snprintf(proto_full, sizeof(proto_full), "%s/%s", 
                         proto_str, filter_get_protocol_name(pkt->app_protocol));
            } else {
                snprintf(proto_full, sizeof(proto_full), "%s", proto_str);
            }
            
            struct in_addr src, dst;
            src.s_addr = pkt->src_ip;
            dst.s_addr = pkt->dst_ip;
            
            printf("%s[#%-5u] [%-8s] %s:%d -> %s:%d | Len: %d\033[0m\n",
                   color, pkt->id, proto_full,
                   inet_ntoa(src), pkt->src_port,
                   inet_ntoa(dst), pkt->dst_port,
                   data_size);
            
            if (config.hex_view) {
                hex_dump(buffer, data_size > 64 ? 64 : data_size);
            }
        }
    }
    
    printf("\n\033[1;31m[*] SNIFFER STOPPED\033[0m\n");
    printf("    Captured: %u packets | Filtered: %u | Conversations: %u\n\n",
           state.packets_captured, state.packets_filtered, total_conversations);
    
    close(sock_raw);
    free(buffer);
    pthread_exit(NULL);
}


