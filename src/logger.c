#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <sys/time.h>
#include <arpa/inet.h>

#include "coke.h"
#include "inspect.h"
#include "filter.h"

/* =============================================================================
 * LOGGER MODULE - PCAP Export
 * ============================================================================= */

// PCAP File Header
struct pcap_hdr {
    uint32_t magic_number;   /* 0xa1b2c3d4 */
    uint16_t version_major;  /* 2 */
    uint16_t version_minor;  /* 4 */
    int32_t  thiszone;       /* GMT to local correction */
    uint32_t sigfigs;        /* accuracy of timestamps */
    uint32_t snaplen;        /* max length of captured packets */
    uint32_t network;        /* data link type (1 = Ethernet) */
};

// PCAP Packet Header
struct pcap_pkthdr {
    uint32_t ts_sec;         /* timestamp seconds */
    uint32_t ts_usec;        /* timestamp microseconds */
    uint32_t incl_len;       /* number of octets of packet saved in file */
    uint32_t orig_len;       /* actual length of packet */
};

/**
 * Initialize a PCAP file with header
 */
FILE* pcap_init(const char* filename) {
    FILE* f = fopen(filename, "wb");
    if (!f) return NULL;

    struct pcap_hdr header = {
        .magic_number = 0xa1b2c3d4,
        .version_major = 2,
        .version_minor = 4,
        .thiszone = 0,
        .sigfigs = 0,
        .snaplen = 65535,
        .network = 1  // LINKTYPE_ETHERNET
    };

    fwrite(&header, sizeof(header), 1, f);
    fflush(f);
    return f;
}

/**
 * Write a single packet to PCAP file
 */
void pcap_write_packet(FILE *f, const uint8_t *data, uint32_t length, 
                       struct timeval *ts) {
    if (!f || !data || length == 0) return;
    
    struct pcap_pkthdr pkthdr = {
        .ts_sec = (uint32_t)ts->tv_sec,
        .ts_usec = (uint32_t)ts->tv_usec,
        .incl_len = length,
        .orig_len = length
    };
    
    fwrite(&pkthdr, sizeof(pkthdr), 1, f);
    fwrite(data, 1, length, f);
    fflush(f);
}

/**
 * Save a range of packets to PCAP file
 */
bool pcap_save_range(const char *filename, uint32_t start_id, uint32_t end_id) {
    FILE *f = pcap_init(filename);
    if (!f) {
        printf("\033[1;31m[SAVE] Could not create file: %s\033[0m\n", filename);
        return false;
    }
    
    uint32_t saved = 0;
    
    for (uint32_t id = start_id; id <= end_id; id++) {
        packet_entry_t *pkt = inspect_get_packet(id);
        if (pkt && pkt->data) {
            pcap_write_packet(f, pkt->data, pkt->captured_length, &pkt->timestamp);
            saved++;
        }
    }
    
    fclose(f);
    
    printf("\033[1;32m[SAVE] Saved %u packets to %s\033[0m\n", saved, filename);
    return true;
}

/**
 * Save all packets to PCAP file
 */
bool pcap_save_all(const char *filename) {
    FILE *f = pcap_init(filename);
    if (!f) {
        printf("\033[1;31m[SAVE] Could not create file: %s\033[0m\n", filename);
        return false;
    }
    
    uint32_t saved = 0;
    packet_entry_t *pkt = inspect_get_first();
    
    while (pkt) {
        if (pkt->data) {
            pcap_write_packet(f, pkt->data, pkt->captured_length, &pkt->timestamp);
            saved++;
        }
        pkt = pkt->next;
    }
    
    fclose(f);
    
    printf("\033[1;32m[SAVE] Saved %u packets to %s\033[0m\n", saved, filename);
    return true;
}

/**
 * Export packets as text
 */
bool export_packets_text(const char *filename) {
    FILE *f = fopen(filename, "w");
    if (!f) {
        printf("\033[1;31m[EXPORT] Could not create file: %s\033[0m\n", filename);
        return false;
    }
    
    fprintf(f, "Coke Packet Export\n");
    fprintf(f, "==================\n\n");
    fprintf(f, "%-6s  %-8s  %-21s  %-21s  %s\n", 
            "ID", "PROTO", "SOURCE", "DESTINATION", "LENGTH");
    fprintf(f, "------  --------  ---------------------  ---------------------  ------\n");
    
    uint32_t count = 0;
    packet_entry_t *pkt = inspect_get_first();
    
    while (pkt) {
        const char *proto = "???";
        if (pkt->ip_protocol == IP_PROTO_TCP) proto = "TCP";
        else if (pkt->ip_protocol == IP_PROTO_UDP) proto = "UDP";
        else if (pkt->ip_protocol == IP_PROTO_ICMP) proto = "ICMP";
        
        struct in_addr src, dst;
        src.s_addr = pkt->src_ip;
        dst.s_addr = pkt->dst_ip;
        
        char src_str[24], dst_str[24];
        snprintf(src_str, sizeof(src_str), "%s:%d", inet_ntoa(src), pkt->src_port);
        snprintf(dst_str, sizeof(dst_str), "%s:%d", inet_ntoa(dst), pkt->dst_port);
        
        fprintf(f, "%-6u  %-8s  %-21s  %-21s  %d\n",
                pkt->id, proto, src_str, dst_str, pkt->length);
        
        pkt = pkt->next;
        count++;
    }
    
    fprintf(f, "\nTotal: %u packets\n", count);
    fclose(f);
    
    printf("\033[1;32m[EXPORT] Exported %u packets to %s\033[0m\n", count, filename);
    return true;
}

/**
 * Export statistics to file
 */
bool export_stats(const char *filename) {
    FILE *f = fopen(filename, "w");
    if (!f) {
        printf("\033[1;31m[EXPORT] Could not create file: %s\033[0m\n", filename);
        return false;
    }
    
    fprintf(f, "Coke Statistics Report\n");
    fprintf(f, "======================\n\n");
    fprintf(f, "Packets captured:  %u\n", state.packets_captured);
    fprintf(f, "Packets filtered:  %u\n", state.packets_filtered);
    fprintf(f, "Conversations:     %u\n", state.conversations_count);
    fprintf(f, "Packets in buffer: %u\n", inspect_get_count());
    
    // Filter info
    fprintf(f, "\nFilter: ");
    if (config.filter_mask == PROTO_ALL) {
        fprintf(f, "none (accepting all)\n");
    } else {
        char filter_desc[128];
        filter_describe(config.filter_mask, filter_desc, sizeof(filter_desc));
        fprintf(f, "%s\n", filter_desc);
    }
    
    fclose(f);
    
    printf("\033[1;32m[EXPORT] Statistics saved to %s\033[0m\n", filename);
    return true;
}
