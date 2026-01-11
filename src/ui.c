#include <stdio.h>
#include <ctype.h>
#include <string.h>

#include "coke.h"
#include "filter.h"

/* =============================================================================
 * UI MODULE
 * ============================================================================= */

/**
 * Print application banner
 */
void print_banner(void) {
    printf("\033[2J\033[H");  // Clear screen
    printf("\033[1;36m");
    printf("\n");
    printf("   ██████╗ ██████╗ ██╗  ██╗███████╗\n");
    printf("  ██╔════╝██╔═══██╗██║ ██╔╝██╔════╝\n");
    printf("  ██║     ██║   ██║█████╔╝ █████╗  \n");
    printf("  ██║     ██║   ██║██╔═██╗ ██╔══╝  \n");
    printf("  ╚██████╗╚██████╔╝██║  ██╗███████╗\n");
    printf("   ╚═════╝ ╚═════╝ ╚═╝  ╚═╝╚══════╝\n");
    printf("\033[0m");
    printf("\n  \033[1;37mPacket Sniffer v2.0\033[0m");
    printf("  \033[0;90m│ Raw Socket Engine │ Ctrl+C to stop capture\033[0m\n");
    printf("  \033[0;90m───────────────────────────────────────────────────────────\033[0m\n");
    printf("\n");
}

/**
 * Print help information
 */
void print_help(void) {
    printf("\n");
    printf("  \033[1;36m╔══════════════════════════════════════════════════════════════╗\033[0m\n");
    printf("  \033[1;36m║                          COMMANDS                            ║\033[0m\n");
    printf("  \033[1;36m╠══════════════════════════════════════════════════════════════╣\033[0m\n");
    printf("  \033[1;36m║\033[0m  \033[1;32mCapture:\033[0m                                                   \033[1;36m║\033[0m\n");
    printf("  \033[1;36m║\033[0m    start              Start packet capture                   \033[1;36m║\033[0m\n");
    printf("  \033[1;36m║\033[0m    stop               Stop packet capture (or Ctrl+C)       \033[1;36m║\033[0m\n");
    printf("  \033[1;36m║\033[0m                                                              \033[1;36m║\033[0m\n");
    printf("  \033[1;36m║\033[0m  \033[1;33mFiltering:\033[0m                                                 \033[1;36m║\033[0m\n");
    printf("  \033[1;36m║\033[0m    filter <protos>    Set filter (e.g., \"filter tcp,udp\")   \033[1;36m║\033[0m\n");
    printf("  \033[1;36m║\033[0m    filter clear       Remove all filters                    \033[1;36m║\033[0m\n");
    printf("  \033[1;36m║\033[0m    filter show        Display current filters               \033[1;36m║\033[0m\n");
    printf("  \033[1;36m║\033[0m                                                              \033[1;36m║\033[0m\n");
    printf("  \033[1;36m║\033[0m  \033[1;35mInspect:\033[0m                                                   \033[1;36m║\033[0m\n");
    printf("  \033[1;36m║\033[0m    inspect            Enter packet inspection mode          \033[1;36m║\033[0m\n");
    printf("  \033[1;36m║\033[0m    show <id>          Show packet details                   \033[1;36m║\033[0m\n");
    printf("  \033[1;36m║\033[0m    list [n]           List last n packets (default 20)     \033[1;36m║\033[0m\n");
    printf("  \033[1;36m║\033[0m                                                              \033[1;36m║\033[0m\n");
    printf("  \033[1;36m║\033[0m  \033[1;34mCompose:\033[0m                                                   \033[1;36m║\033[0m\n");
    printf("  \033[1;36m║\033[0m    compose            List all conversations                \033[1;36m║\033[0m\n");
    printf("  \033[1;36m║\033[0m    compose <id>       Show conversation details             \033[1;36m║\033[0m\n");
    printf("  \033[1;36m║\033[0m    compose stats      Conversation statistics               \033[1;36m║\033[0m\n");
    printf("  \033[1;36m║\033[0m    compose export <id> <file>  Export conversation          \033[1;36m║\033[0m\n");
    printf("  \033[1;36m║\033[0m                                                              \033[1;36m║\033[0m\n");
    printf("  \033[1;36m║\033[0m  \033[1;37mOther:\033[0m                                                     \033[1;36m║\033[0m\n");
    printf("  \033[1;36m║\033[0m    hex                Toggle hex dump view                  \033[1;36m║\033[0m\n");
    printf("  \033[1;36m║\033[0m    status             Show capture status                   \033[1;36m║\033[0m\n");
    printf("  \033[1;36m║\033[0m    clear              Clear screen                          \033[1;36m║\033[0m\n");
    printf("  \033[1;36m║\033[0m    help               Show this help                        \033[1;36m║\033[0m\n");
    printf("  \033[1;36m║\033[0m    exit               Quit                                  \033[1;36m║\033[0m\n");
    printf("  \033[1;36m╚══════════════════════════════════════════════════════════════╝\033[0m\n");
    printf("\n");
    printf("  \033[1;37mProtocols:\033[0m tcp, udp, icmp, arp, dns, http, https/tls, ssh\n");
    printf("\n");
}

/**
 * Print current status
 */
void print_status(void) {
    printf("\n");
    printf("  \033[1;36m═══ STATUS ═══\033[0m\n");
    printf("    Sniffing:        %s\n", is_sniffing ? "\033[1;32mACTIVE\033[0m" : "\033[1;31mSTOPPED\033[0m");
    printf("    Packets captured: %u\n", state.packets_captured);
    printf("    Packets filtered: %u\n", state.packets_filtered);
    printf("    Conversations:    %u\n", state.conversations_count);
    printf("    Hex dump:         %s\n", config.hex_view ? "ON" : "OFF");
    
    if (config.filter_mask != PROTO_ALL) {
        char filter_desc[128];
        filter_describe(config.filter_mask, filter_desc, sizeof(filter_desc));
        printf("    Active filter:    %s\n", filter_desc);
    } else {
        printf("    Active filter:    NONE (accepting all)\n");
    }
    printf("\n");
}

/**
 * Hex dump utility function
 */
void hex_dump(const unsigned char *data, int size) {
    char ascii[17];
    int i, j;
    ascii[16] = '\0';

    printf("\033[0;37m");
    for (i = 0; i < size; ++i) {
        if (i % 16 == 0) {
            printf("   0x%04x: ", i);
        }
        printf("%02X ", data[i]);
        
        if (isprint(data[i])) {
            ascii[i % 16] = data[i];
        } else {
            ascii[i % 16] = '.';
        }

        if ((i + 1) % 16 == 0) {
            printf("  |%s|\n", ascii);
        } else if (i + 1 == size) {
            ascii[(i + 1) % 16] = '\0';
            for (j = (i + 1) % 16; j < 16; ++j) {
                printf("   ");
            }
            printf("  |%s|\n", ascii);
        }
    }
    printf("\033[0m\n");
}
