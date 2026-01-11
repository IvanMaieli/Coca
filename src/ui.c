#include <stdio.h>
#include <ctype.h>
#include <string.h>

#include "coke.h"
#include "filter.h"

/* =============================================================================
 * UI MODULE - Clean ASCII-Compatible Design
 * ============================================================================= */

// ANSI color codes
#define RESET       "\033[0m"
#define BOLD        "\033[1m"
#define DIM         "\033[2m"

// Colors
#define RED         "\033[1;31m"
#define GREEN       "\033[1;32m"
#define YELLOW      "\033[1;33m"
#define BLUE        "\033[1;34m"
#define MAGENTA     "\033[1;35m"
#define CYAN        "\033[1;36m"
#define WHITE       "\033[1;37m"
#define GRAY        "\033[0;90m"

/**
 * Print application banner
 */
void print_banner(void) {
    printf("\033[2J\033[H");  // Clear screen
    printf("\n");
    printf(CYAN);
    printf("     ______      __        \n");
    printf("    / ____/___  / /_____   \n");
    printf("   / /   / __ \\/ //_/ _ \\  \n");
    printf("  / /___/ /_/ / ,< /  __/  \n");
    printf("  \\____/\\____/_/|_|\\___/   \n");
    printf(RESET);
    printf("\n");
    printf("  " WHITE "Packet Sniffer v2.0" RESET);
    printf("  " GRAY "|" RESET);
    printf("  " GREEN "Raw Socket Engine" RESET);
    printf("  " GRAY "|" RESET);
    printf("  " YELLOW "Ctrl+C" RESET " to stop\n");
    printf("  " GRAY "------------------------------------------------------" RESET "\n");
    printf("\n");
}

/**
 * Print help information
 */
void print_help(void) {
    printf("\n");
    printf("  " CYAN "============================================================" RESET "\n");
    printf("  " CYAN "|" RESET WHITE "                     COMMAND REFERENCE                    " RESET CYAN "|" RESET "\n");
    printf("  " CYAN "============================================================" RESET "\n");
    printf("\n");
    
    // Capture
    printf("  " GREEN "[CAPTURE]" RESET "\n");
    printf("    " WHITE "start" RESET "              Start sniffing packets\n");
    printf("    " WHITE "stop" RESET "               Stop capture (or Ctrl+C)\n");
    printf("\n");
    
    // Filtering
    printf("  " YELLOW "[FILTERING]" RESET "\n");
    printf("    " WHITE "filter <protos>" RESET "    Set filter (e.g., " DIM "filter tcp,udp,dns" RESET ")\n");
    printf("    " WHITE "filter clear" RESET "       Remove all filters\n");
    printf("    " WHITE "filter show" RESET "        Display active filters\n");
    printf("\n");
    
    // Inspect
    printf("  " MAGENTA "[INSPECT]" RESET "\n");
    printf("    " WHITE "inspect" RESET "            Enter interactive inspection mode\n");
    printf("    " WHITE "show <id>" RESET "          Show packet details\n");
    printf("    " WHITE "list [n]" RESET "           List last n packets (default 20)\n");
    printf("\n");
    
    // Compose
    printf("  " BLUE "[COMPOSE]" RESET "\n");
    printf("    " WHITE "compose" RESET "            List all conversations\n");
    printf("    " WHITE "compose <id>" RESET "       Show conversation details\n");
    printf("    " WHITE "compose stats" RESET "      Traffic statistics\n");
    printf("\n");
    
    // Other
    printf("  " WHITE "[OTHER]" RESET "\n");
    printf("    " WHITE "hex" RESET "      Toggle hex dump    " WHITE "status" RESET "   Show status\n");
    printf("    " WHITE "clear" RESET "    Clear screen       " WHITE "exit" RESET "     Quit\n");
    printf("\n");
    
    printf("  " CYAN "============================================================" RESET "\n");
    printf("\n");
    printf("  " WHITE "Protocols:" RESET " ");
    printf(GREEN "tcp" RESET ", ");
    printf(BLUE "udp" RESET ", ");
    printf(YELLOW "icmp" RESET ", ");
    printf(MAGENTA "arp" RESET ", ");
    printf(CYAN "dns" RESET ", ");
    printf(GREEN "http" RESET ", ");
    printf(YELLOW "tls" RESET ", ");
    printf(RED "ssh" RESET "\n\n");
}

/**
 * Print current status
 */
void print_status(void) {
    printf("\n");
    printf("  " CYAN "==================== STATUS ====================" RESET "\n\n");
    
    // Sniffing status
    printf("    Sniffing:        ");
    if (is_sniffing) {
        printf(GREEN "[ACTIVE]" RESET "\n");
    } else {
        printf(RED "[STOPPED]" RESET "\n");
    }
    
    // Statistics
    printf("    Packets captured: " GREEN "%u" RESET "\n", state.packets_captured);
    printf("    Packets filtered: " YELLOW "%u" RESET "\n", state.packets_filtered);
    printf("    Conversations:    " CYAN "%u" RESET "\n", state.conversations_count);
    printf("    Hex dump:         %s\n", config.hex_view ? GREEN "ON" RESET : RED "OFF" RESET);
    
    // Filter
    printf("    Active filter:    ");
    if (config.filter_mask == PROTO_ALL) {
        printf(DIM "none (accepting all)" RESET "\n");
    } else {
        char filter_desc[128];
        filter_describe(config.filter_mask, filter_desc, sizeof(filter_desc));
        printf(YELLOW "%s" RESET "\n", filter_desc);
    }
    
    printf("\n  " CYAN "================================================" RESET "\n\n");
}

/**
 * Hex dump utility function
 */
void hex_dump(const unsigned char *data, int size) {
    char ascii[17];
    int i, j;
    ascii[16] = '\0';

    printf(GRAY);
    printf("\n");
    printf("         00 01 02 03 04 05 06 07  08 09 0A 0B 0C 0D 0E 0F   ASCII\n");
    printf("         -------------------------------------------------------\n");
    
    for (i = 0; i < size; ++i) {
        if (i % 16 == 0) {
            printf("  %04x:  ", i);
        }
        
        // Add extra space in middle
        if (i % 16 == 8) {
            printf(" ");
        }
        
        printf("%02X ", data[i]);
        
        if (isprint(data[i])) {
            ascii[i % 16] = data[i];
        } else {
            ascii[i % 16] = '.';
        }

        if ((i + 1) % 16 == 0) {
            printf("  %s\n", ascii);
        } else if (i + 1 == size) {
            ascii[(i + 1) % 16] = '\0';
            // Pad remaining hex positions
            for (j = (i + 1) % 16; j < 16; ++j) {
                printf("   ");
                if (j == 8) printf(" ");
            }
            printf("  %s\n", ascii);
        }
    }
    printf(RESET "\n");
}
