#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <unistd.h>
#include <signal.h>
#include <ctype.h>

#include "coke.h"
#include "filter.h"
#include "inspect.h"
#include "composer.h"
#include "security.h"
#include "session.h"

/* =============================================================================
 * GLOBAL VARIABLES
 * ============================================================================= */

volatile sig_atomic_t is_sniffing = 0;
coke_config_t config;
coke_state_t state;
pthread_mutex_t packet_mutex = PTHREAD_MUTEX_INITIALIZER;
pthread_mutex_t conv_mutex = PTHREAD_MUTEX_INITIALIZER;
pthread_t sniffer_thread;

/* =============================================================================
 * SIGNAL HANDLING
 * ============================================================================= */

static void handle_sigint(int sig) {
    (void)sig;
    if (is_sniffing) {
        printf("\n\033[1;31m[!] INTERRUPT RECEIVED. STOPPING SNIFFER...\033[0m\n");
        is_sniffing = 0;
    } else if (state.in_inspect_mode) {
        printf("\n");
        state.in_inspect_mode = false;
    } else {
        printf("\n\nStay cold. ❄️\n");
        
        // Cleanup
        inspect_cleanup();
        composer_cleanup();
        
        exit(0);
    }
}

/* =============================================================================
 * COMMAND PARSING HELPERS
 * ============================================================================= */

static char* trim_whitespace(char *str) {
    if (!str) return str;
    
    // Trim leading
    while (isspace((unsigned char)*str)) str++;
    
    if (*str == '\0') return str;
    
    // Trim trailing
    char *end = str + strlen(str) - 1;
    while (end > str && isspace((unsigned char)*end)) end--;
    *(end + 1) = '\0';
    
    return str;
}

/* =============================================================================
 * MAIN FUNCTION
 * ============================================================================= */

int main(int argc, char *argv[]) {
    (void)argc;
    (void)argv;
    
    // Initialize configuration with defaults
    config.output_file = "capture.pcap";
    config.filter_mask = PROTO_ALL;
    config.verbose = false;
    config.hex_view = false;
    config.max_packets = DEFAULT_MAX_PACKETS;
    config.max_packet_size = MAX_PACKET_SIZE;
    config.interface = NULL;
    
    // Initialize state
    memset(&state, 0, sizeof(state));
    
    // Initialize security
    security_init();
    session_init();
    
    // Initialize modules
    inspect_init();
    composer_init();
    
    // Setup signal handlers
    struct sigaction sa;
    sa.sa_handler = handle_sigint;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0;
    sigaction(SIGINT, &sa, NULL);
    
    // Print banner
    print_banner();
    
    // Check capabilities
    if (!security_check_capabilities()) {
        printf("\033[1;33m[WARNING] Not running as root and CAP_NET_RAW not available.\033[0m\n");
        printf("\033[1;33m          Run with sudo or set capability: sudo setcap cap_net_raw+ep ./coke\033[0m\n\n");
    }
    
    char cmd[MAX_INPUT_LENGTH];
    
    while (1) {
        // Wait for sniffer to finish if it was running
        if (is_sniffing) {
            pthread_join(sniffer_thread, NULL);
        }
        
        // Show prompt
        printf("\n\033[1;36m[coke]\033[0m\033[1;37m::\033[0m ");
        fflush(stdout);
        
        // Read command
        if (fgets(cmd, sizeof(cmd), stdin) == NULL) {
            break;
        }
        
        // Remove newline and trim
        cmd[strcspn(cmd, "\n")] = 0;
        char *trimmed = trim_whitespace(cmd);
        
        // Skip empty commands
        if (strlen(trimmed) == 0) {
            continue;
        }
        
        // Validate input
        if (!security_validate_input(trimmed, MAX_INPUT_LENGTH - 1)) {
            printf("\033[1;31m[ERROR] Invalid input\033[0m\n");
            continue;
        }
        
        // ===== COMMAND DISPATCHER =====
        
        // Exit
        if (strcmp(trimmed, "exit") == 0 || strcmp(trimmed, "quit") == 0) {
            break;
        }
        
        // Start sniffing
        else if (strcmp(trimmed, "start") == 0) {
            if (is_sniffing) {
                printf("\033[1;33m[!] Sniffer already running\033[0m\n");
            } else {
                is_sniffing = 1;
                if (pthread_create(&sniffer_thread, NULL, sniffer_loop, NULL) != 0) {
                    perror("\033[1;31m[ERROR] Thread creation failed\033[0m");
                    is_sniffing = 0;
                }
            }
        }
        
        // Stop sniffing
        else if (strcmp(trimmed, "stop") == 0) {
            if (is_sniffing) {
                is_sniffing = 0;
                printf("\033[1;33m[!] Stopping sniffer...\033[0m\n");
            } else {
                printf("\033[1;33m[!] Sniffer is not running\033[0m\n");
            }
        }
        
        // Toggle hex view
        else if (strcmp(trimmed, "hex") == 0) {
            config.hex_view = !config.hex_view;
            printf("[Config] Hex Dump: %s\n", config.hex_view ? "ON" : "OFF");
        }
        
        // Clear screen
        else if (strcmp(trimmed, "clear") == 0) {
            print_banner();
        }
        
        // Help
        else if (strcmp(trimmed, "help") == 0 || strcmp(trimmed, "?") == 0) {
            print_help();
        }
        
        // Status
        else if (strcmp(trimmed, "status") == 0) {
            print_status();
        }
        
        // ===== FILTER COMMANDS =====
        
        else if (strncmp(trimmed, "filter", 6) == 0) {
            char *arg = trimmed + 6;
            arg = trim_whitespace(arg);
            
            if (strlen(arg) == 0 || strcmp(arg, "show") == 0) {
                filter_show();
            }
            else if (strcmp(arg, "clear") == 0) {
                filter_clear();
            }
            else {
                config.filter_mask = filter_parse_protocols(arg);
                if (config.filter_mask == PROTO_ALL) {
                    printf("\033[1;32m[FILTER] Accepting all protocols\033[0m\n");
                } else {
                    char desc[128];
                    filter_describe(config.filter_mask, desc, sizeof(desc));
                    printf("\033[1;32m[FILTER] Now filtering: %s\033[0m\n", desc);
                }
            }
        }
        
        // ===== INSPECT COMMANDS =====
        
        else if (strcmp(trimmed, "inspect") == 0) {
            inspect_enter();
        }
        
        else if (strncmp(trimmed, "show ", 5) == 0) {
            uint32_t id = (uint32_t)atoi(trimmed + 5);
            inspect_show_packet(id);
        }
        
        else if (strncmp(trimmed, "list", 4) == 0) {
            char *arg = trimmed + 4;
            arg = trim_whitespace(arg);
            
            uint32_t count = 20;
            if (strlen(arg) > 0) {
                count = (uint32_t)atoi(arg);
                if (count == 0 || count > 100) count = 20;
            }
            
            packet_entry_t *last = inspect_get_last();
            uint32_t start = 1;
            if (last) {
                start = (last->id > count) ? last->id - count + 1 : 1;
            }
            inspect_list(start, count);
        }
        
        // ===== COMPOSE COMMANDS =====
        
        else if (strncmp(trimmed, "compose", 7) == 0) {
            char *arg = trimmed + 7;
            arg = trim_whitespace(arg);
            
            if (strlen(arg) == 0) {
                composer_list();
            }
            else if (strcmp(arg, "stats") == 0) {
                composer_stats();
            }
            else if (strncmp(arg, "export ", 7) == 0) {
                // Parse: export <id> <filename>
                char *export_arg = arg + 7;
                export_arg = trim_whitespace(export_arg);
                
                uint32_t id = 0;
                char filename[128] = {0};
                
                if (sscanf(export_arg, "%u %127s", &id, filename) == 2) {
                    // Determine format from extension
                    int format = 0;
                    if (strstr(filename, ".json")) format = 1;
                    composer_export(id, filename, format);
                } else {
                    printf("\033[1;31m[ERROR] Usage: compose export <id> <filename>\033[0m\n");
                }
            }
            else {
                // Assume it's a conversation ID
                uint32_t id = (uint32_t)atoi(arg);
                if (id > 0) {
                    composer_show(id);
                } else {
                    printf("\033[1;31m[ERROR] Invalid conversation ID\033[0m\n");
                }
            }
        }
        
        // ===== SAVE COMMANDS =====
        
        else if (strncmp(trimmed, "save ", 5) == 0) {
            char *arg = trimmed + 5;
            arg = trim_whitespace(arg);
            
            // Check for range: save file.pcap 10-50
            char filename[128] = {0};
            uint32_t start = 0, end = 0;
            
            if (sscanf(arg, "%127s %u-%u", filename, &start, &end) == 3) {
                pcap_save_range(filename, start, end);
            } else if (sscanf(arg, "%127s", filename) == 1) {
                pcap_save_all(filename);
            } else {
                printf("\033[1;31m[ERROR] Usage: save <filename.pcap> [start-end]\033[0m\n");
            }
        }
        
        // ===== SESSION COMMANDS =====
        
        else if (strncmp(trimmed, "session", 7) == 0) {
            char *arg = trimmed + 7;
            arg = trim_whitespace(arg);
            
            if (strlen(arg) == 0 || strcmp(arg, "list") == 0) {
                session_list();
            }
            else if (strncmp(arg, "save ", 5) == 0) {
                session_save(trim_whitespace(arg + 5));
            }
            else if (strncmp(arg, "load ", 5) == 0) {
                session_load(trim_whitespace(arg + 5));
            }
            else if (strncmp(arg, "delete ", 7) == 0) {
                session_delete(trim_whitespace(arg + 7));
            }
            else {
                printf("\033[1;33m[SESSION] Commands: list, save <name>, load <name>, delete <name>\033[0m\n");
            }
        }
        
        // ===== AUTOSAVE COMMANDS =====
        
        else if (strncmp(trimmed, "autosave", 8) == 0) {
            char *arg = trimmed + 8;
            arg = trim_whitespace(arg);
            
            if (strcmp(arg, "on") == 0) {
                autosave_set_enabled(true);
            }
            else if (strcmp(arg, "off") == 0) {
                autosave_set_enabled(false);
            }
            else if (strncmp(arg, "interval ", 9) == 0) {
                uint32_t interval = (uint32_t)atoi(arg + 9);
                autosave_set_interval(interval);
            }
            else {
                autosave_config_t *cfg = autosave_get_config();
                printf("\n  Autosave: %s\n", cfg->enabled ? "\033[1;32mON\033[0m" : "\033[1;31mOFF\033[0m");
                printf("  Interval: %u seconds\n", cfg->interval_sec);
                printf("\n  Commands: autosave on/off, autosave interval <seconds>\n\n");
            }
        }
        
        // ===== EXPORT COMMANDS =====
        
        else if (strncmp(trimmed, "export ", 7) == 0) {
            char *arg = trimmed + 7;
            arg = trim_whitespace(arg);
            
            if (strncmp(arg, "packets ", 8) == 0) {
                export_packets_text(trim_whitespace(arg + 8));
            }
            else if (strncmp(arg, "stats ", 6) == 0) {
                export_stats(trim_whitespace(arg + 6));
            }
            else {
                printf("\033[1;33m[EXPORT] Commands: export packets <file>, export stats <file>\033[0m\n");
            }
        }
        
        // Unknown command
        else {
            printf("\033[1;33mUnknown command: %s\033[0m (type 'help' for commands)\n", trimmed);
        }
    }
    
    // Cleanup
    if (is_sniffing) {
        is_sniffing = 0;
        pthread_join(sniffer_thread, NULL);
    }
    
    inspect_cleanup();
    composer_cleanup();
    
    printf("\nStay cold. ❄️\n");
    return 0;
}
