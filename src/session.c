#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <dirent.h>
#include <unistd.h>
#include <pwd.h>
#include <time.h>
#include <errno.h>

#include "session.h"
#include "coke.h"
#include "filter.h"
#include <ctype.h>

/* =============================================================================
 * SESSION MODULE IMPLEMENTATION
 * ============================================================================= */

static autosave_config_t autosave_cfg = {
    .enabled = false,
    .interval_sec = 300,  // 5 minutes default
    .file_counter = 0,
    .current_file = NULL
};

static time_t last_autosave = 0;

/**
 * Get home directory
 */
static const char* get_home_dir(void) {
    const char *home = getenv("HOME");
    if (!home) {
        struct passwd *pw = getpwuid(getuid());
        if (pw) {
            home = pw->pw_dir;
        }
    }
    return home ? home : "/tmp";
}

/**
 * Get session directory path
 */
bool session_get_dir(char *buffer, size_t size) {
    const char *home = get_home_dir();
    snprintf(buffer, size, "%s/%s", home, SESSION_DIR);
    return true;
}

/**
 * Create directory recursively
 */
static bool mkdir_recursive(const char *path) {
    char tmp[512];
    char *p = NULL;
    size_t len;
    
    snprintf(tmp, sizeof(tmp), "%s", path);
    len = strlen(tmp);
    
    if (tmp[len - 1] == '/') {
        tmp[len - 1] = 0;
    }
    
    for (p = tmp + 1; *p; p++) {
        if (*p == '/') {
            *p = 0;
            mkdir(tmp, 0755);
            *p = '/';
        }
    }
    
    return mkdir(tmp, 0755) == 0 || errno == EEXIST;
}

/**
 * Initialize session subsystem
 */
bool session_init(void) {
    char session_dir[512];
    session_get_dir(session_dir, sizeof(session_dir));
    
    if (!mkdir_recursive(session_dir)) {
        fprintf(stderr, "\033[1;33m[SESSION] Warning: Could not create session directory\033[0m\n");
        return false;
    }
    
    last_autosave = time(NULL);
    return true;
}

/**
 * Save current session
 */
bool session_save(const char *name) {
    if (!name || strlen(name) == 0) {
        printf("\033[1;31m[SESSION] No session name provided\033[0m\n");
        return false;
    }
    
    // Validate name
    for (const char *p = name; *p; p++) {
        if (!isalnum((unsigned char)*p) && *p != '_' && *p != '-') {
            printf("\033[1;31m[SESSION] Invalid character in session name\033[0m\n");
            return false;
        }
    }
    
    char session_dir[512];
    session_get_dir(session_dir, sizeof(session_dir));
    
    char filepath[640];
    snprintf(filepath, sizeof(filepath), "%s/%s%s", session_dir, name, SESSION_EXT);
    
    FILE *f = fopen(filepath, "w");
    if (!f) {
        printf("\033[1;31m[SESSION] Could not create session file: %s\033[0m\n", strerror(errno));
        return false;
    }
    
    // Write session header
    fprintf(f, "# Coke Session: %s\n", name);
    fprintf(f, "# Saved: %ld\n\n", (long)time(NULL));
    
    // Save configuration
    fprintf(f, "[config]\n");
    fprintf(f, "filter_mask=%u\n", config.filter_mask);
    fprintf(f, "hex_view=%d\n", config.hex_view ? 1 : 0);
    fprintf(f, "verbose=%d\n", config.verbose ? 1 : 0);
    fprintf(f, "max_packets=%u\n", config.max_packets);
    fprintf(f, "\n");
    
    // Save state
    fprintf(f, "[state]\n");
    fprintf(f, "packets_captured=%u\n", state.packets_captured);
    fprintf(f, "packets_filtered=%u\n", state.packets_filtered);
    fprintf(f, "conversations_count=%u\n", state.conversations_count);
    fprintf(f, "\n");
    
    fclose(f);
    
    printf("\033[1;32m[SESSION] Session '%s' saved\033[0m\n", name);
    printf("  Location: %s\n", filepath);
    
    return true;
}

/**
 * Load a session
 */
bool session_load(const char *name) {
    if (!name || strlen(name) == 0) {
        printf("\033[1;31m[SESSION] No session name provided\033[0m\n");
        return false;
    }
    
    char session_dir[512];
    session_get_dir(session_dir, sizeof(session_dir));
    
    char filepath[640];
    snprintf(filepath, sizeof(filepath), "%s/%s%s", session_dir, name, SESSION_EXT);
    
    FILE *f = fopen(filepath, "r");
    if (!f) {
        printf("\033[1;31m[SESSION] Session not found: %s\033[0m\n", name);
        return false;
    }
    
    char line[256];
    char section[64] = "";
    
    while (fgets(line, sizeof(line), f)) {
        // Remove newline
        line[strcspn(line, "\n")] = 0;
        
        // Skip comments and empty lines
        if (line[0] == '#' || line[0] == '\0') continue;
        
        // Section header
        if (line[0] == '[') {
            char *end = strchr(line, ']');
            if (end) {
                *end = '\0';
                size_t slen = strlen(line + 1);
                if (slen >= sizeof(section)) slen = sizeof(section) - 1;
                memcpy(section, line + 1, slen);
                section[slen] = '\0';
            }
            continue;
        }
        
        // Parse key=value
        char *eq = strchr(line, '=');
        if (!eq) continue;
        
        *eq = '\0';
        char *key = line;
        char *value = eq + 1;
        
        if (strcmp(section, "config") == 0) {
            if (strcmp(key, "filter_mask") == 0) {
                config.filter_mask = (protocol_mask_t)atoi(value);
            } else if (strcmp(key, "hex_view") == 0) {
                config.hex_view = atoi(value) != 0;
            } else if (strcmp(key, "verbose") == 0) {
                config.verbose = atoi(value) != 0;
            } else if (strcmp(key, "max_packets") == 0) {
                config.max_packets = (uint32_t)atoi(value);
            }
        }
    }
    
    fclose(f);
    
    printf("\033[1;32m[SESSION] Session '%s' loaded\033[0m\n", name);
    return true;
}

/**
 * List saved sessions
 */
void session_list(void) {
    char session_dir[512];
    session_get_dir(session_dir, sizeof(session_dir));
    
    DIR *dir = opendir(session_dir);
    if (!dir) {
        printf("\033[1;33m[SESSION] No sessions found\033[0m\n");
        return;
    }
    
    printf("\n\033[1;36m  Saved Sessions:\033[0m\n");
    printf("  %-20s  %s\n", "NAME", "MODIFIED");
    printf("  --------------------  -------------------\n");
    
    int count = 0;
    struct dirent *entry;
    
    while ((entry = readdir(dir)) != NULL) {
        // Check for .coke extension
        size_t len = strlen(entry->d_name);
        if (len > 5 && strcmp(entry->d_name + len - 5, SESSION_EXT) == 0) {
            // Get file info
            char filepath[640];
            snprintf(filepath, sizeof(filepath), "%s/%s", session_dir, entry->d_name);
            
            struct stat st;
            if (stat(filepath, &st) == 0) {
                // Remove extension for display
                char name[256];
                strncpy(name, entry->d_name, sizeof(name) - 1);
                name[len - 5] = '\0';
                
                // Format time
                char timebuf[32];
                strftime(timebuf, sizeof(timebuf), "%Y-%m-%d %H:%M:%S", 
                         localtime(&st.st_mtime));
                
                printf("  \033[1;37m%-20s\033[0m  %s\n", name, timebuf);
                count++;
            }
        }
    }
    
    closedir(dir);
    
    if (count == 0) {
        printf("  \033[0;90m(no sessions)\033[0m\n");
    }
    
    printf("\n");
}

/**
 * Delete a session
 */
bool session_delete(const char *name) {
    if (!name || strlen(name) == 0) {
        printf("\033[1;31m[SESSION] No session name provided\033[0m\n");
        return false;
    }
    
    char session_dir[512];
    session_get_dir(session_dir, sizeof(session_dir));
    
    char filepath[640];
    snprintf(filepath, sizeof(filepath), "%s/%s%s", session_dir, name, SESSION_EXT);
    
    if (unlink(filepath) != 0) {
        printf("\033[1;31m[SESSION] Could not delete session: %s\033[0m\n", strerror(errno));
        return false;
    }
    
    printf("\033[1;32m[SESSION] Session '%s' deleted\033[0m\n", name);
    return true;
}

/**
 * Auto-save configuration
 */
void autosave_set_enabled(bool enable) {
    autosave_cfg.enabled = enable;
    if (enable) {
        last_autosave = time(NULL);
        printf("\033[1;32m[AUTOSAVE] Enabled (interval: %u seconds)\033[0m\n", 
               autosave_cfg.interval_sec);
    } else {
        printf("\033[1;33m[AUTOSAVE] Disabled\033[0m\n");
    }
}

void autosave_set_interval(uint32_t seconds) {
    if (seconds < 30) seconds = 30;  // Minimum 30 seconds
    if (seconds > 3600) seconds = 3600;  // Maximum 1 hour
    
    autosave_cfg.interval_sec = seconds;
    printf("\033[1;32m[AUTOSAVE] Interval set to %u seconds\033[0m\n", seconds);
}

autosave_config_t* autosave_get_config(void) {
    return &autosave_cfg;
}

/**
 * Check and perform auto-save if needed
 */
void autosave_check(void) {
    if (!autosave_cfg.enabled) return;
    
    time_t now = time(NULL);
    if (now - last_autosave < autosave_cfg.interval_sec) return;
    
    // Time for auto-save
    last_autosave = now;
    autosave_cfg.file_counter++;
    
    char session_dir[512];
    session_get_dir(session_dir, sizeof(session_dir));
    
    // Create auto-save filename
    char filename[640];
    snprintf(filename, sizeof(filename), "%s/%s%03u.pcap", 
             session_dir, AUTOSAVE_PREFIX, autosave_cfg.file_counter);
    
    // Save packets
    extern bool pcap_save_all(const char *filename);  // From logger.c
    pcap_save_all(filename);
}
