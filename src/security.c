/* Security module implementation */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <ctype.h>
#include <pwd.h>
#include <grp.h>
#include <sys/types.h>
#include <sys/prctl.h>
#include <errno.h>

#include "security.h"
#include "coke.h"

/* =============================================================================
 * SECURITY MODULE IMPLEMENTATION
 * ============================================================================= */

// Original UID/GID for privilege operations
static uid_t original_uid = 0;
static gid_t original_gid = 0;
static bool privileges_dropped = false;

/**
 * Initialize security subsystem
 */
bool security_init(void) {
    original_uid = getuid();
    original_gid = getgid();
    
    // Set process to be dumpable for debugging, but not after privilege drop
    prctl(PR_SET_DUMPABLE, 1);
    
    return true;
}

/**
 * Drop privileges to nobody user after socket creation
 */
bool security_drop_privileges(void) {
    if (privileges_dropped) {
        return true;  // Already dropped
    }
    
    // Only drop if we're root
    if (geteuid() != 0) {
        privileges_dropped = true;
        return true;  // Not root, nothing to drop
    }
    
    // Get nobody user info
    struct passwd *nobody = getpwnam("nobody");
    if (!nobody) {
        // Fallback: try to use a high UID
        fprintf(stderr, "\033[1;33m[SECURITY] Warning: 'nobody' user not found, using UID 65534\033[0m\n");
    }
    
    uid_t target_uid = nobody ? nobody->pw_uid : 65534;
    gid_t target_gid = nobody ? nobody->pw_gid : 65534;
    
    // Drop supplementary groups first
    if (setgroups(0, NULL) < 0) {
        fprintf(stderr, "\033[1;33m[SECURITY] Warning: Could not drop supplementary groups: %s\033[0m\n", 
                strerror(errno));
    }
    
    // Change GID first (while we still have root)
    if (setresgid(target_gid, target_gid, target_gid) < 0) {
        fprintf(stderr, "\033[1;31m[SECURITY] Error: Could not drop GID: %s\033[0m\n", 
                strerror(errno));
        return false;
    }
    
    // Now drop UID
    if (setresuid(target_uid, target_uid, target_uid) < 0) {
        fprintf(stderr, "\033[1;31m[SECURITY] Error: Could not drop UID: %s\033[0m\n", 
                strerror(errno));
        return false;
    }
    
    // Verify we can't get root back
    if (setuid(0) == 0) {
        fprintf(stderr, "\033[1;31m[SECURITY] CRITICAL: Could regain root! Aborting.\033[0m\n");
        exit(EXIT_FAILURE);
    }
    
    // No longer dumpable after privilege drop
    prctl(PR_SET_DUMPABLE, 0);
    
    // Prevent acquiring new privileges
    prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0);
    
    privileges_dropped = true;
    
    if (config.verbose) {
        printf("\033[1;32m[SECURITY] Privileges dropped to UID %d, GID %d\033[0m\n", 
               target_uid, target_gid);
    }
    
    return true;
}

/**
 * Validate user input for safety
 */
bool security_validate_input(const char *str, size_t max_len) {
    if (!str) {
        return false;
    }
    
    size_t len = strnlen(str, max_len + 1);
    
    // Check length
    if (len > max_len) {
        return false;
    }
    
    // Check for null bytes in the middle
    for (size_t i = 0; i < len; i++) {
        char c = str[i];
        
        // Allow printable ASCII and common whitespace
        if (!isprint((unsigned char)c) && c != ' ' && c != '\t') {
            return false;
        }
        
        // Block shell metacharacters that could be dangerous
        if (c == ';' || c == '|' || c == '&' || c == '$' || 
            c == '`' || c == '\\' || c == '\'' || c == '"' ||
            c == '<' || c == '>' || c == '(' || c == ')' ||
            c == '{' || c == '}' || c == '[' || c == ']') {
            return false;
        }
    }
    
    return true;
}

/**
 * Sanitize string in-place
 */
void security_sanitize_string(char *str, size_t max_len) {
    if (!str || max_len == 0) {
        return;
    }
    
    for (size_t i = 0; i < max_len && str[i] != '\0'; i++) {
        unsigned char c = (unsigned char)str[i];
        
        // Replace non-printable with space, except common whitespace
        if (!isprint(c) && c != ' ' && c != '\t') {
            str[i] = ' ';
        }
        
        // Replace dangerous shell metacharacters
        if (c == ';' || c == '|' || c == '&' || c == '$' || 
            c == '`' || c == '\\' || c == '\'' || c == '"' ||
            c == '<' || c == '>' || c == '(' || c == ')' ||
            c == '{' || c == '}' || c == '[' || c == ']') {
            str[i] = '_';
        }
    }
}

/**
 * Securely free memory (zero before free)
 */
void security_secure_free(void *ptr, size_t size) {
    if (ptr && size > 0) {
        // Volatile to prevent compiler optimization
        volatile unsigned char *p = (volatile unsigned char *)ptr;
        while (size--) {
            *p++ = 0;
        }
        free(ptr);
    }
}

/**
 * Check if we have raw socket capabilities
 */
bool security_check_capabilities(void) {
    // Simple check: try to see if we're effectively root or have CAP_NET_RAW
    // CAP_NET_RAW is required for raw sockets
    
    if (geteuid() == 0) {
        return true;
    }
    
    // Try to check capabilities using /proc
    FILE *f = fopen("/proc/self/status", "r");
    if (!f) {
        return false;
    }
    
    char line[256];
    bool has_cap = false;
    
    while (fgets(line, sizeof(line), f)) {
        if (strncmp(line, "CapEff:", 7) == 0) {
            // Parse effective capabilities
            unsigned long long caps;
            if (sscanf(line + 7, "%llx", &caps) == 1) {
                // CAP_NET_RAW is bit 13
                has_cap = (caps & (1ULL << 13)) != 0;
            }
            break;
        }
    }
    
    fclose(f);
    return has_cap;
}
