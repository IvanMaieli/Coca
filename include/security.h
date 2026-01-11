#ifndef SECURITY_H
#define SECURITY_H

#include <stdbool.h>
#include <stddef.h>

/* =============================================================================
 * SECURITY MODULE
 * 
 * Provides security hardening features:
 * - Privilege dropping after socket creation
 * - Input validation and sanitization
 * - Secure memory handling
 * - Capability checking
 * ============================================================================= */

/**
 * Initialize security subsystem
 * Should be called early in main()
 * 
 * @return true on success, false on failure
 */
bool security_init(void);

/**
 * Drop root privileges after acquiring raw socket
 * Falls back to setuid()/setgid() if libcap is not available
 * 
 * @return true on success, false on failure
 */
bool security_drop_privileges(void);

/**
 * Validate and sanitize user input
 * Checks for:
 * - NULL pointer
 * - Maximum length
 * - Control characters
 * - Shell metacharacters
 * 
 * @param str Input string to validate
 * @param max_len Maximum allowed length
 * @return true if input is safe, false otherwise
 */
bool security_validate_input(const char *str, size_t max_len);

/**
 * Securely free memory by zeroing before free
 * Prevents sensitive data leakage
 * 
 * @param ptr Pointer to memory
 * @param size Size of memory block
 */
void security_secure_free(void *ptr, size_t size);

/**
 * Check if process has required capabilities for raw sockets
 * 
 * @return true if CAP_NET_RAW is available, false otherwise
 */
bool security_check_capabilities(void);

/**
 * Sanitize a string in-place
 * Removes or escapes dangerous characters
 * 
 * @param str String to sanitize (modified in place)
 * @param max_len Maximum length to process
 */
void security_sanitize_string(char *str, size_t max_len);

#endif /* SECURITY_H */
