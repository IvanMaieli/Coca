#ifndef SESSION_H
#define SESSION_H

#include <stdbool.h>
#include <stdint.h>

/* =============================================================================
 * SESSION MODULE
 * 
 * Session persistence and auto-save functionality:
 * - Save/load complete sessions (packets, filters, conversations)
 * - Auto-save with file rotation
 * - Session directory management
 * ============================================================================= */

#define SESSION_DIR         ".coke/sessions"
#define SESSION_EXT         ".coke"
#define AUTOSAVE_PREFIX     "autosave_"
#define MAX_SESSION_NAME    64

// Auto-save configuration
typedef struct {
    bool enabled;
    uint32_t interval_sec;
    uint32_t file_counter;
    char *current_file;
} autosave_config_t;

/**
 * Initialize session subsystem
 * Creates session directory if needed
 * 
 * @return true on success
 */
bool session_init(void);

/**
 * Save current session to file
 * 
 * @param name Session name (saved to ~/.coke/sessions/<name>.coke)
 * @return true on success
 */
bool session_save(const char *name);

/**
 * Load a session from file
 * 
 * @param name Session name to load
 * @return true on success
 */
bool session_load(const char *name);

/**
 * List all saved sessions
 */
void session_list(void);

/**
 * Delete a saved session
 * 
 * @param name Session name to delete
 * @return true on success
 */
bool session_delete(const char *name);

/**
 * Enable/disable auto-save
 * 
 * @param enable true to enable, false to disable
 */
void autosave_set_enabled(bool enable);

/**
 * Set auto-save interval
 * 
 * @param seconds Interval between saves
 */
void autosave_set_interval(uint32_t seconds);

/**
 * Get auto-save status
 * 
 * @return Current auto-save configuration
 */
autosave_config_t* autosave_get_config(void);

/**
 * Perform auto-save if needed
 * Called periodically from main loop
 */
void autosave_check(void);

/**
 * Get session directory path
 * 
 * @param buffer Output buffer
 * @param size Buffer size
 * @return true if path retrieved successfully
 */
bool session_get_dir(char *buffer, size_t size);

#endif /* SESSION_H */
