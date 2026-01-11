CC = gcc

# Security-hardened compiler flags
CFLAGS  = -Wall -Wextra -Werror -std=c11 -O2 -Iinclude
CFLAGS += -D_GNU_SOURCE
CFLAGS += -D_FORTIFY_SOURCE=2
CFLAGS += -fstack-protector-strong
CFLAGS += -fPIE
CFLAGS += -Wformat -Wformat-security
CFLAGS += -Wno-unused-parameter

# Linker flags
LDFLAGS = -lpthread -pie

SRC_DIR = src
OBJ_DIR = obj
BIN_DIR = bin

TARGET = $(BIN_DIR)/coke
SRCS = $(wildcard $(SRC_DIR)/*.c)
OBJS = $(patsubst $(SRC_DIR)/%.c, $(OBJ_DIR)/%.o, $(SRCS))

# Colors for output
RED    = \033[1;31m
GREEN  = \033[1;32m
YELLOW = \033[1;33m
CYAN   = \033[1;36m
RESET  = \033[0m

all: directories $(TARGET)
	@echo "$(GREEN)✓ Build complete!$(RESET)"
	@echo "$(CYAN)  Run with: sudo $(TARGET)$(RESET)"

directories:
	@mkdir -p $(OBJ_DIR) $(BIN_DIR)

$(TARGET): $(OBJS)
	@echo "$(CYAN)🔗 Linking...$(RESET)"
	@$(CC) $(OBJS) -o $(TARGET) $(LDFLAGS)

$(OBJ_DIR)/%.o: $(SRC_DIR)/%.c
	@echo "$(YELLOW)🔨 Compiling $<...$(RESET)"
	@$(CC) $(CFLAGS) -c $< -o $@

clean:
	@echo "$(RED)🧹 Cleaning...$(RESET)"
	@rm -rf $(OBJ_DIR) $(BIN_DIR)

# Install with capabilities (alternative to running as root)
install: all
	@echo "$(CYAN)📦 Installing...$(RESET)"
	@sudo cp $(TARGET) /usr/local/bin/coke
	@sudo setcap cap_net_raw+ep /usr/local/bin/coke
	@echo "$(GREEN)✓ Installed to /usr/local/bin/coke with CAP_NET_RAW$(RESET)"

# Development build with debug info
debug: CFLAGS += -g -O0 -DDEBUG
debug: clean all

# Static analysis
check:
	@echo "$(CYAN)🔍 Running static analysis...$(RESET)"
	@cppcheck --enable=all --std=c11 -Iinclude $(SRC_DIR)/*.c 2>&1 || true

.PHONY: all clean directories install debug check
