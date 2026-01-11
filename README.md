# Coke - Linux Terminal Packet Sniffer

```
   ██████╗ ██████╗ ██╗  ██╗███████╗
  ██╔════╝██╔═══██╗██║ ██╔╝██╔════╝
  ██║     ██║   ██║█████╔╝ █████╗  
  ██║     ██║   ██║██╔═██╗ ██╔══╝  
  ╚██████╗╚██████╔╝██║  ██╗███████╗
   ╚═════╝ ╚═════╝ ╚═╝  ╚═╝╚══════╝
```

A powerful, security-focused packet sniffer for the Linux terminal. Coke provides efficient packet capture with real-time filtering, interactive packet inspection, and conversation analysis.

## Features

- **🔍 Inspect Mode**: Interactive packet navigation with detailed layer-by-layer protocol dissection
- **🎯 Multi-Protocol Filtering**: Filter by multiple protocols simultaneously (TCP, UDP, ICMP, ARP, HTTP, DNS, TLS, SSH)
- **🔒 Security Hardened**: Privilege dropping, input validation, ASLR/PIE, stack protection
- **💬 Conversation Composer**: Track bidirectional flows, view statistics, export conversations

## Requirements

- Linux (kernel 2.6+)
- GCC with C11 support
- Root privileges or `CAP_NET_RAW` capability

## Building

```bash
# Standard build
make

# Debug build (with symbols)
make debug

# Install with capabilities (no sudo needed after install)
sudo make install
```

## Usage

```bash
# Run with sudo
sudo ./bin/coke

# Or run without sudo if installed with capabilities
coke
```

### Commands

#### Capture
| Command | Description |
|---------|-------------|
| `start` | Start packet capture |
| `stop` | Stop packet capture (or use Ctrl+C) |

#### Filtering
| Command | Description |
|---------|-------------|
| `filter <protocols>` | Set filter (e.g., `filter tcp,udp`) |
| `filter clear` | Remove all filters |
| `filter show` | Display current filter configuration |

**Supported protocols**: `tcp`, `udp`, `icmp`, `arp`, `dns`, `http`, `https`/`tls`, `ssh`

#### Inspect Mode
| Command | Description |
|---------|-------------|
| `inspect` | Enter interactive inspection mode |
| `show <id>` | Show detailed packet information |
| `list [n]` | List last n packets (default 20) |

Inside inspect mode:
- `n`/`next` - Next packet
- `p`/`prev` - Previous packet
- `g`/`goto <id>` - Jump to packet ID
- `d`/`detail` - Show current packet details
- `l`/`list [n]` - List packets
- `first`/`last` - Jump to first/last packet
- `q`/`quit` - Exit inspect mode

#### Conversation Composer
| Command | Description |
|---------|-------------|
| `compose` | List all tracked conversations |
| `compose <id>` | Show conversation details |
| `compose stats` | Display conversation statistics |
| `compose export <id> <file>` | Export conversation (text or JSON) |

#### Other
| Command | Description |
|---------|-------------|
| `hex` | Toggle hex dump display |
| `status` | Show capture status |
| `clear` | Clear screen |
| `help` | Show help |
| `exit` | Quit |

## Examples

```bash
# Capture only TCP and UDP
coke > filter tcp,udp
coke > start

# Capture only DNS traffic
coke > filter dns
coke > start

# View captured packets
coke > list 50
coke > show 42

# Analyze a conversation
coke > compose
coke > compose 1
coke > compose export 1 session.json
```

## Security

Coke implements several security measures:

1. **Privilege Dropping**: Root privileges are dropped immediately after creating the raw socket
2. **Input Validation**: All user input is validated and sanitized
3. **Memory Safety**: Bounds checking, secure memory clearing
4. **Compiler Hardening**: Built with `-fstack-protector-strong`, `-D_FORTIFY_SOURCE=2`, PIE/ASLR
5. **Signal Safety**: Proper async-signal-safe handlers

### Running Without Root

Instead of running with `sudo`, you can set the `CAP_NET_RAW` capability:

```bash
sudo setcap cap_net_raw+ep ./bin/coke
```

Or use `sudo make install` which does this automatically.

## Architecture

```
src/
├── main.c       # Command dispatcher and initialization
├── sniffer.c    # Raw socket capture engine
├── filter.c     # Protocol filtering system
├── inspect.c    # Packet buffer and inspection
├── composer.c   # Conversation tracking
├── security.c   # Security utilities
├── logger.c     # PCAP file support
└── ui.c         # User interface elements
```

## License

MIT License - See LICENSE file for details.
