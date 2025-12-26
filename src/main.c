#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <sys/socket.h>
#include <linux/if_ether.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <arpa/inet.h>
#include <unistd.h>


/**
 * FUNCTION: hex_dump_payload
 * Formats raw data into a readable Hex Dump (Hex on the left, ASCII on the right).
 */
void hex_dump_payload(const unsigned char *payload, int len) {
    if (len <= 0) return;

    printf("\n   |-- PAYLOAD DATA (%d bytes) --|\n", len);

    for (int i = 0; i < len; i++) {
        // Print ASCII characters every 16 bytes
        if (i != 0 && i % 16 == 0) {
            printf("         ");
            for (int j = i - 16; j < i; j++) {
                if (isprint(payload[j])) printf("%c", payload[j]);
                else printf(".");
            }
            printf("\n");
        }

        // Print hex value of current byte
        if (i % 16 == 0) printf("   %04x ", i);
        printf("%02x ", payload[i]);

        // Handle end of payload (padding for incomplete last line)
        if (i == len - 1) {
            int spaces = (15 - (i % 16)) * 3;
            for (int k = 0; k < spaces; k++) printf(" ");

            printf("         ");
            for (int j = i - (i % 16); j <= i; j++) {
                if (isprint(payload[j])) printf("%c", payload[j]);
                else printf(".");
            }
            printf("\n");
        }
    }
}

int main() {
    unsigned char buffer[65536];
    struct sockaddr_in source, dest;

    // 1. Open RAW Socket at Ethernet level
    const int sock = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (sock < 0) {
        perror("Socket Error (Did you run with sudo?)");
        return 1;
    }

    printf("started. Capturing IP packets...\n");

    while (1) {
        // 2. Capture packet
        ssize_t packet_size = recvfrom(sock, buffer, 65536, 0, NULL, NULL);
        if (packet_size < 0) break;

        // 3. Layer 2 Decapsulation (Ethernet)
        struct ethhdr *eth = (struct ethhdr *)buffer;

        // Analyze only if the upper protocol is IPv4 (0x0800)
        if (ntohs(eth->h_proto) == ETH_P_IP) {

            // 4. Layer 3 Decapsulation (IP)
            const struct iphdr *ip = (struct iphdr *)(buffer + sizeof(struct ethhdr));

            // Calculate IP header length (IHL field)
            const unsigned int ip_header_len = ip->ihl * 4;

            memset(&source, 0, sizeof(source));
            source.sin_addr.s_addr = ip->saddr;
            memset(&dest, 0, sizeof(dest));
            dest.sin_addr.s_addr = ip->daddr;

            // Salta il pacchetto se sorgente O destinazione sono 127.0.0.1
            // 2130706433 è il valore intero di 127.0.0.1 (Network Byte Order)
            if (ip->saddr == htonl(INADDR_LOOPBACK) || ip->daddr == htonl(INADDR_LOOPBACK)) {
                continue; // Salta al prossimo pacchetto nel loop while
            }

            // 5. Layer 4 Decapsulation (TCP or UDP)
            if (ip->protocol == 6) { // TCP
                const struct tcphdr *tcp = (struct tcphdr *)(buffer + sizeof(struct ethhdr) + ip_header_len);

                printf("\n[TCP] %s:%u -> ", inet_ntoa(source.sin_addr), ntohs(tcp->source));
                printf("%s:%u", inet_ntoa(dest.sin_addr), ntohs(tcp->dest));

                // Calculate Payload Offset
                const int header_size = sizeof(struct ethhdr) + ip_header_len + (tcp->doff * 4);
                hex_dump_payload(buffer + header_size, packet_size - header_size);
            }
            else if (ip->protocol == 17) { // UDP
                const struct udphdr *udp = (struct udphdr *)(buffer + sizeof(struct ethhdr) + ip_header_len);

                printf("\n[UDP] %s:%u -> ", inet_ntoa(source.sin_addr), ntohs(udp->source));
                printf("%s:%u", inet_ntoa(dest.sin_addr), ntohs(udp->dest));

                const int header_size = sizeof(struct ethhdr) + ip_header_len + sizeof(struct udphdr);
                hex_dump_payload(buffer + header_size, packet_size - header_size);
            }
            else if (ip->protocol == 1) { // ICMP
                printf("\n[ICMP] %s -> %s (Ping Request/Reply)\n",
                       inet_ntoa(source.sin_addr), inet_ntoa(dest.sin_addr));
            }
        }
    }

    close(sock);
    return 0;
}






