#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#define PORT 5353  // Use a high port to avoid permission issues
#define DNS_PORT 53
#define DNS_SERVER "8.8.8.8"

#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <arpa/inet.h>

// DNS header is always 12 bytes
struct DNSHeader {
    uint16_t id;
    uint16_t flags;
    uint16_t qdcount;
    uint16_t ancount;
    uint16_t nscount;
    uint16_t arcount;
};


// Function to decode the domain name in the DNS packet
void parse_qname(const unsigned char *packet, int *offset, char *qname) {
    int i = 0;
    while (packet[*offset] != 0) {
        int len = packet[*offset];
        (*offset)++;
        for (int j = 0; j < len; j++) {
            qname[i++] = packet[(*offset)++];
        }
        qname[i++] = '.';
    }
    qname[i - 1] = '\0'; // Replace last dot with null terminator
    (*offset)++; // Move past the 0 byte
}

int encode_domain_name(const char *domain, unsigned char *encoded) {
    const char *pos = domain;
    int len = 0;

    while (*pos) {
        const char *dot = strchr(pos, '.');
        if (!dot) dot = pos + strlen(pos);

        int label_len = dot - pos;
        *encoded++ = label_len;
        memcpy(encoded, pos, label_len);
        encoded += label_len;
        len += label_len + 1;

        if (*dot == '\0') break;
        pos = dot + 1;
    }

    *encoded++ = 0;
    return len + 1;
}

char RESOLVED_IP[16];
int parse_dns_packet(const unsigned char *packet, int length) {
    if (length < 12) {
        printf("Packet too short\n");
        return 1;
    }

    struct DNSHeader *dns = (struct DNSHeader *)packet;
    printf("Transaction ID: 0x%04x\n", ntohs(dns->id));
    printf("Flags: 0x%04x\n", ntohs(dns->flags));
    printf("Questions: %d\n", ntohs(dns->qdcount));
    printf("Answers: %d\n", ntohs(dns->ancount));

    int offset = 12; // Start after DNS header
    for (int i = 0; i < ntohs(dns->qdcount); i++) {
        char qname[256];
        parse_qname(packet, &offset, qname);
        printf("Query name: %s\n", qname);
        if (strcmp(qname, "abracadabra.com") == 0) {
            printf("abracadabra.com is BANNED\n");
            snprintf(RESOLVED_IP, 16, "%u.%u.%u.%u",0,0,0,0);
        }
        else {
            int sockfd;
            struct sockaddr_in dest;
            unsigned char buffer[512];
            int offset = 0;

            // 1. Create socket
            sockfd = socket(AF_INET, SOCK_DGRAM, 0);
            if (sockfd < 0) { perror("socket"); return 1; }

            memset(&dest, 0, sizeof(dest));
            dest.sin_family = AF_INET;
            dest.sin_port = htons(DNS_PORT);
            inet_pton(AF_INET, DNS_SERVER, &dest.sin_addr);

            // 2. Construct DNS Header
            struct DNSHeader *dns = (struct DNSHeader *)buffer;
            dns->id = htons(0x1234);
            dns->flags = htons(0x0100);  // Recursion Desired
            dns->qdcount = htons(1);
            dns->ancount = 0;
            dns->nscount = 0;
            dns->arcount = 0;

            offset = sizeof(struct DNSHeader);

            // 3. Encode QNAME (domain name)
            const char *domain = qname;
            offset += encode_domain_name(domain, buffer + offset);

            // 4. Add QTYPE and QCLASS
            buffer[offset++] = 0x00; buffer[offset++] = 0x01; // QTYPE A
            buffer[offset++] = 0x00; buffer[offset++] = 0x01; // QCLASS IN

            // 5. Send DNS request
            sendto(sockfd, buffer, offset, 0, (struct sockaddr *)&dest, sizeof(dest));
            printf("Sent DNS query for %s to %s\n", domain, DNS_SERVER);

            // 6. Receive response
            struct sockaddr_in from;
            socklen_t fromlen = sizeof(from);
            int n = recvfrom(sockfd, buffer, sizeof(buffer), 0, (struct sockaddr *)&from, &fromlen);
            if (n > 0) {
                printf("Received %d bytes from DNS server.\n", n);

                // Optional: print IP if answer found
                // For simplicity, skip full parsing
                for (int i = 0; i < n - 4; i++) {
                    if (buffer[i] == 0xC0 && buffer[i + 1] == 0x0C && buffer[i + 2] == 0x00 && buffer[i + 3] == 0x01) {
                        unsigned char *ip = &buffer[i + 12];
                        printf("Resolved IP: %d.%d.%d.%d\n", ip[0], ip[1], ip[2], ip[3]);
                        snprintf(RESOLVED_IP, 16, "%d.%d.%d.%d", ip[0], ip[1], ip[2], ip[3]);
                        break;
                    }
                }
            } else {
                perror("recvfrom");
            }
            close(sockfd);
        }
        uint16_t qtype = ntohs(*(uint16_t *)&packet[offset]);
        offset += 2;
        uint16_t qclass = ntohs(*(uint16_t *)&packet[offset]);
        offset += 2;

        printf("Query type: %d, class: %d\n", qtype, qclass);
    }
    return 1;
}

int build_dns_response(unsigned char *response, const unsigned char *request, const char *ip_str) {
    int offset = 0;

    struct DNSHeader *req_hdr = (struct DNSHeader *)request;
    struct DNSHeader *resp_hdr = (struct DNSHeader *)response;

    // Copy DNS header and flip QR bit (query -> response)
    memcpy(resp_hdr, req_hdr, sizeof(struct DNSHeader));
    resp_hdr->flags = htons(0x8180);  // Standard response, no error
    resp_hdr->qdcount = htons(1);
    resp_hdr->ancount = htons(1);
    resp_hdr->nscount = 0;
    resp_hdr->arcount = 0;
    offset = sizeof(struct DNSHeader);

    // Copy QNAME + QTYPE + QCLASS from request
    int name_end = 12;
    while (request[name_end] != 0) name_end++;
    name_end += 5; // Skip over 0x00, QTYPE (2), QCLASS (2)
    memcpy(response + offset, request + sizeof(struct DNSHeader), name_end);
    offset += name_end;

    // Answer section starts here
    response[offset++] = 0xC0;  // Pointer to domain name at offset 12
    response[offset++] = 0x0C;
    response[offset++] = 0x00; response[offset++] = 0x01;  // TYPE A
    response[offset++] = 0x00; response[offset++] = 0x01;  // CLASS IN
    response[offset++] = 0x00; response[offset++] = 0x00;  // TTL (set short)
    response[offset++] = 0x00; response[offset++] = 0x10;
    response[offset++] = 0x00; response[offset++] = 0x04;  // RDLENGTH

    // IP address (RDATA)
    unsigned char ip_bytes[4];
    sscanf(ip_str, "%hhu.%hhu.%hhu.%hhu", &ip_bytes[0], &ip_bytes[1], &ip_bytes[2], &ip_bytes[3]);
    memcpy(response + offset, ip_bytes, 4);
    offset += 4;

    return offset;
}


int start_server() {
    int sockfd;
    char buffer[1024];
    struct sockaddr_in server_addr, client_addr;
    socklen_t client_len = sizeof(client_addr);

    // Create UDP socket
    sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd < 0) {
        perror("socket creation failed");
        exit(EXIT_FAILURE);
    }

    // Allow address reuse
    int opt = 1;
    if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) < 0) {
        perror("setsockopt");
        close(sockfd);
        exit(EXIT_FAILURE);
    }

    // Bind socket to local address
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(PORT);
    server_addr.sin_addr.s_addr = INADDR_ANY;

    if (bind(sockfd, (const struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
        perror("bind failed");
        close(sockfd);
        exit(EXIT_FAILURE);
    }

    printf("UDP server listening on port %d...\n", PORT);

    while (1) {
        // Receive data from client
        ssize_t n = recvfrom(sockfd, buffer, sizeof(buffer) - 1, 0,
                             (struct sockaddr *)&client_addr, &client_len);
        if (n < 0) {
            perror("recvfrom failed");
        } else {
            buffer[n] = '\0';
            printf("Received: %s\n", buffer);
            for (int i = 0; i < sizeof(buffer); i++) {
                printf(" 0x%x ", (unsigned)buffer[i] & 0xffU );
            }
            int block = parse_dns_packet((unsigned char *)buffer, n);

            if (strcmp(RESOLVED_IP, "127.0.0.1") == 0) {
                // Send fake response
                unsigned char response[512];
                int resp_len = build_dns_response(response, (unsigned char *)buffer, RESOLVED_IP);
                sendto(sockfd, response, resp_len, 0, (struct sockaddr *)&client_addr, client_len);
            } else {
                // Relay Google's response (already in buffer)
                sendto(sockfd, buffer, n, 0, (struct sockaddr *)&client_addr, client_len);
            }
        }
    }
}
