//
// Created by arsen on 11/23/25.
//

#include "server.h"


char* extract_domain_name(const unsigned char* packet, const unsigned char* name_start_ptr, int* bytes_consumed_out) {
    char *name = (char *)malloc(256); // Allocate for max domain name size (255 chars + null terminator)
    if (name == NULL) {
        perror("ERROR: malloc failed");
        exit(EXIT_FAILURE);
    }
    name[0] = '\0'; // Start with an empty string

    // The reader tracks the current position in the packet where we are reading name bytes.
    const unsigned char* reader = name_start_ptr;

    // tracks how many bytes were consumed from the 'name_start_ptr' position.
    int current_name_length = 0;

    // Flag to indicate if we have followed a pointer, so we don't count bytes anymore.
    int jumped = 0;

    // Safety counter to prevent infinite loops in case of circular compression pointers
    int loops = 0;

    while (1) {
        // Increment loop counter
        if (++loops > 255) {
            fprintf(stderr, "Error: Too many jumps (potential infinite loop in DNS name).");
            free(name);
            *bytes_consumed_out = 0;
            return NULL;
        }

        uint8_t length = *reader;

        // --- 1. POINTER COMPRESSION CHECK (11xx xxxx) ---
        if ((length & 0xC0) == 0xC0) {
            // Found a pointer! It consumes 2 bytes in the current section.

            // Extract the 14-bit offset (mask off the high 2 bits)
            uint16_t pointer = ntohs(*(uint16_t*)reader);
            pointer &= 0x3FFF;

            // If we haven't jumped yet, this is the end of the data we need to consume.
            if (!jumped) {
                // The name data took 2 bytes for the pointer
                *bytes_consumed_out = (reader - name_start_ptr) + 2;
                jumped = 1;
            }

            // Update reader to the new absolute location (from the start of the packet)
            reader = packet + pointer;
            // Continue parsing from the new location, but keep the 'jumped' flag set
            continue;
        }

        // --- 2. END OF NAME CHECK (0000 0000) ---
        if (length == 0) {
            // Null terminator found.
            if (!jumped) {
                // If no jump occurred, the name consumed its raw length + 1 (for the null byte)
                *bytes_consumed_out = (reader - name_start_ptr) + 1;
            }
            break; // Done parsing the name
        }

        // --- 3. LABEL PARSING (0xxx xxxx) ---
        // Basic safety check for label length
        if (length > 63) {
            fprintf(stderr, "Error: Invalid DNS label length (%u).\n", length);
            free(name);
            *bytes_consumed_out = current_name_length + 1; // Return current offset + 1 (for length byte)
            return NULL;
        }

        reader++; // Move past the length byte to the label data

        // Append a '.' separator if the name already has content (not the first label)
        if (name[0] != '\0') {
            strcat(name, ".");
        }

        // Append the label itself (use strncat for safety)
        strncat(name, (const char*)reader, length);

        reader += length; // Move past the label data

        // Only track bytes consumed if we haven't followed a pointer yet
        if (!jumped) {
            current_name_length += (length + 1); // +1 for the length byte itself
        }
    }

    // Ensure the output is set correctly even if the loop finished (it should be set inside the loop)
    if (!jumped && *bytes_consumed_out == 0) {
        *bytes_consumed_out = current_name_length + 1;
    }

    return name;
}

int check_in_blacklist(const char* domain_name, Config* config) {
    char** blacklist = config->blacklist;
    for (int i = 0; blacklist[i] != NULL; i++) {
        if (strcmp(domain_name, blacklist[i]) == 0) {
            return 1;
        }
    }
    return 0;
}

char* get_dns_response(const unsigned char* request,
                       size_t request_len,
                       Config* config,
                       ssize_t* out_len)
{
    struct sockaddr_in serv_addr;
    int sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd < 0) {
        perror("ERROR: socket creation failed");
        return NULL;
    }

    memset(&serv_addr, 0, sizeof(serv_addr));
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_addr.s_addr = inet_addr(config->dns_address);
    serv_addr.sin_port = htons(config->serv_port);

    if (sendto(sockfd, request, request_len, 0,
               (struct sockaddr*)&serv_addr, sizeof(serv_addr)) < 0)
    {
        perror("Error sending data");
        close(sockfd);
        return NULL;
    }

    unsigned char buffer[BUFFER_SIZE];
    socklen_t addr_len = sizeof(serv_addr);

    ssize_t bytes_received =
        recvfrom(sockfd, buffer, BUFFER_SIZE, 0,
                 (struct sockaddr*)&serv_addr, &addr_len);

    if (bytes_received < 0) {
        perror("Error receiving data");
        close(sockfd);
        return NULL;
    }

    char* out = malloc(bytes_received);
    memcpy(out, buffer, bytes_received);
    *out_len = bytes_received;

    close(sockfd);
    return out;
}


int start_server(Config* config) {
    char buffer[BUFFER_SIZE];
    struct sockaddr_in serv_addr, client_addr;
    socklen_t client_len = sizeof(client_addr);
    ssize_t bytes_received;

    // Create the UDP socket
    int sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd < 0) {
        perror("ERROR: socket creation failed");
        return EXIT_FAILURE;
    }
    memset(&serv_addr, 0, sizeof(serv_addr));
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_addr.s_addr = INADDR_ANY;
    serv_addr.sin_port = htons(PORT);

    // Bind the socket
    if (bind(sockfd, (const struct sockaddr*)&serv_addr, sizeof(serv_addr)) < 0) {
        perror("ERROR: bind failed");
        close(sockfd);
        return EXIT_FAILURE;
    }
    printf("UDP receiver listening on port %d...\n", PORT);

    while (1) {
        memset(buffer, 0, BUFFER_SIZE);
        bytes_received = recvfrom(sockfd, buffer, BUFFER_SIZE, 0, (struct sockaddr*)&client_addr, &client_len);
        if (bytes_received < 0) {
            perror("ERROR: recvfrom failed");
            continue;
        }
        buffer[bytes_received] = '\0';
        int offset_out;
        char* parsed_name = extract_domain_name(buffer, buffer + 12, &offset_out);
        printf("Query Name: %s\n", parsed_name);
        int comp = check_in_blacklist(parsed_name, config);
        if (comp != 0) {
            printf("in blacklist");
        }
        else {
            ssize_t response_len = 0;
            char* response = get_dns_response(
                    (unsigned char*)buffer,
                    bytes_received,
                    config,
                    &response_len
            );

            if (response == NULL) {
                printf("DNS upstream query failed");
            }
            else {
                sendto(sockfd, response, response_len, 0,
                      (struct sockaddr*)&client_addr, client_len);
                free(response);
            }
        }
        free(parsed_name);
    }
    return 0;
}