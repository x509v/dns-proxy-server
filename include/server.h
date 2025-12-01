//
// Created by arsen on 11/23/25.
//

#ifndef DNS_NEW_SERVER_H
#define DNS_NEW_SERVER_H

#define PORT 53000
#define BUFFER_SIZE 1024
#include <stdint.h>
#include "config_parser.h"
#include <sys/socket.h>
#include <unistd.h>
#include <netdb.h>
#include <arpa/inet.h>


typedef struct {
    uint16_t id;
    uint16_t flags;
    uint16_t qdcount;
    uint16_t ancount;
    uint16_t nscount;
    uint16_t arcount;
} DNSHeader;


void parse_dns_packet(const unsigned char* packet, int length);
char* extract_domain_name(const unsigned char* packet, const unsigned char* start_ptr, int* offset_out);
int check_in_blacklist(const char* domain_name, Config* config);
char* get_dns_response(const unsigned char* request, size_t request_len, Config* config, ssize_t* out_len);


int start_server(Config *config);



#endif //DNS_NEW_SERVER_H