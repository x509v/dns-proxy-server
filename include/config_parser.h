//
// Created by arsen on 11/23/25.
//

#ifndef DNS_NEW_CONFIG_PARSER_H
#define DNS_NEW_CONFIG_PARSER_H

#ifndef CONFIG_PARSER_H
#define CONFIG_PARSER_H
#include <json-c/json.h>
#include <stdio.h>
#include <string.h>

static const char* CONFIG_FILENAME = "/home/arsen/CLionProjects/dns_new/config/config.json";


typedef struct {
    char * dns_address;
    char* type_of_error_response;
    char** blacklist;
    int serv_port;
    size_t blacklist_size;
} Config;



Config* parse(char const* file);
void free_config(Config* config);

#endif


#endif //DNS_NEW_CONFIG_PARSER_H