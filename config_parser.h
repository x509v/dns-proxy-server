#ifndef CONFIG_PARSER_H
#define CONFIG_PARSER_H
#include <json-c/json.h>


static const char* CONFIG_FILENAME = "/home/arsen/CLionProjects/dns/config/config.json";


struct Config {
    char * dns_address;
    char* type_of_error_response;
    char** blacklist;
    size_t blacklist_size;
};



struct Config* parse(char const* file);
void free_config(struct Config* config);


#endif