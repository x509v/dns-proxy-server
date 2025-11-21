#include "config_parser.h"

#include <stdio.h>
#include <string.h>


struct Config* parse(char const* file) {
    FILE* fp = fopen(file, "r");
    if (fp == NULL) {
        perror("fopen failed");
        exit(EXIT_FAILURE);
    }
    struct Config* config = malloc(sizeof(struct Config));
    char* buffer = malloc(1024 * sizeof(char));
    fread(buffer, 1024, 1, fp);
    fclose(fp);

    struct json_object* parsed_json;
    struct json_object* dns_address;
    struct json_object* blacklist;
    struct json_object* blacklist_one;
    struct json_object* type_of_error_response;
    size_t nblacklist_entries;


    parsed_json = json_tokener_parse(buffer);
    free(buffer);
    json_object_object_get_ex(parsed_json, "dns_address", &dns_address);
    json_object_object_get_ex(parsed_json, "type_of_error_response", &type_of_error_response);
    json_object_object_get_ex(parsed_json, "blacklist", &blacklist);

    config->dns_address = strdup(json_object_get_string(dns_address));
    config->type_of_error_response = strdup(json_object_get_string(type_of_error_response));

    nblacklist_entries = json_object_array_length(blacklist);
    printf("Found %lu blacklist entries\n", nblacklist_entries);
    config->blacklist_size = nblacklist_entries;
    config->blacklist = malloc(config->blacklist_size * sizeof(char*));

    for (int i = 0; i < nblacklist_entries; i++) {
        blacklist_one = json_object_array_get_idx(blacklist, i);
        config->blacklist[i] = strdup(json_object_get_string(blacklist_one));
    }
    return config;
}

void free_config(struct Config* config) {
    if (!config) return;

    free(config->dns_address);
    free(config->type_of_error_response);

    for (size_t i = 0; i < config->blacklist_size; i++) {
        free(config->blacklist[i]);
    }

    free(config->blacklist);
    free(config);
}