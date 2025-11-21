#include <stdio.h>
#include "config_parser.h"
#include "server.h"


int main(void) {
    start_server();
    printf("main\n");
    struct Config* conf = parse(CONFIG_FILENAME);
    for (int i =0 ; i < conf->blacklist_size; ++i) {
        printf("%s\n", conf->blacklist[i]);
    }
    printf("%s\n", conf->dns_address);
    printf("%s\n", conf->type_of_error_response);
    free_config(conf);

    return 0;
}