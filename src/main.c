#include <stdio.h>
#include "config_parser.h"
#include "server.h"

int main(void) {
    Config* config = parse(CONFIG_FILENAME);
    if (!config) {
        return 1;
    }

    start_server(config);
    return 0;
}
