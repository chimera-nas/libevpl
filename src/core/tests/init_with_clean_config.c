#include <stdio.h>

#include "core/evpl.h"


int main(int argc, char *argv[])
{
    struct evpl_config *config = evpl_config_init();

    evpl_init(config);

    evpl_cleanup();

    return 0;
}
