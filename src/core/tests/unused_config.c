#include <stdio.h>

#include "core/evpl.h"


int main(int argc, char *argv[])
{
    struct evpl_config *config = evpl_config_init();

    /* if we called evpl_init(), it would take ownership of the config,
     * but if we decided not to init for whatever reason we need a way
     * to clean it up
     */

    evpl_config_release(config);

    return 0;
}
