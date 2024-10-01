#include <stdio.h>

#include "core/evpl.h"


int main(int argc, char *argv[])
{
    struct evpl_config *config = evpl_config_init();

    evpl_init_auto(config);

    return 0;
}
