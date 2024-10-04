#include <stdio.h>

#include "core/evpl.h"


int main(int argc, char *argv[])
{
    evpl_init(NULL);

    evpl_cleanup();

    return 0;
}
