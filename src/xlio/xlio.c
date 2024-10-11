#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <dlfcn.h>


#include "xlio.h"

#include "core/evpl.h"
#include "core/internal.h"
#include "core/protocol.h"

#include "common.h"

#define XLIO_DL_FN(xlio, name) { \
    xlio->name = dlsym(xlio->hdl, #name); \
    evpl_xlio_abort_if(!xlio->name, "No " #name " symbol found in XLIO library"); \
}

void *
evpl_xlio_init()
{
    struct evpl_xlio_shared *xlio;

    xlio = evpl_zalloc(sizeof(*xlio));

    setenv("XLIO_FORK","0",0);

    xlio->hdl = dlopen("/opt/nvidia/lib/libxlio.so", RTLD_LAZY);

    evpl_xlio_abort_if(!xlio->hdl, "Failed to dynamically load XLIO library");

    XLIO_DL_FN(xlio, socket);
    XLIO_DL_FN(xlio, fcntl);
    XLIO_DL_FN(xlio, bind);
    XLIO_DL_FN(xlio, close);
    XLIO_DL_FN(xlio, recvmmsg);
    XLIO_DL_FN(xlio, sendmmsg);
    XLIO_DL_FN(xlio, epoll_create);
    XLIO_DL_FN(xlio, epoll_ctl);
    XLIO_DL_FN(xlio, epoll_wait);

    return xlio; 
}

void
evpl_xlio_cleanup(void *private_data)
{
    struct evpl_xlio_shared *xlio = private_data;

    dlclose(xlio->hdl);
    evpl_free(xlio);
}

void *
evpl_xlio_create(
    struct evpl *evpl,
    void        *private_data)
{
    /* our per-thread state is just our global state */
    return private_data;
}

void
evpl_xlio_destroy(
    struct evpl *evpl,
    void        *private_data)
{
}

struct evpl_framework evpl_xlio = {
    .id                = EVPL_FRAMEWORK_XLIO,
    .name              = "XLIO",
    .init              = evpl_xlio_init,
    .cleanup           = evpl_xlio_cleanup,
    .create            = evpl_xlio_create,
    .destroy           = evpl_xlio_destroy,
};
