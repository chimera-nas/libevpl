// SPDX-FileCopyrightText: 2026 Ben Jarvis
//
// SPDX-License-Identifier: LGPL-2.1-only

#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <pthread.h>
#include <sys/socket.h>
#include <sys/epoll.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <utlist.h>

#include <rdma/fabric.h>
#include <rdma/fi_domain.h>
#include <rdma/fi_endpoint.h>
#include <rdma/fi_cm.h>
#include <rdma/fi_eq.h>
#include <rdma/fi_rma.h>
#include <rdma/fi_errno.h>

#include "core/evpl.h"
#include "core/libfabric/libfabric.h"
#include "evpl/evpl_libfabric.h"
#include "core/macros.h"
#include "core/protocol.h"
#include "core/bind.h"
#include "core/endpoint.h"
#include "core/evpl_shared.h"
#include "core/event_fn.h"
#include "core/poll.h"
#include "core/allocator.h"
#include "core/iovec.h"

extern struct evpl_shared *evpl_shared;

#define evpl_libfabric_debug(...) evpl_debug("libfabric", __FILE__, __LINE__, \
                                             __VA_ARGS__)
#define evpl_libfabric_info(...)  evpl_info("libfabric", __FILE__, __LINE__, \
                                            __VA_ARGS__)
#define evpl_libfabric_error(...) evpl_error("libfabric", __FILE__, __LINE__, \
                                             __VA_ARGS__)
#define evpl_libfabric_fatal(...) evpl_fatal("libfabric", __FILE__, __LINE__, \
                                             __VA_ARGS__)
#define evpl_libfabric_abort(...) evpl_abort("libfabric", __FILE__, __LINE__, \
                                             __VA_ARGS__)

#define evpl_libfabric_fatal_if(cond, ...) \
        evpl_fatal_if(cond, "libfabric", __FILE__, __LINE__, __VA_ARGS__)

#define evpl_libfabric_abort_if(cond, ...) \
        evpl_abort_if(cond, "libfabric", __FILE__, __LINE__, __VA_ARGS__)

/* The API surface this backend is written against */
#define EVPL_LIBFABRIC_API_VERSION FI_VERSION(1, 18)

/* Requested-key allocation starts high to stay clear of keys an
 * application may have chosen on an externally provided domain */
#define EVPL_LIBFABRIC_MR_KEY_BASE 0x80000000u

/* Max iovec elements gathered into one provider op (stack arrays);
 * the effective limit is min of this and the provider's iov_limit */
#define EVPL_LIBFABRIC_MAX_IOV     16

/* Bounded rearm attempts in the poll-exit trywait loop */
#define EVPL_LIBFABRIC_TRYWAIT_MAX 8

/* Manual-progress backstop tick while any endpoint exists */
#define EVPL_LIBFABRIC_TICK_US     1000

#define EVPL_LIBFABRIC_OP_RECV     0
#define EVPL_LIBFABRIC_OP_SEND     1
#define EVPL_LIBFABRIC_OP_READ     2
#define EVPL_LIBFABRIC_OP_WRITE    3

/* One (fabric, domain) pair; for the tcp provider this corresponds to a
 * network interface, for verbs to an HCA port.  Shared by all threads,
 * mirroring rdmacm's per-device parent PDs. */
/* A device is one (fabric, domain, endpoint type): providers refuse to
 * host endpoints of a different type than the domain was opened for, so
 * MSG and RDM each get their own domain per interface/HCA */
struct evpl_libfabric_device {
    struct fid_fabric *fabric;
    struct fid_domain *domain;
    struct fid_av     *av;        /* shared across threads; RDM only, lazy */
    struct fi_info    *info;      /* dup'd getinfo result */
    enum fi_ep_type    ep_type;
    uint64_t           mr_mode;
    int                mr_local;  /* desc required on local ops */
    int                mr_virt_addr;
    size_t             iov_limit;
    size_t             rma_iov_limit;
    size_t             inject_size;
    size_t             tx_size;
    size_t             rx_size;
    int                index;
};

/* Process-global framework state (evpl_shared->framework_private) */
struct evpl_libfabric_devices {
    struct evpl_libfabric_device *devices;
    int                           num_devices;
    int                           external; /* app-owned domain: never close */
    uint32_t                      next_mr_key;
    pthread_mutex_t               lock;
};

/* Per-slab registration state: one entry per device, like rdmacm's mrset */
struct evpl_libfabric_mr {
    struct fid_mr *mr;
    void          *base; /* slab base, for offset-mode rma addressing */
    uint32_t       key;
};

struct evpl_libfabric;

/* Per-thread per-device state (CQ/EQ opened lazily on first use) */
struct evpl_libfabric_thread_device {
    struct evpl_libfabric        *lf;
    struct evpl_libfabric_device *dev;
    struct fid_cq                *cq;
    struct fid_eq                *eq;
    int                           cq_wait_mode; /* FI_WAIT_FD/POLLFD/NONE */
    int                           eq_wait_mode;
    struct evpl_event             cq_event;
    struct evpl_event             eq_event;
    int                           cq_epfd; /* FI_WAIT_POLLFD only */
    int                           eq_epfd;
    uint64_t                      cq_change_index;
    uint64_t                      eq_change_index;
    int                           num_ep;
};

/* Per-op context, pooled per thread.  The provider scratch area
 * (fi_context2) MUST be the first member: FI_CONTEXT/FI_CONTEXT2 mode
 * providers treat the op context pointer as their own storage. */
struct evpl_libfabric_ctx {
    struct fi_context2         fi_ctx;
    uint8_t                    op;
    uint8_t                    last; /* TX: completion retires the tail dgram */
    struct evpl_libfabric_ep  *lfep;
    struct evpl_iovec          iovec; /* RECV buffer / coalesced TX staging */
    struct evpl_libfabric_ctx *prev;
    struct evpl_libfabric_ctx *next;
};

/* Per-thread framework state */
struct evpl_libfabric {
    struct evpl                          *evpl;
    struct evpl_libfabric_devices        *shared;
    struct evpl_libfabric_thread_device  *devices;
    int                                   num_devices;
    struct evpl_libfabric_thread_device **active_devices;
    int                                   num_active_devices;
    int                                   num_eps;
    struct evpl_poll                     *poll;
    struct evpl_timer                     tick;
    int                                   tick_armed;
    struct evpl_libfabric_ctx            *free_ctx;
};

/* Per-bind protocol state, lives in evpl_bind_private() */
struct evpl_libfabric_ep {
    struct evpl_libfabric               *lf;
    struct evpl_libfabric_thread_device *tdev;
    struct fid_ep                       *ep;
    struct fid_pep                      *pep;  /* listeners only */
    struct fi_info                      *info; /* owned; freed at close */
    int                                  stream;
    int                                  rdm;
    int                                  connected;
    int                                  closed;
    int                                  cur_sends;
    int                                  cur_rdma_reads;
    int                                  rq_posted;
    uint64_t                             send_offset; /* bytes of the waist
                                                       * dgram already posted */
    uint64_t                             read_offset; /* likewise, dgram_read */
    struct evpl_libfabric_ctx           *posted_recvs;
    struct evpl_libfabric_ctx           *posted_sends;
};

/* FI_CONNREQ handoff from the listener thread to a worker's attach() */
struct evpl_libfabric_accepted {
    struct fi_info *info;
};

/* Per-destination state cached on the evpl_address (RDM protocol):
 * fi_addr_t values are AV-scoped and the AV is per device */
struct evpl_libfabric_peer {
    int       num_devices;
    uint8_t  *valid;
    fi_addr_t fi_addr[]; /* trailed by valid[] storage */
};

/*
 * Framework: process-global state
 */

static struct fi_info *
evpl_libfabric_hints_type(
    enum fi_ep_type ep_type,
    uint64_t        caps)
{
    struct evpl_global_config *config = evpl_shared->config;
    struct fi_info            *hints;

    hints = fi_allocinfo();

    evpl_libfabric_abort_if(!hints, "failed to allocate fi_info hints");

    hints->ep_attr->type          = ep_type;
    hints->caps                   = caps;
    hints->addr_format            = FI_SOCKADDR_IN;
    hints->mode                   = FI_CONTEXT | FI_CONTEXT2;
    hints->domain_attr->mr_mode   = FI_MR_LOCAL | FI_MR_VIRT_ADDR |
        FI_MR_ALLOCATED | FI_MR_PROV_KEY;
    hints->domain_attr->threading = FI_THREAD_SAFE;

    if (config->libfabric_provider) {
        hints->fabric_attr->prov_name = strdup(config->libfabric_provider);
    }

    return hints;
} /* evpl_libfabric_hints_type */

static struct fi_info *
evpl_libfabric_hints(void)
{
    return evpl_libfabric_hints_type(FI_EP_MSG, FI_MSG | FI_RMA);
} /* evpl_libfabric_hints */

static void
evpl_libfabric_init_devices(
    struct evpl_libfabric_devices *devices,
    struct fi_info                *info,
    enum fi_ep_type                ep_type)
{
    struct evpl_libfabric_device *dev;
    struct fi_info               *fi;
    int                           rc, i;

    for (fi = info; fi; fi = fi->next) {

        /* one device per distinct (fabric, domain, ep type); getinfo
         * returns multiple entries per domain for different capability
         * sets */
        for (i = 0; i < devices->num_devices; ++i) {
            if (devices->devices[i].ep_type == ep_type &&
                strcmp(devices->devices[i].info->domain_attr->name,
                       fi->domain_attr->name) == 0 &&
                strcmp(devices->devices[i].info->fabric_attr->name,
                       fi->fabric_attr->name) == 0) {
                break;
            }
        }

        if (i < devices->num_devices) {
            continue;
        }

        dev = &devices->devices[devices->num_devices];

        dev->info    = fi_dupinfo(fi);
        dev->ep_type = ep_type;

        rc = fi_fabric(dev->info->fabric_attr, &dev->fabric, NULL);

        if (rc) {
            evpl_libfabric_error("fi_fabric(%s): %s",
                                 dev->info->fabric_attr->name,
                                 fi_strerror(-rc));
            fi_freeinfo(dev->info);
            dev->info = NULL;
            continue;
        }

        rc = fi_domain(dev->fabric, dev->info, &dev->domain, NULL);

        if (rc) {
            evpl_libfabric_error("fi_domain(%s): %s",
                                 dev->info->domain_attr->name,
                                 fi_strerror(-rc));
            fi_close(&dev->fabric->fid);
            fi_freeinfo(dev->info);
            dev->info = NULL;
            continue;
        }

        dev->mr_mode       = dev->info->domain_attr->mr_mode;
        dev->mr_local      = !!(dev->mr_mode & FI_MR_LOCAL);
        dev->mr_virt_addr  = !!(dev->mr_mode & FI_MR_VIRT_ADDR);
        dev->iov_limit     = dev->info->tx_attr->iov_limit;
        dev->rma_iov_limit = dev->info->tx_attr->rma_iov_limit;
        dev->inject_size   = dev->info->tx_attr->inject_size;
        dev->tx_size       = dev->info->tx_attr->size;
        dev->rx_size       = dev->info->rx_attr->size;
        dev->index         = devices->num_devices;

        if (dev->iov_limit > EVPL_LIBFABRIC_MAX_IOV) {
            dev->iov_limit = EVPL_LIBFABRIC_MAX_IOV;
        }

        evpl_libfabric_debug(
            "device %d: prov %s fabric %s domain %s type %u mr_mode 0x%lx iov_limit %zu inject %zu",
            dev->index, dev->info->fabric_attr->prov_name,
            dev->info->fabric_attr->name, dev->info->domain_attr->name,
            dev->ep_type, dev->mr_mode, dev->iov_limit, dev->inject_size);

        devices->num_devices++;
    }
} /* evpl_libfabric_init_devices */

SYMBOL_EXPORT void
evpl_global_config_set_libfabric_external_domain(
    struct evpl_global_config *config,
    struct fid_fabric         *fabric,
    struct fid_domain         *domain,
    const struct fi_info      *info)
{
    config->libfabric_external_fabric = fabric;
    config->libfabric_external_domain = domain;
    config->libfabric_external_info   = info;
} /* evpl_global_config_set_libfabric_external_domain */

static void *
evpl_libfabric_init_external(void)
{
    struct evpl_global_config     *config = evpl_shared->config;
    struct evpl_libfabric_devices *devices;
    struct evpl_libfabric_device  *dev;

    evpl_libfabric_abort_if(!config->libfabric_external_fabric ||
                            !config->libfabric_external_info,
                            "external libfabric domain requires the fabric, "
                            "domain and fi_info it was created from");

    devices = evpl_zalloc(sizeof(*devices));

    pthread_mutex_init(&devices->lock, NULL);
    devices->next_mr_key = EVPL_LIBFABRIC_MR_KEY_BASE;
    devices->external    = 1;
    devices->devices     = evpl_zalloc(sizeof(*devices->devices));
    devices->num_devices = 1;

    dev = &devices->devices[0];

    dev->fabric  = config->libfabric_external_fabric;
    dev->domain  = config->libfabric_external_domain;
    dev->info    = fi_dupinfo(config->libfabric_external_info);
    dev->ep_type = dev->info->ep_attr->type;

    evpl_libfabric_abort_if(
        dev->info->domain_attr->threading == FI_THREAD_DOMAIN,
        "an external libfabric domain opened with FI_THREAD_DOMAIN cannot "
        "be shared across evpl threads");

    dev->mr_mode       = dev->info->domain_attr->mr_mode;
    dev->mr_local      = !!(dev->mr_mode & FI_MR_LOCAL);
    dev->mr_virt_addr  = !!(dev->mr_mode & FI_MR_VIRT_ADDR);
    dev->iov_limit     = dev->info->tx_attr->iov_limit;
    dev->rma_iov_limit = dev->info->tx_attr->rma_iov_limit;
    dev->inject_size   = dev->info->tx_attr->inject_size;
    dev->tx_size       = dev->info->tx_attr->size;
    dev->rx_size       = dev->info->rx_attr->size;
    dev->index         = 0;

    if (dev->iov_limit > EVPL_LIBFABRIC_MAX_IOV) {
        dev->iov_limit = EVPL_LIBFABRIC_MAX_IOV;
    }

    evpl_libfabric_debug(
        "external device: prov %s fabric %s domain %s type %u mr_mode 0x%lx",
        dev->info->fabric_attr->prov_name, dev->info->fabric_attr->name,
        dev->info->domain_attr->name, dev->ep_type, dev->mr_mode);

    return devices;
} /* evpl_libfabric_init_external */

static void *
evpl_libfabric_init(void)
{
    struct evpl_libfabric_devices *devices;
    struct fi_info                *hints, *msg_info, *rdm_info, *fi;
    int                            rc, n;

    if (evpl_shared->config->libfabric_external_domain) {
        return evpl_libfabric_init_external();
    }

    hints = evpl_libfabric_hints();

    rc = fi_getinfo(EVPL_LIBFABRIC_API_VERSION, NULL, NULL, 0, hints,
                    &msg_info);

    fi_freeinfo(hints);

    if (rc) {
        evpl_libfabric_info(
            "no usable libfabric provider (%s); libfabric protocols unavailable",
            fi_strerror(-rc));
        return NULL;
    }

    hints = evpl_libfabric_hints_type(FI_EP_RDM, FI_MSG | FI_SOURCE);

    rc = fi_getinfo(EVPL_LIBFABRIC_API_VERSION, NULL, NULL, 0, hints,
                    &rdm_info);

    fi_freeinfo(hints);

    if (rc) {
        rdm_info = NULL;
    }

    devices = evpl_zalloc(sizeof(*devices));

    pthread_mutex_init(&devices->lock, NULL);
    devices->next_mr_key = EVPL_LIBFABRIC_MR_KEY_BASE;

    n = 0;
    for (fi = msg_info; fi; fi = fi->next) {
        n++;
    }
    for (fi = rdm_info; fi; fi = fi->next) {
        n++;
    }

    devices->devices = evpl_zalloc(sizeof(*devices->devices) * n);

    evpl_libfabric_init_devices(devices, msg_info, FI_EP_MSG);
    evpl_libfabric_init_devices(devices, rdm_info, FI_EP_RDM);

    fi_freeinfo(msg_info);

    if (rdm_info) {
        fi_freeinfo(rdm_info);
    }

    if (devices->num_devices == 0) {
        evpl_libfabric_info(
            "no usable libfabric device; libfabric protocols unavailable");
        pthread_mutex_destroy(&devices->lock);
        evpl_free(devices->devices);
        evpl_free(devices);
        return NULL;
    }

    return devices;
} /* evpl_libfabric_init */

static void
evpl_libfabric_cleanup(void *private_data)
{
    struct evpl_libfabric_devices *devices = private_data;
    struct evpl_libfabric_device  *dev;
    int                            i;

    for (i = 0; i < devices->num_devices; ++i) {
        dev = &devices->devices[i];

        if (dev->av) {
            fi_close(&dev->av->fid);
        }

        if (!devices->external) {
            fi_close(&dev->domain->fid);
            fi_close(&dev->fabric->fid);
        }

        fi_freeinfo(dev->info);
    }

    pthread_mutex_destroy(&devices->lock);
    evpl_free(devices->devices);
    evpl_free(devices);
} /* evpl_libfabric_cleanup */

/*
 * Memory registration
 */

static void *
evpl_libfabric_register(
    void *buffer,
    int   size,
    void *buffer_private,
    void *framework_global)
{
    struct evpl_libfabric_devices *devices = framework_global;
    struct evpl_libfabric_device  *dev;
    struct evpl_libfabric_mr      *mrset   = buffer_private;
    uint64_t                       requested_key;
    int                            rc, i;

    if (!mrset) {
        mrset = evpl_zalloc(sizeof(*mrset) * devices->num_devices);
    }

    for (i = 0; i < devices->num_devices; ++i) {
        dev = &devices->devices[i];

        if (mrset[i].mr) {
            continue;
        }

        if (dev->mr_mode & FI_MR_PROV_KEY) {
            requested_key = 0;
        } else {
            pthread_mutex_lock(&devices->lock);
            requested_key = devices->next_mr_key++;
            pthread_mutex_unlock(&devices->lock);
        }

        rc = fi_mr_reg(dev->domain, buffer, size,
                       FI_SEND | FI_RECV | FI_READ | FI_WRITE |
                       FI_REMOTE_READ | FI_REMOTE_WRITE,
                       0, requested_key, 0, &mrset[i].mr, NULL);

        evpl_libfabric_abort_if(rc, "fi_mr_reg(%s, %p, %d): %s",
                                dev->info->domain_attr->name, buffer, size,
                                fi_strerror(-rc));

        /* evpl advertises 32-bit rkeys (the NFS-RDMA and SMB-Direct wire
         * formats are 32-bit); refuse providers that mint wider keys */
        evpl_libfabric_abort_if(fi_mr_key(mrset[i].mr) > UINT32_MAX,
                                "provider %s produces 64-bit MR keys, "
                                "incompatible with evpl's 32-bit rdma key API",
                                dev->info->fabric_attr->prov_name);

        mrset[i].base = buffer;
        mrset[i].key  = (uint32_t) fi_mr_key(mrset[i].mr);
    }

    return mrset;
} /* evpl_libfabric_register */

static void
evpl_libfabric_unregister(
    void *buffer_private,
    void *framework_global)
{
    struct evpl_libfabric_devices *devices = framework_global;
    struct evpl_libfabric_mr      *mrset   = buffer_private;
    int                            i;

    for (i = 0; i < devices->num_devices; ++i) {
        if (mrset[i].mr) {
            fi_close(&mrset[i].mr->fid);
        }
    }

    evpl_free(mrset);
} /* evpl_libfabric_unregister */

static void
evpl_libfabric_get_rdma_address(
    struct evpl_bind  *bind,
    struct evpl_iovec *iov,
    uint32_t          *r_key,
    uint64_t          *r_address)
{
    struct evpl_libfabric_ep      *lfep = evpl_bind_private(bind);
    struct evpl_libfabric_devices *devices;
    struct evpl_libfabric_device  *dev;
    struct evpl_libfabric_mr      *mrset;

    if (lfep->tdev) {
        dev = lfep->tdev->dev;
    } else {
        /* An accepted bind's attach callback runs before the protocol
         * attach, so the bind may not be tied to a device yet; keys are
         * per device, so this is only unambiguous with a single device */
        devices = evpl_shared->framework_private[EVPL_FRAMEWORK_LIBFABRIC];

        evpl_libfabric_abort_if(!devices,
                                "rdma address requested with no libfabric devices");

        dev = NULL;

        for (int i = 0; i < devices->num_devices; ++i) {
            if (devices->devices[i].ep_type == FI_EP_MSG) {
                if (dev) {
                    evpl_libfabric_debug(
                        "rdma address requested before bind attached to a "
                        "device; assuming the first MSG device");
                    break;
                }
                dev = &devices->devices[i];
            }
        }

        evpl_libfabric_abort_if(!dev,
                                "rdma address requested with no MSG-capable device");
    }

    mrset = evpl_memory_framework_private(iov, EVPL_FRAMEWORK_LIBFABRIC);

    evpl_libfabric_abort_if(!mrset || !mrset[dev->index].mr,
                            "rdma address requested for unregistered memory");

    *r_key = mrset[dev->index].key;

    if (dev->mr_virt_addr) {
        *r_address = (uint64_t) iov->data;
    } else {
        *r_address = (uint64_t) ((char *) iov->data -
                                 (char *) mrset[dev->index].base);
    }
} /* evpl_libfabric_get_rdma_address */

static void
evpl_libfabric_release_address(
    void *address_private,
    void *framework_global)
{
    struct evpl_libfabric_peer    *peer    = address_private;
    struct evpl_libfabric_devices *devices = framework_global;
    int                            i;

    for (i = 0; i < peer->num_devices; ++i) {
        if (peer->valid[i] && devices->devices[i].av) {
            fi_av_remove(devices->devices[i].av, &peer->fi_addr[i], 1, 0);
        }
    }

    evpl_free(peer);
} /* evpl_libfabric_release_address */

/* Open the shared per-device address vector on first RDM use */
static struct fid_av *
evpl_libfabric_device_av(
    struct evpl_libfabric_devices *devices,
    struct evpl_libfabric_device  *dev)
{
    struct fi_av_attr av_attr;
    int               rc;

    pthread_mutex_lock(&devices->lock);

    if (!dev->av) {
        memset(&av_attr, 0, sizeof(av_attr));
        av_attr.type = FI_AV_UNSPEC;

        rc = fi_av_open(dev->domain, &av_attr, &dev->av, NULL);

        evpl_libfabric_abort_if(rc, "fi_av_open(%s): %s",
                                dev->info->domain_attr->name,
                                fi_strerror(-rc));
    }

    pthread_mutex_unlock(&devices->lock);

    return dev->av;
} /* evpl_libfabric_device_av */

/* Resolve an evpl address to this device's fi_addr_t, caching on the
 * address private slot */
static fi_addr_t
evpl_libfabric_peer_resolve(
    struct evpl_libfabric        *lf,
    struct evpl_libfabric_device *dev,
    struct evpl_address          *addr)
{
    struct evpl_libfabric_devices *devices = lf->shared;
    struct evpl_libfabric_peer    *peer;
    int                            rc;

    peer = evpl_address_private(addr, EVPL_FRAMEWORK_LIBFABRIC);

    if (!peer) {
        peer = evpl_zalloc(sizeof(*peer) +
                           devices->num_devices * sizeof(fi_addr_t) +
                           devices->num_devices * sizeof(uint8_t));

        peer->num_devices = devices->num_devices;
        peer->valid       = (uint8_t *) &peer->fi_addr[devices->num_devices];

        evpl_address_set_private(addr, EVPL_FRAMEWORK_LIBFABRIC, peer);
    }

    if (!peer->valid[dev->index]) {

        rc = fi_av_insert(evpl_libfabric_device_av(devices, dev),
                          addr->addr, 1, &peer->fi_addr[dev->index], 0, NULL);

        evpl_libfabric_abort_if(rc != 1, "fi_av_insert: %s",
                                rc < 0 ? fi_strerror(-rc) : "no address inserted");

        peer->valid[dev->index] = 1;
    }

    return peer->fi_addr[dev->index];
} /* evpl_libfabric_peer_resolve */

/*
 * Op context pool
 */

static struct evpl_libfabric_ctx *
evpl_libfabric_ctx_alloc(struct evpl_libfabric *lf)
{
    struct evpl_libfabric_ctx *ctx = lf->free_ctx;

    if (ctx) {
        DL_DELETE(lf->free_ctx, ctx);
    } else {
        ctx = evpl_zalloc(sizeof(*ctx));
    }

    ctx->last        = 0;
    ctx->iovec.data  = NULL;
    ctx->iovec.ref   = NULL;

    return ctx;
} /* evpl_libfabric_ctx_alloc */

static void
evpl_libfabric_ctx_free(
    struct evpl_libfabric     *lf,
    struct evpl_libfabric_ctx *ctx)
{
    DL_PREPEND(lf->free_ctx, ctx);
} /* evpl_libfabric_ctx_free */

/*
 * Address helpers
 */

static void
evpl_libfabric_addr_strings(
    struct evpl_address *addr,
    char                *node,
    size_t               node_len,
    char                *service,
    size_t               service_len)
{
    struct sockaddr_in  *sin;
    struct sockaddr_in6 *sin6;

    if (addr->addr->sa_family == AF_INET) {
        sin = (struct sockaddr_in *) addr->addr;
        inet_ntop(AF_INET, &sin->sin_addr, node, node_len);
        snprintf(service, service_len, "%u", ntohs(sin->sin_port));
    } else if (addr->addr->sa_family == AF_INET6) {
        sin6 = (struct sockaddr_in6 *) addr->addr;
        inet_ntop(AF_INET6, &sin6->sin6_addr, node, node_len);
        snprintf(service, service_len, "%u", ntohs(sin6->sin6_port));
    } else {
        evpl_libfabric_abort("unsupported address family %u",
                             addr->addr->sa_family);
    }
} /* evpl_libfabric_addr_strings */

static int
evpl_libfabric_match_device(
    struct evpl_libfabric *lf,
    struct fi_info        *info)
{
    struct evpl_libfabric_devices *devices = lf->shared;
    int                            i;

    for (i = 0; i < devices->num_devices; ++i) {
        if (devices->devices[i].ep_type == info->ep_attr->type &&
            strcmp(devices->devices[i].info->domain_attr->name,
                   info->domain_attr->name) == 0 &&
            strcmp(devices->devices[i].info->fabric_attr->name,
                   info->fabric_attr->name) == 0) {
            return i;
        }
    }

    return -1;
} /* evpl_libfabric_match_device */

static int
evpl_libfabric_first_device_of_type(
    struct evpl_libfabric *lf,
    enum fi_ep_type        ep_type)
{
    struct evpl_libfabric_devices *devices = lf->shared;
    int                            i;

    for (i = 0; i < devices->num_devices; ++i) {
        if (devices->devices[i].ep_type == ep_type) {
            return i;
        }
    }

    return -1;
} /* evpl_libfabric_first_device_of_type */

/* Match a connection's fi_info to a device by the source (local interface)
 * address; the tcp provider reports the generic domain name "tcp" on
 * connection requests arriving at a wildcard-bound passive endpoint, so
 * name matching alone is not sufficient there */
static int
evpl_libfabric_match_device_by_addr(
    struct evpl_libfabric *lf,
    struct fi_info        *info)
{
    struct evpl_libfabric_devices *devices = lf->shared;
    struct sockaddr_in            *sin, *dev_sin;
    struct sockaddr_in6           *sin6, *dev_sin6;
    struct fi_info                *dev_info;
    int                            i;

    if (!info->src_addr || !info->src_addrlen) {
        return -1;
    }

    for (i = 0; i < devices->num_devices; ++i) {
        dev_info = devices->devices[i].info;

        if (devices->devices[i].ep_type != info->ep_attr->type ||
            !dev_info->src_addr ||
            dev_info->addr_format != info->addr_format) {
            continue;
        }

        if (info->addr_format == FI_SOCKADDR_IN) {
            sin     = info->src_addr;
            dev_sin = dev_info->src_addr;

            if (sin->sin_addr.s_addr == dev_sin->sin_addr.s_addr) {
                return i;
            }
        } else if (info->addr_format == FI_SOCKADDR_IN6) {
            sin6     = info->src_addr;
            dev_sin6 = dev_info->src_addr;

            if (memcmp(&sin6->sin6_addr, &dev_sin6->sin6_addr,
                       sizeof(sin6->sin6_addr)) == 0) {
                return i;
            }
        }
    }

    return -1;
} /* evpl_libfabric_match_device_by_addr */

static int
evpl_libfabric_addr_is_wildcard(struct evpl_address *addr)
{
    struct sockaddr_in  *sin;
    struct sockaddr_in6 *sin6;

    if (addr->addr->sa_family == AF_INET) {
        sin = (struct sockaddr_in *) addr->addr;
        return sin->sin_addr.s_addr == htonl(INADDR_ANY);
    }

    if (addr->addr->sa_family == AF_INET6) {
        sin6 = (struct sockaddr_in6 *) addr->addr;
        return IN6_IS_ADDR_UNSPECIFIED(&sin6->sin6_addr);
    }

    return 0;
} /* evpl_libfabric_addr_is_wildcard */

/*
 * Completion and event processing
 */

static int  evpl_libfabric_poll_cq(
    struct evpl                         *evpl,
    struct evpl_libfabric_thread_device *tdev,
    int                                  drain);

static int  evpl_libfabric_drain_eq(
    struct evpl                         *evpl,
    struct evpl_libfabric_thread_device *tdev,
    struct fid                          *closed_fid);

static void evpl_libfabric_fill_rq(
    struct evpl              *evpl,
    struct evpl_libfabric_ep *lfep);

static void
evpl_libfabric_handle_recv(
    struct evpl               *evpl,
    struct evpl_libfabric_ctx *ctx,
    size_t                     len,
    fi_addr_t                  src)
{
    struct evpl_libfabric_ep *lfep = ctx->lfep;
    struct evpl_libfabric    *lf   = lfep->lf;
    struct evpl_bind         *bind;
    struct evpl_address      *addr;
    struct evpl_notify        notify;
    struct sockaddr_storage   ss;
    size_t                    sslen;
    int                       rc;

    DL_DELETE(lfep->posted_recvs, ctx);
    lfep->rq_posted--;

    if (unlikely(lfep->closed)) {
        evpl_iovec_release_internal(evpl, &ctx->iovec);
        evpl_libfabric_ctx_free(lf, ctx);
        return;
    }

    bind = evpl_private2bind(lfep);

    ctx->iovec.length = len;

    if (lfep->stream) {

        evpl_iovec_ring_add(&bind->iovec_recv, &ctx->iovec);

        notify.notify_type   = EVPL_NOTIFY_RECV_DATA;
        notify.notify_status = 0;

        bind->notify_callback(evpl, bind, &notify, bind->private_data);

    } else {

        addr = NULL;

        if (lfep->rdm && src != FI_ADDR_NOTAVAIL) {

            sslen = sizeof(ss);

            rc = fi_av_lookup(lfep->tdev->dev->av, src,
                              &ss, &sslen);

            if (rc == 0) {
                addr = evpl_address_init((struct sockaddr *) &ss, sslen);
            }
        }

        /* the iovec reference is donated to the callback, matching the
         * datagram convention of the udp and rdmacm backends */
        notify.notify_type     = EVPL_NOTIFY_RECV_MSG;
        notify.notify_status   = 0;
        notify.recv_msg.iovec  = &ctx->iovec;
        notify.recv_msg.niov   = 1;
        notify.recv_msg.length = len;
        notify.recv_msg.addr   = addr ? addr : bind->remote;

        bind->notify_callback(evpl, bind, &notify, bind->private_data);

        if (addr) {
            evpl_address_release(addr);
        }
    }

    evpl_libfabric_ctx_free(lf, ctx);

    evpl_libfabric_fill_rq(evpl, lfep);
} /* evpl_libfabric_handle_recv */

static void
evpl_libfabric_handle_send(
    struct evpl               *evpl,
    struct evpl_libfabric_ctx *ctx,
    int                        status)
{
    struct evpl_libfabric_ep *lfep = ctx->lfep;
    struct evpl_libfabric    *lf   = lfep->lf;
    struct evpl_bind         *bind;
    struct evpl_dgram        *dgram;
    struct evpl_iovec        *iovec;
    struct evpl_notify        notify;
    uint64_t                  length;
    uint8_t                   dgram_type;
    void                      (*callback)(
        int   cb_status,
        void *cb_private_data);
    void                     *private_data;
    int                       i, niov;

    DL_DELETE(lfep->posted_sends, ctx);
    lfep->cur_sends--;

    if (ctx->iovec.ref) {
        /* coalesced staging buffer */
        evpl_iovec_release_internal(evpl, &ctx->iovec);
    }

    if (unlikely(lfep->closed)) {
        evpl_libfabric_ctx_free(lf, ctx);
        return;
    }

    if (!ctx->last) {
        evpl_libfabric_ctx_free(lf, ctx);
        return;
    }

    evpl_libfabric_ctx_free(lf, ctx);

    bind = evpl_private2bind(lfep);

    dgram = evpl_dgram_ring_tail(&bind->dgram_send);

    evpl_libfabric_abort_if(!dgram, "send completion with empty dgram ring");

    niov         = dgram->niov;
    length       = dgram->length;
    dgram_type   = dgram->dgram_type;
    callback     = dgram->callback;
    private_data = dgram->private_data;

    /* unconnected sends carry an address reference from endpoint
     * resolution, dropped once the datagram is on the wire (udp.c does
     * the same in its transmit path) */
    if (lfep->rdm && dgram->addr) {
        evpl_address_release(dgram->addr);
    }

    evpl_dgram_ring_remove(&bind->dgram_send);

    for (i = 0; i < niov; ++i) {
        iovec = evpl_iovec_ring_tail(&bind->iovec_send);
        evpl_iovec_release_internal(evpl, iovec);
        evpl_iovec_ring_remove(&bind->iovec_send);
    }

    if (dgram_type == EVPL_DGRAM_TYPE_RDMA_WRITE) {
        if (callback) {
            callback(status, private_data);
        }
    } else if (status == 0 && (bind->flags & EVPL_BIND_SENT_NOTIFY)) {
        notify.notify_type   = EVPL_NOTIFY_SENT;
        notify.notify_status = 0;
        notify.sent.bytes    = length;
        notify.sent.msgs     = 1;

        bind->notify_callback(evpl, bind, &notify, bind->private_data);
    }

    if (unlikely(lfep->cur_sends == 0 &&
                 evpl_iovec_ring_is_empty(&bind->iovec_send))) {
        if (bind->flags & EVPL_BIND_FINISH) {
            evpl_close(evpl, bind);
            return;
        }
    }

    if (!evpl_dgram_ring_is_empty(&bind->dgram_send)) {
        evpl_defer(evpl, &bind->flush_deferral);
    }
} /* evpl_libfabric_handle_send */

static void
evpl_libfabric_handle_read(
    struct evpl               *evpl,
    struct evpl_libfabric_ctx *ctx,
    int                        status)
{
    struct evpl_libfabric_ep *lfep = ctx->lfep;
    struct evpl_libfabric    *lf   = lfep->lf;
    struct evpl_bind         *bind;
    struct evpl_dgram        *dgram;
    struct evpl_iovec        *iovec;
    void                      (*callback)(
        int   cb_status,
        void *cb_private_data);
    void                     *private_data;
    int                       i, niov;

    DL_DELETE(lfep->posted_sends, ctx);
    lfep->cur_rdma_reads--;

    if (unlikely(lfep->closed) || !ctx->last) {
        evpl_libfabric_ctx_free(lf, ctx);
        return;
    }

    evpl_libfabric_ctx_free(lf, ctx);

    bind = evpl_private2bind(lfep);

    dgram = evpl_dgram_ring_tail(&bind->dgram_read);

    evpl_libfabric_abort_if(!dgram, "read completion with empty dgram ring");

    niov         = dgram->niov;
    callback     = dgram->callback;
    private_data = dgram->private_data;

    evpl_dgram_ring_remove(&bind->dgram_read);

    for (i = 0; i < niov; ++i) {
        iovec = evpl_iovec_ring_tail(&bind->iovec_rdma_read);
        evpl_iovec_release_internal(evpl, iovec);
        evpl_iovec_ring_remove(&bind->iovec_rdma_read);
    }

    if (callback) {
        callback(status, private_data);
    }

    if (!evpl_dgram_ring_is_empty(&bind->dgram_read)) {
        evpl_defer(evpl, &bind->flush_deferral);
    }
} /* evpl_libfabric_handle_read */

static void
evpl_libfabric_handle_cq_error(
    struct evpl                         *evpl,
    struct evpl_libfabric_thread_device *tdev)
{
    struct evpl_libfabric_ctx *ctx;
    struct evpl_libfabric_ep  *lfep;
    struct fi_cq_err_entry     err;
    ssize_t                    rc;

    memset(&err, 0, sizeof(err));

    rc = fi_cq_readerr(tdev->cq, &err, 0);

    if (rc < 0) {
        return;
    }

    ctx  = err.op_context;
    lfep = ctx->lfep;

    if (err.err != FI_ECANCELED && !lfep->closed) {
        evpl_libfabric_error("completion error op %u err %d (%s) prov_errno %d",
                             ctx->op, err.err, fi_strerror(err.err),
                             err.prov_errno);
    }

    switch (ctx->op) {
        case EVPL_LIBFABRIC_OP_RECV:
            DL_DELETE(lfep->posted_recvs, ctx);
            lfep->rq_posted--;
            evpl_iovec_release_internal(evpl, &ctx->iovec);
            evpl_libfabric_ctx_free(lfep->lf, ctx);
            break;
        case EVPL_LIBFABRIC_OP_SEND:
            evpl_libfabric_handle_send(evpl, ctx, EIO);
            break;
        case EVPL_LIBFABRIC_OP_READ:
            evpl_libfabric_handle_read(evpl, ctx, EIO);
            break;
        default:
            evpl_libfabric_abort("cq error for unknown op %u", ctx->op);
    } /* switch */
} /* evpl_libfabric_handle_cq_error */

static int
evpl_libfabric_poll_cq(
    struct evpl                         *evpl,
    struct evpl_libfabric_thread_device *tdev,
    int                                  drain)
{
    struct fi_cq_msg_entry     comps[64];
    fi_addr_t                  src[64];
    struct evpl_libfabric_ctx *ctx;
    ssize_t                    n;
    int                        i, total = 0;

    if (!tdev->cq) {
        return 0;
    }

 again:

    n = fi_cq_readfrom(tdev->cq, comps, 64, src);

    if (n == -FI_EAGAIN) {
        return total;
    }

    if (n == -FI_EAVAIL) {
        evpl_libfabric_handle_cq_error(evpl, tdev);
        total++;
        goto again;
    }

    evpl_libfabric_abort_if(n < 0, "fi_cq_readfrom: %s", fi_strerror(-n));

    evpl_activity(evpl);

    for (i = 0; i < n; ++i) {

        ctx = comps[i].op_context;

        switch (ctx->op) {
            case EVPL_LIBFABRIC_OP_RECV:
                evpl_libfabric_handle_recv(evpl, ctx, comps[i].len, src[i]);
                break;
            case EVPL_LIBFABRIC_OP_SEND:
                evpl_libfabric_handle_send(evpl, ctx, 0);
                break;
            case EVPL_LIBFABRIC_OP_READ:
                evpl_libfabric_handle_read(evpl, ctx, 0);
                break;
            default:
                evpl_libfabric_abort("unknown completion op %u", ctx->op);
        } /* switch */
    }

    total += n;

    if (drain && n > 0) {
        goto again;
    }

    return total;
} /* evpl_libfabric_poll_cq */

static void
evpl_libfabric_connected(
    struct evpl              *evpl,
    struct evpl_libfabric_ep *lfep)
{
    struct evpl_bind       *bind = evpl_private2bind(lfep);
    struct evpl_notify      notify;
    struct sockaddr_storage ss;
    size_t                  sslen = sizeof(ss);
    int                     rc;

    lfep->connected = 1;

    if (!bind->local) {
        rc = fi_getname(&lfep->ep->fid, &ss, &sslen);

        if (rc == 0) {
            bind->local = evpl_address_init((struct sockaddr *) &ss, sslen);
        }
    }

    notify.notify_type   = EVPL_NOTIFY_CONNECTED;
    notify.notify_status = 0;

    bind->notify_callback(evpl, bind, &notify, bind->private_data);

    evpl_defer(evpl, &bind->flush_deferral);
} /* evpl_libfabric_connected */

static void
evpl_libfabric_connreq(
    struct evpl              *evpl,
    struct evpl_libfabric_ep *lfep,
    struct fi_info           *info)
{
    struct evpl_bind               *listen_bind = evpl_private2bind(lfep);
    struct evpl_libfabric_accepted *accepted;
    struct evpl_address            *remote_addr;

    evpl_libfabric_abort_if(!info->dest_addr || !info->dest_addrlen,
                            "FI_CONNREQ without peer address");

    remote_addr = evpl_address_init(info->dest_addr, info->dest_addrlen);

    accepted       = evpl_zalloc(sizeof(*accepted));
    accepted->info = info;

    listen_bind->accept_callback(evpl,
                                 listen_bind,
                                 remote_addr,
                                 accepted,
                                 listen_bind->private_data);
} /* evpl_libfabric_connreq */

/* Drain the EQ.  closed_fid, when set, drops events for an endpoint that
 * has just been fi_close()d (its context can no longer be dereferenced) */
static int
evpl_libfabric_drain_eq(
    struct evpl                         *evpl,
    struct evpl_libfabric_thread_device *tdev,
    struct fid                          *closed_fid)
{
    struct evpl_libfabric_ep *lfep;
    struct evpl_bind         *bind;
    struct fi_eq_err_entry    err;
    uint32_t                  event;
    ssize_t                   rc;
    int                       total = 0;
    struct {
        struct fi_eq_cm_entry entry;
        uint8_t               data[256];
    } buf;

    if (!tdev->eq) {
        return 0;
    }

    for (;;) {

        rc = fi_eq_read(tdev->eq, &event, &buf, sizeof(buf), 0);

        if (rc == -FI_EAGAIN) {
            return total;
        }

        if (rc == -FI_EAVAIL) {

            memset(&err, 0, sizeof(err));

            rc = fi_eq_readerr(tdev->eq, &err, 0);

            if (rc < 0) {
                return total;
            }

            total++;

            if (closed_fid && err.fid == closed_fid) {
                continue;
            }

            lfep = err.fid ? err.fid->context : NULL;

            if (lfep && !lfep->closed) {
                evpl_libfabric_info("connection error: %s",
                                    fi_strerror(err.err));
                bind = evpl_private2bind(lfep);
                evpl_close(evpl, bind);
            }

            continue;
        }

        evpl_libfabric_abort_if(rc < 0, "fi_eq_read: %s", fi_strerror(-rc));

        total++;

        if (closed_fid && buf.entry.fid == closed_fid) {
            if (event == FI_CONNREQ) {
                fi_freeinfo(buf.entry.info);
            }
            continue;
        }

        evpl_activity(evpl);

        switch (event) {
            case FI_CONNREQ:
                lfep = buf.entry.fid->context;
                evpl_libfabric_connreq(evpl, lfep, buf.entry.info);
                break;
            case FI_CONNECTED:
                lfep = buf.entry.fid->context;
                evpl_libfabric_connected(evpl, lfep);
                break;
            case FI_SHUTDOWN:
                lfep = buf.entry.fid->context;

                lfep->connected = 0;

                bind = evpl_private2bind(lfep);

                if (bind->flags & EVPL_BIND_CLOSE_DEFERRED) {
                    bind->flags &= ~EVPL_BIND_CLOSE_DEFERRED;
                } else {
                    evpl_close(evpl, bind);
                }
                break;
            default:
                evpl_libfabric_debug("unhandled eq event %u", event);
        } /* switch */
    }
} /* evpl_libfabric_drain_eq */

/*
 * Wait object wiring
 */

static void
evpl_libfabric_cq_event_callback(
    struct evpl       *evpl,
    struct evpl_event *event)
{
    struct evpl_libfabric_thread_device *tdev =
        container_of(event, struct evpl_libfabric_thread_device, cq_event);

    evpl_libfabric_poll_cq(evpl, tdev, 1);

    evpl_event_mark_unreadable(evpl, event);
} /* evpl_libfabric_cq_event_callback */

static void
evpl_libfabric_eq_event_callback(
    struct evpl       *evpl,
    struct evpl_event *event)
{
    struct evpl_libfabric_thread_device *tdev =
        container_of(event, struct evpl_libfabric_thread_device, eq_event);

    evpl_libfabric_drain_eq(evpl, tdev, NULL);

    evpl_event_mark_unreadable(evpl, event);
} /* evpl_libfabric_eq_event_callback */

/* For FI_WAIT_POLLFD wait objects the provider exposes a mutable set of
 * fds; mirror them into a private epoll whose fd is what evpl watches */
static void
evpl_libfabric_pollfd_sync(
    struct fid *fid,
    int         epfd,
    uint64_t   *change_index)
{
    struct fi_wait_pollfd wp;
    struct pollfd         fds[64];
    struct epoll_event    ev;
    int                   rc, i;

    memset(&wp, 0, sizeof(wp));
    wp.nfds = 64;
    wp.fd   = fds;

    rc = fi_control(fid, FI_GETWAIT, &wp);

    if (rc != 0 || wp.nfds > 64) {
        return;
    }

    if (wp.change_index == *change_index) {
        return;
    }

    *change_index = wp.change_index;

    /* rebuild: EPOLL_CTL_ADD is idempotent-ish via EEXIST; stale members
     * are removed automatically when the provider closes those fds */
    for (i = 0; i < (int) wp.nfds; ++i) {
        memset(&ev, 0, sizeof(ev));
        ev.events  = fds[i].events;
        ev.data.fd = fds[i].fd;

        rc = epoll_ctl(epfd, EPOLL_CTL_ADD, fds[i].fd, &ev);

        if (rc && errno == EEXIST) {
            epoll_ctl(epfd, EPOLL_CTL_MOD, fds[i].fd, &ev);
        }
    }
} /* evpl_libfabric_pollfd_sync */

static void
evpl_libfabric_cq_pollfd_callback(
    struct evpl       *evpl,
    struct evpl_event *event)
{
    struct evpl_libfabric_thread_device *tdev =
        container_of(event, struct evpl_libfabric_thread_device, cq_event);
    struct epoll_event evs[8];

    /* consume readiness from the inner epoll */
    epoll_wait(tdev->cq_epfd, evs, 8, 0);

    evpl_libfabric_poll_cq(evpl, tdev, 1);

    evpl_libfabric_pollfd_sync(&tdev->cq->fid, tdev->cq_epfd,
                               &tdev->cq_change_index);

    evpl_event_mark_unreadable(evpl, event);
} /* evpl_libfabric_cq_pollfd_callback */

static void
evpl_libfabric_eq_pollfd_callback(
    struct evpl       *evpl,
    struct evpl_event *event)
{
    struct evpl_libfabric_thread_device *tdev =
        container_of(event, struct evpl_libfabric_thread_device, eq_event);
    struct epoll_event evs[8];

    epoll_wait(tdev->eq_epfd, evs, 8, 0);

    evpl_libfabric_drain_eq(evpl, tdev, NULL);

    evpl_libfabric_pollfd_sync(&tdev->eq->fid, tdev->eq_epfd,
                               &tdev->eq_change_index);

    evpl_event_mark_unreadable(evpl, event);
} /* evpl_libfabric_eq_pollfd_callback */

static void
evpl_libfabric_wire_wait(
    struct evpl                *evpl,
    struct fid                 *fid,
    int                         wait_mode,
    struct evpl_event          *event,
    int                        *epfd_out,
    uint64_t                   *change_index,
    evpl_event_read_callback_t  fd_callback,
    evpl_event_read_callback_t  pollfd_callback)
{
    int fd = -1;
    int rc;

    switch (wait_mode) {
        case FI_WAIT_FD:

            rc = fi_control(fid, FI_GETWAIT, &fd);

            evpl_libfabric_abort_if(rc, "fi_control(FI_GETWAIT): %s",
                                    fi_strerror(-rc));

            evpl_add_event(evpl, event, fd, fd_callback, NULL, NULL);
            evpl_event_read_interest(evpl, event);
            break;

        case FI_WAIT_POLLFD:

            *epfd_out = epoll_create1(EPOLL_CLOEXEC);

            evpl_libfabric_abort_if(*epfd_out < 0, "epoll_create1 failed");

            evpl_libfabric_pollfd_sync(fid, *epfd_out, change_index);

            evpl_add_event(evpl, event, *epfd_out, pollfd_callback, NULL, NULL);
            evpl_event_read_interest(evpl, event);
            break;

        default:
            /* FI_WAIT_NONE: progress via poll callbacks and the tick timer */
            break;
    } /* switch */
} /* evpl_libfabric_wire_wait */

static struct evpl_libfabric_thread_device *
evpl_libfabric_tdev_open(
    struct evpl           *evpl,
    struct evpl_libfabric *lf,
    int                    devindex)
{
    struct evpl_libfabric_thread_device *tdev = &lf->devices[devindex];
    struct evpl_libfabric_device        *dev  = tdev->dev;
    struct fi_cq_attr                    cq_attr;
    struct fi_eq_attr                    eq_attr;
    int                                  rc;

    if (tdev->cq) {
        return tdev;
    }

    memset(&cq_attr, 0, sizeof(cq_attr));
    cq_attr.size   = evpl_shared->config->libfabric_cq_size;
    cq_attr.format = FI_CQ_FORMAT_MSG;

    cq_attr.wait_obj = FI_WAIT_FD;
    rc               = fi_cq_open(dev->domain, &cq_attr, &tdev->cq, tdev);

    if (rc == 0) {
        tdev->cq_wait_mode = FI_WAIT_FD;
    } else {
        cq_attr.wait_obj = FI_WAIT_POLLFD;
        rc               = fi_cq_open(dev->domain, &cq_attr, &tdev->cq, tdev);

        if (rc == 0) {
            tdev->cq_wait_mode = FI_WAIT_POLLFD;
        } else {
            cq_attr.wait_obj = FI_WAIT_NONE;
            rc               = fi_cq_open(dev->domain, &cq_attr, &tdev->cq,
                                          tdev);

            evpl_libfabric_abort_if(rc, "fi_cq_open(%s): %s",
                                    dev->info->domain_attr->name,
                                    fi_strerror(-rc));

            tdev->cq_wait_mode = FI_WAIT_NONE;
        }
    }

    memset(&eq_attr, 0, sizeof(eq_attr));

    eq_attr.wait_obj = FI_WAIT_FD;
    rc               = fi_eq_open(dev->fabric, &eq_attr, &tdev->eq, tdev);

    if (rc == 0) {
        tdev->eq_wait_mode = FI_WAIT_FD;
    } else {
        eq_attr.wait_obj = FI_WAIT_POLLFD;
        rc               = fi_eq_open(dev->fabric, &eq_attr, &tdev->eq, tdev);

        if (rc == 0) {
            tdev->eq_wait_mode = FI_WAIT_POLLFD;
        } else {
            eq_attr.wait_obj = FI_WAIT_UNSPEC;
            rc               = fi_eq_open(dev->fabric, &eq_attr, &tdev->eq,
                                          tdev);

            evpl_libfabric_abort_if(rc, "fi_eq_open(%s): %s",
                                    dev->info->fabric_attr->name,
                                    fi_strerror(-rc));

            tdev->eq_wait_mode = FI_WAIT_NONE;
        }
    }

    evpl_libfabric_wire_wait(evpl, &tdev->cq->fid, tdev->cq_wait_mode,
                             &tdev->cq_event, &tdev->cq_epfd,
                             &tdev->cq_change_index,
                             evpl_libfabric_cq_event_callback,
                             evpl_libfabric_cq_pollfd_callback);

    evpl_libfabric_wire_wait(evpl, &tdev->eq->fid, tdev->eq_wait_mode,
                             &tdev->eq_event, &tdev->eq_epfd,
                             &tdev->eq_change_index,
                             evpl_libfabric_eq_event_callback,
                             evpl_libfabric_eq_pollfd_callback);

    return tdev;
} /* evpl_libfabric_tdev_open */

/*
 * Busy-poll integration
 */

static void
evpl_libfabric_poll_enter(
    struct evpl *evpl,
    void        *arg)
{
    struct evpl_libfabric               *lf = arg;
    struct evpl_libfabric_thread_device *tdev;
    int                                  i;

    for (i = 0; i < lf->num_active_devices; ++i) {
        tdev = lf->active_devices[i];

        if (tdev->cq_wait_mode != FI_WAIT_NONE) {
            evpl_event_read_disinterest(evpl, &tdev->cq_event);
        }
        if (tdev->eq_wait_mode != FI_WAIT_NONE) {
            evpl_event_read_disinterest(evpl, &tdev->eq_event);
        }
    }
} /* evpl_libfabric_poll_enter */

static void
evpl_libfabric_poll_exit(
    struct evpl *evpl,
    void        *arg)
{
    struct evpl_libfabric               *lf = arg;
    struct evpl_libfabric_thread_device *tdev;
    struct fid                          *fids[2];
    int                                  i, n, try;
    ssize_t                              rc;

    for (i = 0; i < lf->num_active_devices; ++i) {
        tdev = lf->active_devices[i];

        n = 0;

        if (tdev->cq_wait_mode != FI_WAIT_NONE) {
            evpl_event_read_interest(evpl, &tdev->cq_event);
            fids[n++] = &tdev->cq->fid;
        }
        if (tdev->eq_wait_mode != FI_WAIT_NONE) {
            evpl_event_read_interest(evpl, &tdev->eq_event);
            fids[n++] = &tdev->eq->fid;
        }

        if (n == 0) {
            continue;
        }

        /* arm the wait objects before the loop sleeps; -FI_EAGAIN means
         * work is already pending, so consume it and re-arm */
        for (try = 0; try < EVPL_LIBFABRIC_TRYWAIT_MAX; ++try) {

            rc = fi_trywait(tdev->dev->fabric, fids, n);

            if (rc == FI_SUCCESS) {
                break;
            }

            evpl_libfabric_poll_cq(evpl, tdev, 1);
            evpl_libfabric_drain_eq(evpl, tdev, NULL);
        }
    }
} /* evpl_libfabric_poll_exit */

static void
evpl_libfabric_poll(
    struct evpl *evpl,
    void        *arg)
{
    struct evpl_libfabric *lf = arg;
    int                    i;

    for (i = 0; i < lf->num_active_devices; ++i) {
        evpl_libfabric_poll_cq(evpl, lf->active_devices[i], 0);
        evpl_libfabric_drain_eq(evpl, lf->active_devices[i], NULL);
    }
} /* evpl_libfabric_poll */

/* Manual-progress backstop: providers such as tcp only advance internal
 * state (connection handshakes in particular) inside fi_* calls, and the
 * wait fd is not guaranteed to signal that pending internal work */
static void
evpl_libfabric_tick(
    struct evpl       *evpl,
    struct evpl_timer *timer)
{
    struct evpl_libfabric *lf = container_of(timer, struct evpl_libfabric,
                                             tick);

    evpl_libfabric_poll(evpl, lf);
} /* evpl_libfabric_tick */

static void
evpl_libfabric_ep_added(
    struct evpl                         *evpl,
    struct evpl_libfabric               *lf,
    struct evpl_libfabric_thread_device *tdev)
{
    if (tdev->num_ep == 0) {
        lf->active_devices[lf->num_active_devices++] = tdev;
    }

    tdev->num_ep++;
    lf->num_eps++;

    if (!lf->tick_armed) {
        evpl_add_timer(evpl, &lf->tick, evpl_libfabric_tick,
                       EVPL_LIBFABRIC_TICK_US);
        lf->tick_armed = 1;
    }
} /* evpl_libfabric_ep_added */

static void
evpl_libfabric_ep_removed(
    struct evpl                         *evpl,
    struct evpl_libfabric               *lf,
    struct evpl_libfabric_thread_device *tdev)
{
    int i;

    tdev->num_ep--;
    lf->num_eps--;

    if (tdev->num_ep == 0) {
        for (i = 0; i < lf->num_active_devices; ++i) {
            if (lf->active_devices[i] == tdev) {
                lf->active_devices[i] =
                    lf->active_devices[--lf->num_active_devices];
                break;
            }
        }
    }

    if (lf->num_eps == 0 && lf->tick_armed) {
        evpl_remove_timer(evpl, &lf->tick);
        lf->tick_armed = 0;
    }
} /* evpl_libfabric_ep_removed */

/*
 * Framework: per-thread state
 */

static void *
evpl_libfabric_create(
    struct evpl *evpl,
    void        *private_data)
{
    struct evpl_libfabric_devices *devices = private_data;
    struct evpl_libfabric         *lf;
    int                            i;

    if (!devices) {
        return NULL;
    }

    lf = evpl_zalloc(sizeof(*lf));

    lf->evpl           = evpl;
    lf->shared         = devices;
    lf->num_devices    = devices->num_devices;
    lf->devices        = evpl_zalloc(sizeof(*lf->devices) * lf->num_devices);
    lf->active_devices = evpl_zalloc(sizeof(*lf->active_devices) *
                                     lf->num_devices);

    for (i = 0; i < lf->num_devices; ++i) {
        lf->devices[i].lf      = lf;
        lf->devices[i].dev     = &devices->devices[i];
        lf->devices[i].cq_epfd = -1;
        lf->devices[i].eq_epfd = -1;
    }

    lf->poll = evpl_add_poll(evpl,
                             evpl_libfabric_poll_enter,
                             evpl_libfabric_poll_exit,
                             evpl_libfabric_poll,
                             lf);

    return lf;
} /* evpl_libfabric_create */

static void
evpl_libfabric_destroy(
    struct evpl *evpl,
    void        *private_data)
{
    struct evpl_libfabric               *lf = private_data;
    struct evpl_libfabric_thread_device *tdev;
    struct evpl_libfabric_ctx           *ctx;
    int                                  i;

    if (!lf) {
        return;
    }

    for (i = 0; i < lf->num_devices; ++i) {
        tdev = &lf->devices[i];

        if (tdev->cq && tdev->cq_wait_mode != FI_WAIT_NONE) {
            evpl_remove_event(evpl, &tdev->cq_event);
        }

        if (tdev->eq && tdev->eq_wait_mode != FI_WAIT_NONE) {
            evpl_remove_event(evpl, &tdev->eq_event);
        }

        if (tdev->cq) {
            fi_close(&tdev->cq->fid);
        }

        if (tdev->eq) {
            fi_close(&tdev->eq->fid);
        }

        if (tdev->cq_epfd >= 0) {
            close(tdev->cq_epfd);
        }

        if (tdev->eq_epfd >= 0) {
            close(tdev->eq_epfd);
        }
    }

    if (lf->tick_armed) {
        evpl_remove_timer(evpl, &lf->tick);
    }

    if (lf->poll) {
        evpl_remove_poll(evpl, lf->poll);
    }

    while (lf->free_ctx) {
        ctx = lf->free_ctx;
        DL_DELETE(lf->free_ctx, ctx);
        evpl_free(ctx);
    }

    evpl_free(lf->active_devices);
    evpl_free(lf->devices);
    evpl_free(lf);
} /* evpl_libfabric_destroy */

/*
 * Receive path
 */

static void
evpl_libfabric_fill_rq(
    struct evpl              *evpl,
    struct evpl_libfabric_ep *lfep)
{
    struct evpl_libfabric        *lf     = lfep->lf;
    struct evpl_libfabric_device *dev    = lfep->tdev->dev;
    struct evpl_global_config    *config = evpl_shared->config;
    struct evpl_libfabric_ctx    *ctx;
    struct evpl_libfabric_mr     *mrset;
    struct iovec                  iov;
    void                         *desc;
    struct fi_msg                 msg;
    unsigned int                  size;
    ssize_t                       rc;

    if (config->libfabric_datagram_size_override) {
        size = config->libfabric_datagram_size_override;
    } else {
        size = config->max_datagram_size;
    }

    while (lfep->rq_posted < (int) config->libfabric_rq_size) {

        ctx = evpl_libfabric_ctx_alloc(lf);

        ctx->op   = EVPL_LIBFABRIC_OP_RECV;
        ctx->lfep = lfep;

        evpl_iovec_alloc_datagram(evpl, &ctx->iovec, size);

        desc = NULL;

        if (dev->mr_local) {
            mrset = evpl_memory_framework_private(&ctx->iovec,
                                                  EVPL_FRAMEWORK_LIBFABRIC);
            desc = fi_mr_desc(mrset[dev->index].mr);
        }

        iov.iov_base = ctx->iovec.data;
        iov.iov_len  = ctx->iovec.length;

        memset(&msg, 0, sizeof(msg));
        msg.msg_iov   = &iov;
        msg.desc      = &desc;
        msg.iov_count = 1;
        msg.addr      = FI_ADDR_UNSPEC;
        msg.context   = ctx;

        rc = fi_recvmsg(lfep->ep, &msg, FI_COMPLETION);

        if (rc == -FI_EAGAIN) {
            evpl_iovec_release_internal(evpl, &ctx->iovec);
            evpl_libfabric_ctx_free(lf, ctx);
            break;
        }

        evpl_libfabric_abort_if(rc, "fi_recvmsg: %s", fi_strerror(-rc));

        DL_APPEND(lfep->posted_recvs, ctx);
        lfep->rq_posted++;
    }
} /* evpl_libfabric_fill_rq */

/*
 * Send path
 */

static inline size_t
evpl_libfabric_recv_capacity(void)
{
    struct evpl_global_config *config = evpl_shared->config;

    if (config->libfabric_datagram_size_override) {
        return config->libfabric_datagram_size_override;
    }

    return config->max_datagram_size;
} /* evpl_libfabric_recv_capacity */

/* Gather up to iov_limit elements / max_bytes bytes of the waist dgram
 * from `ring`, starting at the given byte offset.  Returns bytes gathered. */
static size_t
evpl_libfabric_gather(
    struct evpl_iovec_ring *ring,
    struct evpl_dgram      *dgram,
    uint64_t                offset,
    size_t                  max_iov,
    size_t                  max_bytes,
    struct iovec           *iov,
    void                  **desc,
    int                     mr_local,
    int                     devindex,
    size_t                 *r_niov)
{
    struct evpl_iovec        *cur;
    struct evpl_libfabric_mr *mrset;
    uint64_t                  skip = offset;
    size_t                    gathered = 0, chunk, niov = 0;
    int                       k;

    for (k = 0; k < dgram->niov && niov < max_iov && gathered < max_bytes;
         ++k) {

        cur = &ring->iovec[(ring->waist + k) & ring->mask];

        if (skip >= cur->length) {
            skip -= cur->length;
            continue;
        }

        chunk = cur->length - skip;

        if (chunk > max_bytes - gathered) {
            chunk = max_bytes - gathered;
        }

        iov[niov].iov_base = (char *) cur->data + skip;
        iov[niov].iov_len  = chunk;

        if (mr_local) {
            mrset = evpl_memory_framework_private(cur,
                                                  EVPL_FRAMEWORK_LIBFABRIC);
            desc[niov] = fi_mr_desc(mrset[devindex].mr);
        } else {
            desc[niov] = NULL;
        }

        gathered += chunk;
        skip      = 0;
        niov++;
    }

    *r_niov = niov;

    return gathered;
} /* evpl_libfabric_gather */

static void
evpl_libfabric_flush_rdma_reads(
    struct evpl      *evpl,
    struct evpl_bind *bind)
{
    struct evpl_libfabric_ep     *lfep = evpl_bind_private(bind);
    struct evpl_libfabric        *lf   = lfep->lf;
    struct evpl_libfabric_device *dev  = lfep->tdev->dev;
    struct evpl_libfabric_ctx    *ctx;
    struct evpl_dgram            *dgram;
    struct iovec                  iov[EVPL_LIBFABRIC_MAX_IOV];
    void                         *desc[EVPL_LIBFABRIC_MAX_IOV];
    struct fi_rma_iov             rma_iov;
    struct fi_msg_rma             msg;
    size_t                        niov, len;
    ssize_t                       rc;
    int                           read_limit;

    read_limit = evpl_shared->config->libfabric_tx_size;

    while (lfep->cur_rdma_reads < read_limit &&
           bind->dgram_read.waist != bind->dgram_read.head) {

        dgram = evpl_dgram_ring_waist(&bind->dgram_read);

        len = evpl_libfabric_gather(&bind->iovec_rdma_read, dgram,
                                    lfep->read_offset, dev->iov_limit,
                                    (size_t) -1, iov, desc, dev->mr_local,
                                    dev->index, &niov);

        ctx = evpl_libfabric_ctx_alloc(lf);

        ctx->op   = EVPL_LIBFABRIC_OP_READ;
        ctx->lfep = lfep;
        ctx->last = (lfep->read_offset + len == dgram->length);

        rma_iov.addr = dgram->remote_address + lfep->read_offset;
        rma_iov.len  = len;
        rma_iov.key  = dgram->remote_key;

        memset(&msg, 0, sizeof(msg));
        msg.msg_iov       = iov;
        msg.desc          = desc;
        msg.iov_count     = niov;
        msg.addr          = FI_ADDR_UNSPEC;
        msg.rma_iov       = &rma_iov;
        msg.rma_iov_count = 1;
        msg.context       = ctx;

        rc = fi_readmsg(lfep->ep, &msg, FI_COMPLETION);

        if (rc == -FI_EAGAIN) {
            evpl_libfabric_ctx_free(lf, ctx);
            /* nothing may be in flight to re-trigger us from the CQ */
            evpl_defer(evpl, &bind->flush_deferral);
            break;
        }

        evpl_libfabric_abort_if(rc, "fi_readmsg: %s", fi_strerror(-rc));

        DL_APPEND(lfep->posted_sends, ctx);
        lfep->cur_rdma_reads++;

        lfep->read_offset += len;

        if (lfep->read_offset == dgram->length) {

            bind->iovec_rdma_read.waist =
                (bind->iovec_rdma_read.waist + dgram->niov) &
                bind->iovec_rdma_read.mask;

            bind->dgram_read.waist =
                (bind->dgram_read.waist + 1) & bind->dgram_read.mask;

            lfep->read_offset = 0;
        }
    }
} /* evpl_libfabric_flush_rdma_reads */

static void
evpl_libfabric_flush(
    struct evpl      *evpl,
    struct evpl_bind *bind)
{
    struct evpl_libfabric_ep     *lfep = evpl_bind_private(bind);
    struct evpl_libfabric        *lf   = lfep->lf;
    struct evpl_libfabric_device *dev;
    struct evpl_libfabric_ctx    *ctx;
    struct evpl_dgram            *dgram;
    struct evpl_iovec            *cur;
    struct iovec                  iov[EVPL_LIBFABRIC_MAX_IOV];
    void                         *desc[EVPL_LIBFABRIC_MAX_IOV];
    struct fi_msg                 msg;
    struct fi_rma_iov             rma_iov;
    struct fi_msg_rma             rma_msg;
    uint64_t                      flags;
    fi_addr_t                     dest;
    size_t                        niov, len, cap;
    ssize_t                       rc;
    int                           k, tx_limit;

    if (unlikely(!lfep->ep || !lfep->connected)) {
        return;
    }

    dev      = lfep->tdev->dev;
    tx_limit = evpl_shared->config->libfabric_tx_size;
    cap      = evpl_libfabric_recv_capacity();

    evpl_libfabric_flush_rdma_reads(evpl, bind);

    while (lfep->cur_sends < tx_limit &&
           bind->dgram_send.waist != bind->dgram_send.head) {

        dgram = evpl_dgram_ring_waist(&bind->dgram_send);

        if (dgram->dgram_type == EVPL_DGRAM_TYPE_RDMA_WRITE) {

            len = evpl_libfabric_gather(&bind->iovec_send, dgram,
                                        lfep->send_offset, dev->iov_limit,
                                        (size_t) -1, iov, desc,
                                        dev->mr_local, dev->index, &niov);

            ctx = evpl_libfabric_ctx_alloc(lf);

            ctx->op   = EVPL_LIBFABRIC_OP_SEND;
            ctx->lfep = lfep;
            ctx->last = (lfep->send_offset + len == dgram->length);

            rma_iov.addr = dgram->remote_address + lfep->send_offset;
            rma_iov.len  = len;
            rma_iov.key  = dgram->remote_key;

            memset(&rma_msg, 0, sizeof(rma_msg));
            rma_msg.msg_iov       = iov;
            rma_msg.desc          = desc;
            rma_msg.iov_count     = niov;
            rma_msg.addr          = FI_ADDR_UNSPEC;
            rma_msg.rma_iov       = &rma_iov;
            rma_msg.rma_iov_count = 1;
            rma_msg.context       = ctx;

            rc = fi_writemsg(lfep->ep, &rma_msg, FI_COMPLETION);

            if (rc == -FI_EAGAIN) {
                evpl_libfabric_ctx_free(lf, ctx);
                evpl_defer(evpl, &bind->flush_deferral);
                break;
            }

            evpl_libfabric_abort_if(rc, "fi_writemsg: %s", fi_strerror(-rc));

            DL_APPEND(lfep->posted_sends, ctx);
            lfep->cur_sends++;

            lfep->send_offset += len;

            if (lfep->send_offset == dgram->length) {

                bind->iovec_send.waist =
                    (bind->iovec_send.waist + dgram->niov) &
                    bind->iovec_send.mask;

                bind->dgram_send.waist =
                    (bind->dgram_send.waist + 1) & bind->dgram_send.mask;

                lfep->send_offset = 0;
            }

            continue;
        }

        dest = FI_ADDR_UNSPEC;

        if (lfep->rdm) {
            dest = evpl_libfabric_peer_resolve(lf, dev, dgram->addr);
        }

        if (lfep->stream || dgram->niov <= (int) dev->iov_limit) {

            len = evpl_libfabric_gather(&bind->iovec_send, dgram,
                                        lfep->send_offset,
                                        dev->iov_limit,
                                        lfep->stream ? cap : (size_t) -1,
                                        iov, desc, dev->mr_local,
                                        dev->index, &niov);

            evpl_libfabric_abort_if(!lfep->stream &&
                                    lfep->send_offset + len < dgram->length,
                                    "datagram of %u bytes cannot be sent whole "
                                    "(receive capacity %zu)",
                                    dgram->length, cap);

            ctx = evpl_libfabric_ctx_alloc(lf);

            ctx->op   = EVPL_LIBFABRIC_OP_SEND;
            ctx->lfep = lfep;
            ctx->last = (lfep->send_offset + len == dgram->length);

            memset(&msg, 0, sizeof(msg));
            msg.msg_iov   = iov;
            msg.desc      = desc;
            msg.iov_count = niov;
            msg.addr      = dest;
            msg.context   = ctx;

        } else {

            /* connected-datagram send with more iovecs than the provider
             * accepts: the message boundary must hold, so coalesce */
            evpl_libfabric_abort_if(dgram->length > cap,
                                    "datagram of %u bytes cannot be sent whole "
                                    "(receive capacity %zu)",
                                    dgram->length, cap);

            ctx = evpl_libfabric_ctx_alloc(lf);

            ctx->op   = EVPL_LIBFABRIC_OP_SEND;
            ctx->lfep = lfep;
            ctx->last = 1;

            evpl_iovec_alloc_datagram(evpl, &ctx->iovec, dgram->length);

            len = 0;

            for (k = 0; k < dgram->niov; ++k) {
                cur = &bind->iovec_send.iovec[
                    (bind->iovec_send.waist + k) & bind->iovec_send.mask];

                memcpy((char *) ctx->iovec.data + len, cur->data, cur->length);
                len += cur->length;
            }

            iov[0].iov_base = ctx->iovec.data;
            iov[0].iov_len  = len;

            if (dev->mr_local) {
                struct evpl_libfabric_mr *mrset =
                    evpl_memory_framework_private(&ctx->iovec,
                                                  EVPL_FRAMEWORK_LIBFABRIC);
                desc[0] = fi_mr_desc(mrset[dev->index].mr);
            } else {
                desc[0] = NULL;
            }

            niov = 1;

            memset(&msg, 0, sizeof(msg));
            msg.msg_iov   = iov;
            msg.desc      = desc;
            msg.iov_count = 1;
            msg.addr      = dest;
            msg.context   = ctx;
        }

        flags = FI_COMPLETION;

        if (len <= dev->inject_size &&
            (evpl_shared->config->libfabric_inject_max == 0 ||
             len <= evpl_shared->config->libfabric_inject_max)) {
            flags |= FI_INJECT;
        }

        rc = fi_sendmsg(lfep->ep, &msg, flags);

        if (rc == -FI_EAGAIN) {
            if (ctx->iovec.ref) {
                evpl_iovec_release_internal(evpl, &ctx->iovec);
            }
            evpl_libfabric_ctx_free(lf, ctx);
            evpl_defer(evpl, &bind->flush_deferral);
            break;
        }

        evpl_libfabric_abort_if(rc, "fi_sendmsg: %s", fi_strerror(-rc));

        DL_APPEND(lfep->posted_sends, ctx);
        lfep->cur_sends++;

        lfep->send_offset += len;

        if (lfep->send_offset == dgram->length) {

            bind->iovec_send.waist =
                (bind->iovec_send.waist + dgram->niov) &
                bind->iovec_send.mask;

            bind->dgram_send.waist =
                (bind->dgram_send.waist + 1) & bind->dgram_send.mask;

            lfep->send_offset = 0;
        }
    }
} /* evpl_libfabric_flush */

/*
 * Connection management
 */

static struct evpl_libfabric *
evpl_libfabric_thread(struct evpl *evpl)
{
    struct evpl_libfabric *lf;

    lf = evpl_framework_private(evpl, EVPL_FRAMEWORK_LIBFABRIC);

    evpl_libfabric_abort_if(!lf,
                            "no usable libfabric provider is available");

    return lf;
} /* evpl_libfabric_thread */

static void
evpl_libfabric_ep_setup(
    struct evpl              *evpl,
    struct evpl_libfabric    *lf,
    struct evpl_libfabric_ep *lfep,
    struct fi_info           *info,
    int                       devindex)
{
    struct evpl_libfabric_thread_device *tdev;
    struct evpl_libfabric_device        *dev;
    int                                  rc;

    tdev = evpl_libfabric_tdev_open(evpl, lf, devindex);
    dev  = tdev->dev;

    lfep->tdev = tdev;

    rc = fi_endpoint(dev->domain, info, &lfep->ep, lfep);

    evpl_libfabric_abort_if(rc, "fi_endpoint(%s): %s",
                            dev->info->domain_attr->name, fi_strerror(-rc));

    rc = fi_ep_bind(lfep->ep, &tdev->eq->fid, 0);

    evpl_libfabric_abort_if(rc, "fi_ep_bind(eq): %s", fi_strerror(-rc));

    rc = fi_ep_bind(lfep->ep, &tdev->cq->fid,
                    FI_TRANSMIT | FI_RECV | FI_SELECTIVE_COMPLETION);

    evpl_libfabric_abort_if(rc, "fi_ep_bind(cq): %s", fi_strerror(-rc));

    rc = fi_enable(lfep->ep);

    evpl_libfabric_abort_if(rc, "fi_enable: %s", fi_strerror(-rc));

    evpl_libfabric_fill_rq(evpl, lfep);

    evpl_libfabric_ep_added(evpl, lf, tdev);
} /* evpl_libfabric_ep_setup */

static int
evpl_libfabric_listen(
    struct evpl      *evpl,
    struct evpl_bind *bind)
{
    struct evpl_libfabric               *lf   = evpl_libfabric_thread(evpl);
    struct evpl_libfabric_ep            *lfep = evpl_bind_private(bind);
    struct evpl_libfabric_thread_device *tdev;
    struct fi_info                      *hints, *info, *fi;
    char                                 node[INET6_ADDRSTRLEN];
    char                                 service[16];
    int                                  rc, devindex = -1;

    memset(lfep, 0, sizeof(*lfep));

    lfep->lf     = lf;
    lfep->stream = bind->protocol->stream;

    evpl_libfabric_addr_strings(bind->local, node, sizeof(node),
                                service, sizeof(service));

    hints = evpl_libfabric_hints();

    rc = fi_getinfo(EVPL_LIBFABRIC_API_VERSION, node, service, FI_SOURCE,
                    hints, &info);

    fi_freeinfo(hints);

    if (rc) {
        evpl_libfabric_error("fi_getinfo(%s:%s): %s", node, service,
                             fi_strerror(-rc));
        return -1;
    }

    for (fi = info; fi; fi = fi->next) {
        devindex = evpl_libfabric_match_device(lf, fi);

        if (devindex >= 0) {
            break;
        }
    }

    if (devindex < 0 && evpl_libfabric_addr_is_wildcard(bind->local)) {
        /* a wildcard listen is not tied to one interface: the passive
         * endpoint accepts on all of them, and the device that matters is
         * chosen per connection at FI_CONNREQ time from the connection's
         * own fi_info */
        devindex = evpl_libfabric_first_device_of_type(lf, FI_EP_MSG);
        fi       = info;
    }

    if (devindex < 0) {
        evpl_libfabric_error("no configured libfabric device can listen on %s:%s",
                             node, service);
        fi_freeinfo(info);
        return -1;
    }

    lfep->info = fi_dupinfo(fi);

    fi_freeinfo(info);

    tdev = evpl_libfabric_tdev_open(evpl, lf, devindex);

    lfep->tdev = tdev;

    rc = fi_passive_ep(tdev->dev->fabric, lfep->info, &lfep->pep, lfep);

    if (rc) {
        evpl_libfabric_error("fi_passive_ep(%s:%s): %s", node, service,
                             fi_strerror(-rc));
        goto fail;
    }

    rc = fi_pep_bind(lfep->pep, &tdev->eq->fid, 0);

    if (rc) {
        evpl_libfabric_error("fi_pep_bind(eq): %s", fi_strerror(-rc));
        goto fail;
    }

    rc = fi_listen(lfep->pep);

    if (rc) {
        evpl_libfabric_error("fi_listen(%s:%s): %s", node, service,
                             fi_strerror(-rc));
        goto fail;
    }

    evpl_libfabric_ep_added(evpl, lf, tdev);

    return 0;

 fail:
    if (lfep->pep) {
        fi_close(&lfep->pep->fid);
        lfep->pep = NULL;
    }

    fi_freeinfo(lfep->info);
    lfep->info = NULL;

    return -1;
} /* evpl_libfabric_listen */

static void
evpl_libfabric_attach(
    struct evpl      *evpl,
    struct evpl_bind *bind,
    void             *accepted)
{
    struct evpl_libfabric          *lf       = evpl_libfabric_thread(evpl);
    struct evpl_libfabric_ep       *lfep     = evpl_bind_private(bind);
    struct evpl_libfabric_accepted *accepted_info = accepted;
    int                             rc, devindex;

    memset(lfep, 0, sizeof(*lfep));

    lfep->lf     = lf;
    lfep->stream = bind->protocol->stream;
    lfep->info   = accepted_info->info;

    evpl_free(accepted_info);

    devindex = evpl_libfabric_match_device(lf, lfep->info);

    if (devindex < 0) {
        devindex = evpl_libfabric_match_device_by_addr(lf, lfep->info);
    }

    if (devindex < 0) {
        devindex = evpl_libfabric_first_device_of_type(lf, FI_EP_MSG);
    }

    evpl_libfabric_abort_if(devindex < 0,
                            "connection request for unknown device %s",
                            lfep->info->domain_attr->name);

    evpl_libfabric_ep_setup(evpl, lf, lfep, lfep->info, devindex);

    rc = fi_accept(lfep->ep, NULL, 0);

    evpl_libfabric_abort_if(rc, "fi_accept: %s", fi_strerror(-rc));
} /* evpl_libfabric_attach */

static void
evpl_libfabric_connect(
    struct evpl      *evpl,
    struct evpl_bind *bind)
{
    struct evpl_libfabric    *lf   = evpl_libfabric_thread(evpl);
    struct evpl_libfabric_ep *lfep = evpl_bind_private(bind);
    struct fi_info           *hints, *info, *fi;
    char                      node[INET6_ADDRSTRLEN];
    char                      service[16];
    int                       rc, devindex = -1;

    memset(lfep, 0, sizeof(*lfep));

    lfep->lf     = lf;
    lfep->stream = bind->protocol->stream;

    evpl_libfabric_addr_strings(bind->remote, node, sizeof(node),
                                service, sizeof(service));

    hints = evpl_libfabric_hints();

    rc = fi_getinfo(EVPL_LIBFABRIC_API_VERSION, node, service, 0,
                    hints, &info);

    fi_freeinfo(hints);

    evpl_libfabric_abort_if(rc, "fi_getinfo(%s:%s): %s", node, service,
                            fi_strerror(-rc));

    for (fi = info; fi; fi = fi->next) {
        devindex = evpl_libfabric_match_device(lf, fi);

        if (devindex >= 0) {
            break;
        }
    }

    evpl_libfabric_abort_if(devindex < 0,
                            "no configured libfabric device can reach %s:%s",
                            node, service);

    lfep->info = fi_dupinfo(fi);

    fi_freeinfo(info);

    evpl_libfabric_ep_setup(evpl, lf, lfep, lfep->info, devindex);

    rc = fi_connect(lfep->ep, lfep->info->dest_addr, NULL, 0);

    evpl_libfabric_abort_if(rc, "fi_connect: %s", fi_strerror(-rc));
} /* evpl_libfabric_connect */

static void
evpl_libfabric_bind(
    struct evpl      *evpl,
    struct evpl_bind *bind)
{
    struct evpl_libfabric               *lf   = evpl_libfabric_thread(evpl);
    struct evpl_libfabric_ep            *lfep = evpl_bind_private(bind);
    struct evpl_libfabric_thread_device *tdev;
    struct evpl_libfabric_device        *dev;
    struct fi_info                      *hints, *info, *fi;
    char                                 node[INET6_ADDRSTRLEN];
    char                                 service[16];
    int                                  rc, devindex = -1;

    memset(lfep, 0, sizeof(*lfep));

    lfep->lf  = lf;
    lfep->rdm = 1;

    evpl_libfabric_addr_strings(bind->local, node, sizeof(node),
                                service, sizeof(service));

    hints = evpl_libfabric_hints_type(FI_EP_RDM, FI_MSG | FI_SOURCE);

    rc = fi_getinfo(EVPL_LIBFABRIC_API_VERSION, node, service, FI_SOURCE,
                    hints, &info);

    fi_freeinfo(hints);

    evpl_libfabric_abort_if(rc, "fi_getinfo(rdm %s:%s): %s", node, service,
                            fi_strerror(-rc));

    for (fi = info; fi; fi = fi->next) {
        devindex = evpl_libfabric_match_device(lf, fi);

        if (devindex >= 0) {
            break;
        }
    }

    if (devindex < 0 && evpl_libfabric_addr_is_wildcard(bind->local)) {
        devindex = evpl_libfabric_first_device_of_type(lf, FI_EP_RDM);
        fi       = info;
    }

    evpl_libfabric_abort_if(devindex < 0,
                            "no configured libfabric device can bind %s:%s",
                            node, service);

    lfep->info = fi_dupinfo(fi);

    fi_freeinfo(info);

    tdev = evpl_libfabric_tdev_open(evpl, lf, devindex);
    dev  = tdev->dev;

    lfep->tdev = tdev;

    rc = fi_endpoint(dev->domain, lfep->info, &lfep->ep, lfep);

    evpl_libfabric_abort_if(rc, "fi_endpoint(rdm %s): %s",
                            dev->info->domain_attr->name, fi_strerror(-rc));

    rc = fi_ep_bind(lfep->ep,
                    &evpl_libfabric_device_av(lf->shared, dev)->fid, 0);

    evpl_libfabric_abort_if(rc, "fi_ep_bind(av): %s", fi_strerror(-rc));

    rc = fi_ep_bind(lfep->ep, &tdev->cq->fid,
                    FI_TRANSMIT | FI_RECV | FI_SELECTIVE_COMPLETION);

    evpl_libfabric_abort_if(rc, "fi_ep_bind(cq): %s", fi_strerror(-rc));

    rc = fi_enable(lfep->ep);

    evpl_libfabric_abort_if(rc, "fi_enable(rdm): %s", fi_strerror(-rc));

    evpl_libfabric_fill_rq(evpl, lfep);

    /* connectionless: ready to transmit immediately */
    lfep->connected = 1;

    evpl_libfabric_ep_added(evpl, lf, tdev);
} /* evpl_libfabric_bind */

static void
evpl_libfabric_pending_close(
    struct evpl      *evpl,
    struct evpl_bind *bind)
{
    struct evpl_libfabric_ep *lfep = evpl_bind_private(bind);

    /* teardown completes synchronously in close(), so the bind is not
     * parked with EVPL_BIND_CLOSE_DEFERRED; fi_shutdown just informs the
     * peer */
    if (lfep->ep && lfep->connected) {
        fi_shutdown(lfep->ep, 0);
    }
} /* evpl_libfabric_pending_close */

static void
evpl_libfabric_close(
    struct evpl      *evpl,
    struct evpl_bind *bind)
{
    struct evpl_libfabric_ep            *lfep = evpl_bind_private(bind);
    struct evpl_libfabric               *lf   = lfep->lf;
    struct evpl_libfabric_thread_device *tdev = lfep->tdev;
    struct evpl_libfabric_ctx           *ctx;
    struct fid                          *closed_fid = NULL;

    lfep->closed    = 1;
    lfep->connected = 0;

    if (lfep->pep) {
        closed_fid = &lfep->pep->fid;
        fi_close(&lfep->pep->fid);
        lfep->pep = NULL;
    }

    if (lfep->ep) {
        closed_fid = &lfep->ep->fid;
        fi_close(&lfep->ep->fid);
        lfep->ep = NULL;
    }

    if (tdev && closed_fid) {

        /* completions already queued for this endpoint (including the
         * FI_ECANCELED entries for its posted receives) must be consumed
         * before the bind memory is recycled */
        evpl_libfabric_poll_cq(evpl, tdev, 1);
        evpl_libfabric_drain_eq(evpl, tdev, closed_fid);

        /* anything the provider dropped without a completion */
        while (lfep->posted_recvs) {
            ctx = lfep->posted_recvs;
            DL_DELETE(lfep->posted_recvs, ctx);
            lfep->rq_posted--;
            evpl_iovec_release_internal(evpl, &ctx->iovec);
            evpl_libfabric_ctx_free(lf, ctx);
        }

        while (lfep->posted_sends) {
            ctx = lfep->posted_sends;
            DL_DELETE(lfep->posted_sends, ctx);
            lfep->cur_sends--;
            if (ctx->iovec.ref) {
                evpl_iovec_release_internal(evpl, &ctx->iovec);
            }
            evpl_libfabric_ctx_free(lf, ctx);
        }

        if (lfep->rdm) {
            /* unretired datagrams still hold their endpoint-resolution
             * address references (dropped at retire on the normal path) */
            struct evpl_bind       *bind = evpl_private2bind(lfep);
            struct evpl_dgram_ring *ring = &bind->dgram_send;
            int                     idx;

            for (idx = ring->tail; idx != ring->head;
                 idx = (idx + 1) & ring->mask) {
                if (ring->dgram[idx].addr) {
                    evpl_address_release(ring->dgram[idx].addr);
                }
            }
        }

        evpl_libfabric_ep_removed(evpl, lf, tdev);
    }

    if (lfep->info) {
        fi_freeinfo(lfep->info);
        lfep->info = NULL;
    }
} /* evpl_libfabric_close */

struct evpl_framework evpl_framework_libfabric = {
    .id                = EVPL_FRAMEWORK_LIBFABRIC,
    .name              = "LIBFABRIC",
    .init              = evpl_libfabric_init,
    .cleanup           = evpl_libfabric_cleanup,
    .create            = evpl_libfabric_create,
    .destroy           = evpl_libfabric_destroy,
    .register_memory   = evpl_libfabric_register,
    .unregister_memory = evpl_libfabric_unregister,
    .get_rdma_address  = evpl_libfabric_get_rdma_address,
    .release_address   = evpl_libfabric_release_address,
};

struct evpl_protocol  evpl_libfabric_msg_stream = {
    .id            = EVPL_STREAM_LIBFABRIC_MSG,
    .connected     = 1,
    .stream        = 1,
    .rdma          = 1,
    .name          = "STREAM_LIBFABRIC_MSG",
    .framework     = &evpl_framework_libfabric,
    .listen        = evpl_libfabric_listen,
    .attach        = evpl_libfabric_attach,
    .connect       = evpl_libfabric_connect,
    .pending_close = evpl_libfabric_pending_close,
    .close         = evpl_libfabric_close,
    .flush         = evpl_libfabric_flush,
};

struct evpl_protocol  evpl_libfabric_msg_datagram = {
    .id            = EVPL_DATAGRAM_LIBFABRIC_MSG,
    .connected     = 1,
    .stream        = 0,
    .rdma          = 1,
    .name          = "DATAGRAM_LIBFABRIC_MSG",
    .framework     = &evpl_framework_libfabric,
    .listen        = evpl_libfabric_listen,
    .attach        = evpl_libfabric_attach,
    .connect       = evpl_libfabric_connect,
    .pending_close = evpl_libfabric_pending_close,
    .close         = evpl_libfabric_close,
    .flush         = evpl_libfabric_flush,
};

struct evpl_protocol  evpl_libfabric_rdm_datagram = {
    .id            = EVPL_DATAGRAM_LIBFABRIC_RDM,
    .connected     = 0,
    .stream        = 0,
    .name          = "DATAGRAM_LIBFABRIC_RDM",
    .framework     = &evpl_framework_libfabric,
    .bind          = evpl_libfabric_bind,
    .pending_close = evpl_libfabric_pending_close,
    .close         = evpl_libfabric_close,
    .flush         = evpl_libfabric_flush,
};
