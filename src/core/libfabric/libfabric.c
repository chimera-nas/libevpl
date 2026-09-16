// SPDX-FileCopyrightText: 2026 Ben Jarvis
//
// SPDX-License-Identifier: LGPL-2.1-only

#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <pthread.h>
#include <sys/socket.h>
#include <poll.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <utlist.h>
#include <uthash.h>

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

/* The API surface this backend is written against.  fi_getinfo() refuses a
 * requested version newer than the installed library, so this doubles as the
 * minimum libfabric this backend runs on -- keep it at the oldest release
 * carrying everything used here (fi_context2, FI_WAIT_POLLFD/FI_GETWAIT, and
 * the FI_MR_* bitmask form of mr_mode, which needs only 1.5).  1.17 is what
 * Ubuntu 24.04 ships, and raising this past a distro's package silently
 * disables the backend there rather than failing the build. */
#define EVPL_LIBFABRIC_API_VERSION FI_VERSION(1, 17)

/* Requested-key allocation starts high to stay clear of keys an
 * application may have chosen on an externally provided domain */
#define EVPL_LIBFABRIC_MR_KEY_BASE 0x80000000u

/* Max iovec elements gathered into one provider op (stack arrays);
 * the effective limit is min of this and the provider's iov_limit */
#define EVPL_LIBFABRIC_MAX_IOV     16

/* Bound retries while obtaining a changing provider descriptor snapshot. */
#define EVPL_LIBFABRIC_TRYWAIT_MAX 8

/* Manual-progress backstop for active queues without native wait objects. */
#define EVPL_LIBFABRIC_TICK_US     1000

#define EVPL_LIBFABRIC_OP_RECV     0
#define EVPL_LIBFABRIC_OP_SEND     1
#define EVPL_LIBFABRIC_OP_READ     2
#define EVPL_LIBFABRIC_OP_WRITE    3

/* RDM has no portable way to recover an unknown sender on providers without
 * FI_SOURCE_ERR (including tcp and rxm).  Carry the listening address in a
 * versioned, OS-independent envelope.  All fields are in network byte order;
 * the current backend negotiates FI_SOCKADDR_IN only. */
#define EVPL_LIBFABRIC_RDM_MAGIC   0x45565001u
struct evpl_libfabric_rdm_header {
    uint32_t magic;
    uint32_t address;
    uint16_t port;
    uint16_t reserved;
};
_Static_assert(sizeof(struct evpl_libfabric_rdm_header) == 12, "RDM wire header size");

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
    enum fi_ep_type ep_type;
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

struct evpl_libfabric_wait {
    struct evpl_libfabric               *lf;
    struct evpl_libfabric_thread_device *tdev;
    struct evpl_libfabric_cq            *cq;
    struct fid                          *fid;
    int                                  mode;
    int                                  valid;
    uint64_t                             change_index;
    size_t                               capacity;
    struct pollfd                       *fds;
    struct evpl_libfabric_wait_member   *members;
    struct evpl_libfabric_wait          *prev;
    struct evpl_libfabric_wait          *next;
};

struct evpl_libfabric_fd {
    struct evpl_libfabric             *lf;
    struct evpl_event                  event;
    int                                fd;
    int                                registered;
    int                                dirty;
    struct evpl_libfabric_wait_member *members;
    UT_hash_handle                     hh;
};

struct evpl_libfabric_wait_member {
    struct evpl_libfabric_wait        *wait;
    struct evpl_libfabric_fd          *watch;
    short                              events;
    struct evpl_libfabric_wait_member *prev, *next;
    struct evpl_libfabric_wait_member *fd_prev, *fd_next;
};

/* Shared MSG receives have no endpoint in their operation context.  A
 * separate receive CQ identifies the connection without adding wire headers
 * or relying on FI_SOURCE (which verbs MSG does not implement). */
struct evpl_libfabric_cq {
    struct evpl_libfabric_thread_device *tdev;
    struct evpl_libfabric_ep            *recv_ep;
    struct fid_cq                       *cq;
    struct evpl_libfabric_wait           wait;
    struct evpl_libfabric_cq            *prev;
    struct evpl_libfabric_cq            *next;
};

struct evpl_libfabric_recvq {
    struct evpl_libfabric_thread_device *tdev;
    struct fid_ep                       *ep;
    struct evpl_libfabric_ep            *owner; /* NULL for shared receives */
    struct evpl_libfabric_ctx           *posted_recvs;
    unsigned int                         posted;
};

/* Per-thread per-device state (CQ/EQ opened lazily on first use) */
struct evpl_libfabric_thread_device {
    struct evpl_libfabric        *lf;
    struct evpl_libfabric_device *dev;
    struct evpl_libfabric_cq      cq;
    struct evpl_libfabric_cq     *recv_cqs;
    struct evpl_libfabric_recvq   srq;
    int                           srq_unavailable;
    unsigned int                  srq_users;
    struct fid_eq                *eq;
    struct evpl_libfabric_wait    eq_wait;
    int                           num_ep;
};

/* Logical transfers remain stable when the application grows either ring.
 * Lists follow submission order, so completed successors retain their buffers
 * until the prefix can retire.  A transfer is complete only after all chunks
 * have been submitted and every submitted chunk has returned. */
struct evpl_libfabric_transfer {
    unsigned int                    pending;
    int                             submitted;
    int                             status;
    struct evpl_libfabric_transfer *prev;
    struct evpl_libfabric_transfer *next;
};

/* Per-op context, pooled per thread.  The provider scratch area
 * (fi_context2) MUST be the first member: FI_CONTEXT/FI_CONTEXT2 mode
 * providers treat the op context pointer as their own storage. */
struct evpl_libfabric_ctx {
    struct fi_context2              fi_ctx;
    uint8_t                         op;
    struct evpl_libfabric_transfer *transfer;
    struct evpl_libfabric_ep       *lfep;
    struct evpl_libfabric_recvq    *rq;
    struct evpl_iovec               iovec; /* RECV buffer / coalesced TX staging */
    struct evpl_libfabric_ctx      *prev;
    struct evpl_libfabric_ctx      *next;
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
    struct evpl_libfabric_ep             *retry_eps;
    struct evpl_poll                     *poll;
    struct evpl_timer                     tick;
    int                                   tick_armed;
    int                                   polling;
    struct evpl_libfabric_wait           *waits;
    struct evpl_libfabric_fd             *wait_fds;
    struct evpl_libfabric_ctx            *free_ctx;
    struct evpl_libfabric_transfer       *free_transfer;
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
    struct evpl_libfabric_cq             recv_cq;
    struct evpl_libfabric_recvq          private_rq;
    struct evpl_libfabric_recvq         *rq;
    struct evpl_iovec                    rdm_header;
    int                                  retry_pending;
    struct evpl_libfabric_ep            *retry_prev, *retry_next;
    uint64_t                             send_offset; /* bytes of the waist
                                                       * dgram already posted */
    uint64_t                             read_offset; /* likewise, dgram_read */
    struct evpl_libfabric_ctx           *posted_sends;
    struct evpl_libfabric_transfer      *send_transfers;
    struct evpl_libfabric_transfer      *read_transfers;
    struct evpl_libfabric_transfer      *send_transfer;
    struct evpl_libfabric_transfer      *read_transfer;
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

    hints->ep_attr->type        = ep_type;
    hints->caps                 = caps;
    hints->addr_format          = FI_SOCKADDR_IN;
    hints->mode                 = FI_CONTEXT | FI_CONTEXT2;
    hints->domain_attr->mr_mode = FI_MR_LOCAL | FI_MR_VIRT_ADDR |
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
    struct fi_info                *hints, *msg_info = NULL, *rdm_info = NULL, *fi;
    int                            rc, n;

    if (evpl_shared->config->libfabric_external_domain) {
        return evpl_libfabric_init_external();
    }

    hints = evpl_libfabric_hints();

    rc = fi_getinfo(EVPL_LIBFABRIC_API_VERSION, NULL, NULL, 0, hints,
                    &msg_info);

    fi_freeinfo(hints);

    if (rc) {
        evpl_libfabric_info("no MSG provider: %s; trying RDM independently",
                            fi_strerror(-rc));
        msg_info = NULL;
    }

    hints = evpl_libfabric_hints_type(FI_EP_RDM, FI_MSG);

    rc = fi_getinfo(EVPL_LIBFABRIC_API_VERSION, NULL, NULL, 0, hints,
                    &rdm_info);

    fi_freeinfo(hints);

    if (rc) {
        rdm_info = NULL;
    }

    if (!msg_info && !rdm_info) {
        evpl_libfabric_info("no usable MSG or RDM provider; libfabric protocols unavailable");
        return NULL;
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
    struct evpl_libfabric_mr      *mrset = buffer_private;
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
    struct evpl_libfabric_ep     *lfep = evpl_bind_private(bind);
    struct evpl_libfabric_device *dev;
    struct evpl_libfabric_mr     *mrset;

    /* Keys are domain-specific.  An accept callback runs before attach,
     * and even an attached endpoint must not advertise keys before the
     * connection is established. */
    evpl_libfabric_abort_if(!lfep->tdev || !lfep->connected,
                            "evpl_rdma_get_address requires EVPL_NOTIFY_CONNECTED "
                            "before advertising a libfabric rkey");
    dev = lfep->tdev->dev;

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

    ctx->transfer   = NULL;
    ctx->iovec.data = NULL;
    ctx->iovec.ref  = NULL;

    return ctx;
} /* evpl_libfabric_ctx_alloc */

static void
evpl_libfabric_ctx_free(
    struct evpl_libfabric     *lf,
    struct evpl_libfabric_ctx *ctx)
{
    DL_PREPEND(lf->free_ctx, ctx);
} /* evpl_libfabric_ctx_free */

static struct evpl_libfabric_transfer *
evpl_libfabric_transfer_alloc(struct evpl_libfabric *lf)
{
    struct evpl_libfabric_transfer *transfer = lf->free_transfer;

    if (transfer) {
        DL_DELETE(lf->free_transfer, transfer);
    } else {
        transfer = evpl_zalloc(sizeof(*transfer));
    }
    transfer->pending   = 0;
    transfer->submitted = 0;
    transfer->status    = 0;
    return transfer;
} /* evpl_libfabric_transfer_alloc */

static void
evpl_libfabric_transfer_free(
    struct evpl_libfabric          *lf,
    struct evpl_libfabric_transfer *transfer)
{
    DL_PREPEND(lf->free_transfer, transfer);
} /* evpl_libfabric_transfer_free */

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

static int evpl_libfabric_poll_cq(
    struct evpl              *evpl,
    struct evpl_libfabric_cq *cq,
    int                       drain);

static int evpl_libfabric_drain_eq(
    struct evpl                         *evpl,
    struct evpl_libfabric_thread_device *tdev,
    struct fid                          *closed_fid);

static void evpl_libfabric_fill_rq(
    struct evpl                 *evpl,
    struct evpl_libfabric_recvq *rq);

static void
evpl_libfabric_handle_recv(
    struct evpl               *evpl,
    struct evpl_libfabric_ctx *ctx,
    struct evpl_libfabric_ep  *lfep,
    size_t                     len)
{
    struct evpl_libfabric_recvq     *rq = ctx->rq;
    struct evpl_libfabric           *lf = rq->tdev->lf;
    struct evpl_bind                *bind;
    struct evpl_address             *addr;
    struct evpl_notify               notify;
    struct evpl_libfabric_rdm_header header;
    struct sockaddr_in               source;

    DL_DELETE(rq->posted_recvs, ctx);
    rq->posted--;

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

        if (lfep->rdm) {
            if (len < sizeof(header)) {
                goto malformed;
            }
            memcpy(&header, ctx->iovec.data, sizeof(header));
            if (ntohl(header.magic) != EVPL_LIBFABRIC_RDM_MAGIC ||
                header.reserved || !header.port || !header.address) {
                goto malformed;
            }
            memset(&source, 0, sizeof(source));
#ifdef __APPLE__
            source.sin_len = sizeof(source);
#endif /* ifdef __APPLE__ */
            source.sin_family      = AF_INET;
            source.sin_addr.s_addr = header.address;
            source.sin_port        = header.port;
            addr                   = evpl_address_init((struct sockaddr *) &source, sizeof(source));
            len                   -= sizeof(header);
            ctx->iovec.data        = (char *) ctx->iovec.data + sizeof(header);
            ctx->iovec.length      = len;
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
    return;

 malformed:
    /* A malformed or older unframed datagram is not an application message. */
    evpl_iovec_release_internal(evpl, &ctx->iovec);
    evpl_libfabric_ctx_free(lf, ctx);
} /* evpl_libfabric_handle_recv */

static void
evpl_libfabric_retire_send(
    struct evpl              *evpl,
    struct evpl_libfabric_ep *lfep,
    int                       status)
{
    struct evpl_bind  *bind;
    struct evpl_dgram *dgram;
    struct evpl_iovec *iovec;
    struct evpl_notify notify;
    uint64_t           length;
    uint8_t            dgram_type;

    void               (*callback)(
        int   cb_status,
        void *cb_private_data);
    void              *private_data;
    int                i, niov;

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

} /* evpl_libfabric_retire_send */

static void
evpl_libfabric_retire_read(
    struct evpl              *evpl,
    struct evpl_libfabric_ep *lfep,
    int                       status)
{
    struct evpl_bind  *bind;
    struct evpl_dgram *dgram;
    struct evpl_iovec *iovec;

    void               (*callback)(
        int   cb_status,
        void *cb_private_data);
    void              *private_data;
    int                i, niov;

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

} /* evpl_libfabric_retire_read */

/* Every completion returns capacity, even when the transfer still has
 * unposted chunks.  Retirement is independent of completion order. */
static void
evpl_libfabric_complete(
    struct evpl               *evpl,
    struct evpl_libfabric_ctx *ctx,
    int                        status)
{
    struct evpl_libfabric_ep        *lfep     = ctx->lfep;
    struct evpl_libfabric           *lf       = lfep->lf;
    struct evpl_bind                *bind     = evpl_private2bind(lfep);
    struct evpl_libfabric_transfer  *transfer = ctx->transfer;
    struct evpl_libfabric_transfer **transfers;
    int                              read = ctx->op == EVPL_LIBFABRIC_OP_READ;

    DL_DELETE(lfep->posted_sends, ctx);
    if (read) {
        lfep->cur_rdma_reads--;
        transfers = &lfep->read_transfers;
    } else {
        lfep->cur_sends--;
        transfers = &lfep->send_transfers;
    }
    if (ctx->iovec.ref) {
        evpl_iovec_release_internal(evpl, &ctx->iovec);
    }
    evpl_libfabric_abort_if(!transfer || !transfer->pending,
                            "completion without an outstanding transfer");
    transfer->pending--;
    if (status && !transfer->status) {
        transfer->status = status;
    }
    evpl_libfabric_ctx_free(lf, ctx);

    if (unlikely(lfep->closed)) {
        return;
    }

    while ((transfer = *transfers) && transfer->submitted && !transfer->pending) {
        status = transfer->status;
        DL_DELETE(*transfers, transfer);
        evpl_libfabric_transfer_free(lf, transfer);
        if (read) {
            evpl_libfabric_retire_read(evpl, lfep, status);
        } else {
            evpl_libfabric_retire_send(evpl, lfep, status);
        }
    }

    if (bind->flags & EVPL_BIND_PENDING_CLOSED) {
        return;
    }
    if (!read && !lfep->cur_sends &&
        evpl_iovec_ring_is_empty(&bind->iovec_send) &&
        (bind->flags & EVPL_BIND_FINISH)) {
        evpl_close(evpl, bind);
        return;
    }
    if (bind->dgram_send.waist != bind->dgram_send.head ||
        bind->dgram_read.waist != bind->dgram_read.head) {
        evpl_defer(evpl, &bind->flush_deferral);
    }
} /* evpl_libfabric_complete */

static void
evpl_libfabric_handle_cq_error(
    struct evpl              *evpl,
    struct evpl_libfabric_cq *cq)
{
    struct evpl_libfabric_ctx *ctx;
    struct evpl_libfabric_ep  *lfep;
    struct fi_cq_err_entry     err;
    ssize_t                    rc;

    memset(&err, 0, sizeof(err));

    rc = fi_cq_readerr(cq->cq, &err, 0);

    if (rc < 0) {
        return;
    }

    ctx  = err.op_context;
    lfep = cq->recv_ep ? cq->recv_ep : ctx->lfep;

    if (err.err != FI_ECANCELED && !lfep->closed) {
        evpl_libfabric_error("completion error op %u err %d (%s) prov_errno %d",
                             ctx->op, err.err, fi_strerror(err.err),
                             err.prov_errno);
    }

    switch (ctx->op) {
        case EVPL_LIBFABRIC_OP_RECV:
            DL_DELETE(ctx->rq->posted_recvs, ctx);
            ctx->rq->posted--;
            evpl_iovec_release_internal(evpl, &ctx->iovec);
            evpl_libfabric_ctx_free(lfep->lf, ctx);
            break;
        case EVPL_LIBFABRIC_OP_SEND:
            evpl_libfabric_complete(evpl, ctx, EIO);
            break;
        case EVPL_LIBFABRIC_OP_READ:
            evpl_libfabric_complete(evpl, ctx, EIO);
            break;
        default:
            evpl_libfabric_abort("cq error for unknown op %u", ctx->op);
    } /* switch */
} /* evpl_libfabric_handle_cq_error */

static int
evpl_libfabric_poll_cq(
    struct evpl              *evpl,
    struct evpl_libfabric_cq *cq,
    int                       drain)
{
    struct fi_cq_msg_entry     comps[64];
    struct evpl_libfabric_ctx *ctx;
    ssize_t                    n;
    int                        i, total = 0;

    if (!cq->cq) {
        return 0;
    }

 again:

    /* RDM carries a portable source address in its wire envelope. */
    n = fi_cq_read(cq->cq, comps, 64);

    if (n == -FI_EAGAIN) {
        if (cq->recv_ep && !cq->recv_ep->closed) {
            evpl_libfabric_fill_rq(evpl, cq->recv_ep->rq);
        }
        return total;
    }

    if (n == -FI_EAVAIL) {
        evpl_libfabric_handle_cq_error(evpl, cq);
        total++;
        goto again;
    }

    evpl_libfabric_abort_if(n < 0, "CQ read: %s", fi_strerror(-n));

    evpl_activity(evpl);

    for (i = 0; i < n; ++i) {

        ctx = comps[i].op_context;

        switch (ctx->op) {
            case EVPL_LIBFABRIC_OP_RECV:
                evpl_libfabric_handle_recv(evpl, ctx,
                                           cq->recv_ep ? cq->recv_ep : ctx->lfep, comps[i].len);
                break;
            case EVPL_LIBFABRIC_OP_SEND:
                evpl_libfabric_complete(evpl, ctx, 0);
                break;
            case EVPL_LIBFABRIC_OP_READ:
                evpl_libfabric_complete(evpl, ctx, 0);
                break;
            default:
                evpl_libfabric_abort("unknown completion op %u", ctx->op);
        } /* switch */
    }

    if (cq->recv_ep && !cq->recv_ep->closed) {
        evpl_libfabric_fill_rq(evpl, cq->recv_ep->rq);
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

    union {
        struct fi_eq_cm_entry entry;
        uint8_t               data[sizeof(struct fi_eq_cm_entry) + 256];
    } buf;

    if (!tdev->eq) {
        return 0;
    }

    for (;;) {

        /* Normal progress yields after a batch.  Teardown must consume all
         * events referencing the closed fid before its context is recycled. */
        if (!closed_fid && total >= 64) {
            return total;
        }

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

/* Descriptors are borrowed from the provider and can be shared by multiple
 * CQs/EQs.  One event per fd combines all subscriber interests. */
static void
evpl_libfabric_wait_progress(struct evpl_libfabric_wait *wait)
{
    if (wait->cq) {
        evpl_libfabric_poll_cq(wait->lf->evpl, wait->cq, 0);
    } else {
        evpl_libfabric_drain_eq(wait->lf->evpl, wait->tdev, NULL);
    }
} /* evpl_libfabric_wait_progress */

static void
evpl_libfabric_wait_event(
    struct evpl       *evpl,
    struct evpl_event *event)
{
    struct evpl_libfabric_fd          *watch = container_of(event, struct evpl_libfabric_fd, event);
    struct evpl_libfabric_wait_member *member;

    evpl_event_mark_unreadable(evpl, event);
    evpl_event_mark_unwritable(evpl, event);
    event->flags &= ~EVPL_ERROR;
    DL_FOREACH2(watch->members, member, fd_next)
    {
        evpl_libfabric_wait_progress(member->wait);
    }
    /* fi_trywait and descriptor resynchronization happen before the next
     * sleep, after callbacks and deferred endpoint closes have run. */
} /* evpl_libfabric_wait_event */

static void
evpl_libfabric_fd_interest(struct evpl_libfabric_fd *watch)
{
    struct evpl                       *evpl = watch->lf->evpl;
    struct evpl_libfabric_wait_member *member;
    short                              events = 0;

    if (!watch->registered) {
        return;
    }

    if (!watch->lf->polling) {
        DL_FOREACH2(watch->members, member, fd_next)
        {
            events |= member->events;
        }
    }
    if (events & POLLIN) {
        evpl_event_read_interest(evpl, &watch->event);
    } else {
        evpl_event_read_disinterest(evpl, &watch->event);
    }
    if (events & POLLOUT) {
        evpl_event_write_interest(evpl, &watch->event);
    } else {
        evpl_event_write_disinterest(evpl, &watch->event);
    }
} /* evpl_libfabric_fd_interest */

static void
evpl_libfabric_fds_commit(struct evpl_libfabric *lf)
{
    struct evpl_libfabric_fd          *watch, *tmp;
    struct evpl                       *evpl = lf->evpl;
    struct evpl_libfabric_wait_member *member;
    short                              events;

    HASH_ITER(hh, lf->wait_fds, watch, tmp)
    {
        if (!watch->dirty) {
            continue;
        }
        /* Refresh affected registrations even if the numeric fd persists:
         * a provider may close a socket and reuse its number between polls. */
        if (watch->registered) {
            evpl_event_read_disinterest(evpl, &watch->event);
            evpl_event_write_disinterest(evpl, &watch->event);
            evpl_remove_event(evpl, &watch->event);
        }
        if (!watch->members) {
            HASH_DEL(lf->wait_fds, watch);
            evpl_free(watch);
            continue;
        }
        events = 0;
        DL_FOREACH2(watch->members, member, fd_next)
        {
            events |= member->events;
        }
        evpl_add_event_flags(evpl, &watch->event, watch->fd, EVPL_LEVEL_TRIGGERED,
                             events & POLLIN ? evpl_libfabric_wait_event : NULL,
                             events & POLLOUT ? evpl_libfabric_wait_event : NULL,
                             evpl_libfabric_wait_event);
        watch->registered = 1;
        watch->dirty      = 0;
        evpl_libfabric_fd_interest(watch);
    }
} /* evpl_libfabric_fds_commit */

static void
evpl_libfabric_wait_detach(struct evpl_libfabric_wait *wait)
{
    struct evpl_libfabric_wait_member *member;

    while (wait->members) {
        member = wait->members;
        DL_DELETE(wait->members, member);
        DL_DELETE2(member->watch->members, member, fd_prev, fd_next);
        member->watch->dirty = 1;
        evpl_free(member);
    }
} /* evpl_libfabric_wait_detach */

static void
evpl_libfabric_wait_attach(
    struct evpl_libfabric_wait *wait,
    int                         fd,
    short                       events)
{
    struct evpl_libfabric_fd          *watch;
    struct evpl_libfabric_wait_member *member;

    if (fd < 0) {
        return;
    }
    evpl_libfabric_abort_if(events & ~(POLLIN | POLLOUT),
                            "unsupported provider poll events 0x%x", events);
    HASH_FIND_INT(wait->lf->wait_fds, &fd, watch);
    if (!watch) {
        watch     = evpl_zalloc(sizeof(*watch));
        watch->lf = wait->lf;
        watch->fd = fd;
        HASH_ADD_INT(wait->lf->wait_fds, fd, watch);
    }
    member         = evpl_zalloc(sizeof(*member));
    member->wait   = wait;
    member->watch  = watch;
    member->events = events;
    DL_APPEND(wait->members, member);
    DL_APPEND2(watch->members, member, fd_prev, fd_next);
    watch->dirty = 1;
} /* evpl_libfabric_wait_attach */

/* FI_GETWAIT can grow its descriptor array while fi_trywait advances
 * connection state.  Retry a bounded number of times; never sleep using an
 * incomplete snapshot.  Unchanged lists require only the size/index query. */
static int
evpl_libfabric_wait_sync(struct evpl_libfabric_wait *wait)
{
    struct fi_wait_pollfd wp;
    unsigned int          i;
    int                   rc, attempt;

    if (wait->mode != FI_WAIT_POLLFD) {
        return 0;
    }
    memset(&wp, 0, sizeof(wp));
    rc = fi_control(wait->fid, FI_GETWAIT, &wp);
    evpl_libfabric_abort_if(rc && rc != -FI_ETOOSMALL,
                            "fi_control(FI_GETWAIT): %s", fi_strerror(-rc));
    if (wait->valid && wp.change_index == wait->change_index) {
        return 0;
    }
    for (attempt = 0; attempt < EVPL_LIBFABRIC_TRYWAIT_MAX; attempt++) {
        if (wp.nfds > wait->capacity) {
            wait->capacity = wp.nfds;
            wait->fds      = evpl_realloc(wait->fds, wait->capacity * sizeof(*wait->fds));
        }
        wp.nfds = wait->capacity;
        wp.fd   = wait->fds;
        rc      = fi_control(wait->fid, FI_GETWAIT, &wp);
        if (rc == -FI_ETOOSMALL) {
            continue;
        }
        evpl_libfabric_abort_if(rc, "fi_control(FI_GETWAIT): %s", fi_strerror(-rc));
        evpl_libfabric_wait_detach(wait);
        for (i = 0; i < wp.nfds; i++) {
            evpl_libfabric_wait_attach(wait, wp.fd[i].fd, wp.fd[i].events);
        }
        wait->change_index = wp.change_index;
        wait->valid        = 1;
        return 0;
    }
    return 1;
} /* evpl_libfabric_wait_sync */

static void evpl_libfabric_update_tick(
    struct evpl_libfabric *lf);

static void
evpl_libfabric_wire_wait(
    struct evpl_libfabric_thread_device *tdev,
    struct evpl_libfabric_wait          *wait,
    struct fid                          *fid,
    int                                  mode,
    struct evpl_libfabric_cq            *cq)
{
    int fd, rc;

    wait->lf   = tdev->lf;
    wait->tdev = tdev;
    wait->fid  = fid;
    wait->mode = mode;
    wait->cq   = cq;
    DL_APPEND(wait->lf->waits, wait);
    if (mode == FI_WAIT_FD) {
        rc = fi_control(fid, FI_GETWAIT, &fd);
        evpl_libfabric_abort_if(rc, "fi_control(FI_GETWAIT): %s", fi_strerror(-rc));
        evpl_libfabric_wait_attach(wait, fd, POLLIN);
    } else {
        evpl_libfabric_wait_sync(wait);
    }
    evpl_libfabric_update_tick(wait->lf);
} /* evpl_libfabric_wire_wait */

static void
evpl_libfabric_unwire_wait(struct evpl_libfabric_wait *wait)
{
    if (!wait->fid) {
        return;
    }
    evpl_libfabric_wait_detach(wait);
    DL_DELETE(wait->lf->waits, wait);
    /* Other queues may still list a descriptor that endpoint close just
     * retired.  Commit only after prepare_wait has refreshed every snapshot,
     * rather than re-registering a stale shared descriptor here. */
    evpl_free(wait->fds);
    wait->fds = NULL;
    wait->fid = NULL;
    evpl_libfabric_update_tick(wait->lf);
} /* evpl_libfabric_unwire_wait */

static void
evpl_libfabric_cq_open(
    struct evpl                         *evpl,
    struct evpl_libfabric_thread_device *tdev,
    struct evpl_libfabric_cq            *cq,
    struct evpl_libfabric_ep            *recv_ep)
{
    struct evpl_libfabric_device *dev = tdev->dev;
    struct fi_cq_attr             cq_attr;
    int                           rc;

    cq->tdev    = tdev;
    cq->recv_ep = recv_ep;
    memset(&cq_attr, 0, sizeof(cq_attr));
    cq_attr.size = recv_ep ? evpl_shared->config->libfabric_rq_size :
        evpl_shared->config->libfabric_cq_size;
    cq_attr.format = FI_CQ_FORMAT_MSG;

    cq_attr.wait_obj = FI_WAIT_POLLFD;
    rc               = fi_cq_open(dev->domain, &cq_attr, &cq->cq, tdev);

    if (rc == 0) {
        cq->wait.mode = FI_WAIT_POLLFD;
    } else {
        cq_attr.wait_obj = FI_WAIT_FD;
        rc               = fi_cq_open(dev->domain, &cq_attr, &cq->cq, tdev);

        if (rc == 0) {
            cq->wait.mode = FI_WAIT_FD;
        } else {
            cq_attr.wait_obj = FI_WAIT_NONE;
            rc               = fi_cq_open(dev->domain, &cq_attr, &cq->cq,
                                          tdev);

            evpl_libfabric_abort_if(rc, "fi_cq_open(%s): %s",
                                    dev->info->domain_attr->name,
                                    fi_strerror(-rc));

            cq->wait.mode = FI_WAIT_NONE;
        }
    }

    evpl_libfabric_wire_wait(tdev, &cq->wait, &cq->cq->fid, cq->wait.mode, cq);

    if (recv_ep) {
        DL_APPEND(tdev->recv_cqs, cq);
    }
} /* evpl_libfabric_cq_open */

static void
evpl_libfabric_cq_close(
    struct evpl              *evpl,
    struct evpl_libfabric_cq *cq)
{
    int rc;

    if (!cq->cq) {
        return;
    }
    evpl_libfabric_unwire_wait(&cq->wait);
    rc = fi_close(&cq->cq->fid);
    evpl_libfabric_abort_if(rc, "fi_close(cq): %s", fi_strerror(-rc));
    cq->cq = NULL;
    if (cq->recv_ep) {
        DL_DELETE(cq->tdev->recv_cqs, cq);
    }
} /* evpl_libfabric_cq_close */

static struct evpl_libfabric_thread_device *
evpl_libfabric_tdev_open(
    struct evpl           *evpl,
    struct evpl_libfabric *lf,
    int                    devindex)
{
    struct evpl_libfabric_thread_device *tdev = &lf->devices[devindex];
    struct evpl_libfabric_device        *dev  = tdev->dev;
    struct fi_eq_attr                    eq_attr;
    int                                  rc;

    if (tdev->cq.cq) {
        return tdev;
    }

    evpl_libfabric_cq_open(evpl, tdev, &tdev->cq, NULL);

    memset(&eq_attr, 0, sizeof(eq_attr));

    eq_attr.wait_obj = FI_WAIT_POLLFD;
    rc               = fi_eq_open(dev->fabric, &eq_attr, &tdev->eq, tdev);

    if (rc == 0) {
        tdev->eq_wait.mode = FI_WAIT_POLLFD;
    } else {
        eq_attr.wait_obj = FI_WAIT_FD;
        rc               = fi_eq_open(dev->fabric, &eq_attr, &tdev->eq, tdev);

        if (rc == 0) {
            tdev->eq_wait.mode = FI_WAIT_FD;
        } else {
            eq_attr.wait_obj = FI_WAIT_UNSPEC;
            rc               = fi_eq_open(dev->fabric, &eq_attr, &tdev->eq,
                                          tdev);

            evpl_libfabric_abort_if(rc, "fi_eq_open(%s): %s",
                                    dev->info->fabric_attr->name,
                                    fi_strerror(-rc));

            tdev->eq_wait.mode = FI_WAIT_NONE;
        }
    }

    evpl_libfabric_wire_wait(tdev, &tdev->eq_wait, &tdev->eq->fid,
                             tdev->eq_wait.mode, NULL);

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
    struct evpl_libfabric    *lf = arg;
    struct evpl_libfabric_fd *watch, *tmp;

    lf->polling = 1;
    HASH_ITER(hh, lf->wait_fds, watch, tmp)
    {
        evpl_libfabric_fd_interest(watch);
    }
} /* evpl_libfabric_poll_enter */

static void
evpl_libfabric_poll_exit(
    struct evpl *evpl,
    void        *arg)
{
    struct evpl_libfabric    *lf = arg;
    struct evpl_libfabric_fd *watch, *tmp;

    lf->polling = 0;
    HASH_ITER(hh, lf->wait_fds, watch, tmp)
    {
        evpl_libfabric_fd_interest(watch);
    }
} /* evpl_libfabric_poll_exit */

static void evpl_libfabric_poll(
    struct evpl *evpl,
    void        *arg);

/* A flush deferral must not re-arm itself on EAGAIN: deferrals run until
* empty, so that prevents CQ progress needed by connection handshakes. */
static void
evpl_libfabric_retry(struct evpl_libfabric_ep *lfep)
{
    if (!lfep->retry_pending) {
        lfep->retry_pending = 1;
        DL_APPEND2(lfep->lf->retry_eps, lfep, retry_prev, retry_next);
    }
} /* evpl_libfabric_retry */

static void
evpl_libfabric_retry_flush(struct evpl_libfabric *lf)
{
    struct evpl_libfabric_ep *lfep;

    while (lf->retry_eps) {
        lfep = lf->retry_eps;
        DL_DELETE2(lf->retry_eps, lfep, retry_prev, retry_next);
        lfep->retry_pending = 0;
        evpl_defer(lf->evpl, &evpl_private2bind(lfep)->flush_deferral);
    }
} /* evpl_libfabric_retry_flush */

static int
evpl_libfabric_prepare_wait(
    struct evpl *evpl,
    void        *arg)
{
    struct evpl_libfabric      *lf = arg;
    struct evpl_libfabric_wait *wait;
    int                         rc, busy = 0;

    if (lf->retry_eps) {
        evpl_libfabric_poll(evpl, lf);
        busy = 1;
    }

    DL_FOREACH(lf->waits, wait)
    {
        if (wait->mode == FI_WAIT_NONE) {
            continue;
        }
        /* Check separately: fi_trywait requires a common wait-object type
         * within each call, and providers can select different CQ/EQ types. */
        rc = fi_trywait(wait->tdev->dev->fabric, &wait->fid, 1);
        if (rc == -FI_EAGAIN) {
            evpl_libfabric_wait_progress(wait);
            busy = 1;
        } else {
            evpl_libfabric_abort_if(rc, "fi_trywait: %s", fi_strerror(-rc));
        }
    }
    /* Progress on a later CQ can change another CQ's provider descriptor
     * set.  Snapshot all sets only after every progress call has completed. */
    DL_FOREACH(lf->waits, wait)
    {
        busy |= evpl_libfabric_wait_sync(wait);
    }
    evpl_libfabric_fds_commit(lf);
    return busy;
} /* evpl_libfabric_prepare_wait */

static void
evpl_libfabric_poll(
    struct evpl *evpl,
    void        *arg)
{
    struct evpl_libfabric    *lf = arg;
    int                       i;
    struct evpl_libfabric_cq *cq;

    for (i = 0; i < lf->num_active_devices; ++i) {
        evpl_libfabric_poll_cq(evpl, &lf->active_devices[i]->cq, 0);
        DL_FOREACH(lf->active_devices[i]->recv_cqs, cq)
        {
            evpl_libfabric_poll_cq(evpl, cq, 0);
        }
        evpl_libfabric_drain_eq(evpl, lf->active_devices[i], NULL);
    }
    evpl_libfabric_retry_flush(lf);
} /* evpl_libfabric_poll */

/* Queues without native wait objects still need periodic manual progress. */
static void
evpl_libfabric_tick(
    struct evpl       *evpl,
    struct evpl_timer *timer)
{
    struct evpl_libfabric *lf = container_of(timer, struct evpl_libfabric, tick);

    evpl_libfabric_poll(evpl, lf);
} /* evpl_libfabric_tick */

static void
evpl_libfabric_update_tick(struct evpl_libfabric *lf)
{
    struct evpl_libfabric_wait *wait;
    int                         needed = 0;

    DL_FOREACH(lf->waits, wait)
    {
        if (wait->tdev->num_ep && wait->mode == FI_WAIT_NONE) {
            needed = 1;
            break;
        }
    }
    if (needed && !lf->tick_armed) {
        evpl_add_timer(lf->evpl, &lf->tick, evpl_libfabric_tick,
                       EVPL_LIBFABRIC_TICK_US);
        lf->tick_armed = 1;
    } else if (!needed && lf->tick_armed) {
        evpl_remove_timer(lf->evpl, &lf->tick);
        lf->tick_armed = 0;
    }
} /* evpl_libfabric_update_tick */

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

    evpl_libfabric_update_tick(lf);
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

    evpl_libfabric_update_tick(lf);
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
        lf->devices[i].lf  = lf;
        lf->devices[i].dev = &devices->devices[i];
    }

    lf->poll = evpl_add_poll(evpl,
                             evpl_libfabric_poll_enter,
                             evpl_libfabric_poll_exit,
                             evpl_libfabric_poll,
                             lf);
    lf->polling = evpl->poll_mode;
    evpl_poll_set_prepare_callback(lf->poll, evpl_libfabric_prepare_wait);

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

        evpl_libfabric_abort_if(tdev->recv_cqs || tdev->srq.ep,
                                "receive queues remain at thread shutdown");
        evpl_libfabric_cq_close(evpl, &tdev->cq);

        evpl_libfabric_unwire_wait(&tdev->eq_wait);

        if (tdev->eq) {
            fi_close(&tdev->eq->fid);
        }

    }

    /* All subscriptions are gone; retire the borrowed-fd watchers before
     * freeing the framework that owns their callbacks. */
    evpl_libfabric_fds_commit(lf);

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

    while (lf->free_transfer) {
        struct evpl_libfabric_transfer *transfer = lf->free_transfer;
        DL_DELETE(lf->free_transfer, transfer);
        evpl_free(transfer);
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
    struct evpl                 *evpl,
    struct evpl_libfabric_recvq *rq)
{
    struct evpl_libfabric        *lf     = rq->tdev->lf;
    struct evpl_libfabric_device *dev    = rq->tdev->dev;
    struct evpl_global_config    *config = evpl_shared->config;
    struct evpl_libfabric_ctx    *ctx;
    struct evpl_libfabric_mr     *mrset;
    struct iovec                  iov;
    void                         *desc;
    struct fi_msg                 msg;
    unsigned int                  size;
    ssize_t                       rc;

    unsigned int                  batch = config->libfabric_rq_batch;

    if (!rq->ep || (rq->owner && rq->owner->closed)) {
        return;
    }
    if (!batch || batch > config->libfabric_rq_size) {
        batch = config->libfabric_rq_size;
    }
    if (config->libfabric_rq_size - rq->posted < batch) {
        return;
    }

    if (config->libfabric_datagram_size_override) {
        size = config->libfabric_datagram_size_override;
    } else {
        size = config->max_datagram_size;
    }

    while (rq->posted < config->libfabric_rq_size) {

        ctx = evpl_libfabric_ctx_alloc(lf);

        ctx->op   = EVPL_LIBFABRIC_OP_RECV;
        ctx->lfep = rq->owner;
        ctx->rq   = rq;

        if (rq->owner && rq->owner->rdm) {
            rc = evpl_iovec_alloc(evpl, size + sizeof(struct evpl_libfabric_rdm_header),
                                  8, 1, 0, &ctx->iovec);
            evpl_libfabric_abort_if(rc != 1, "RDM receive buffer including header exceeds buffer size");
        } else {
            evpl_iovec_alloc_datagram(evpl, &ctx->iovec, size);
        }

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

        rc = fi_recvmsg(rq->ep, &msg, FI_COMPLETION);

        if (rc == -FI_EAGAIN) {
            evpl_iovec_release_internal(evpl, &ctx->iovec);
            evpl_libfabric_ctx_free(lf, ctx);
            break;
        }

        evpl_libfabric_abort_if(rc, "fi_recvmsg: %s", fi_strerror(-rc));

        DL_APPEND(rq->posted_recvs, ctx);
        rq->posted++;
    }
} /* evpl_libfabric_fill_rq */

/* The shared queue is closed only after its last endpoint and receive CQ
 * have been drained.  A connection close must never free another connection's
 * posted receives. */
static void
evpl_libfabric_rq_release(
    struct evpl                 *evpl,
    struct evpl_libfabric_recvq *rq)
{
    struct evpl_libfabric_ctx *ctx;

    while (rq->posted_recvs) {
        ctx = rq->posted_recvs;
        DL_DELETE(rq->posted_recvs, ctx);
        evpl_iovec_release_internal(evpl, &ctx->iovec);
        evpl_libfabric_ctx_free(rq->tdev->lf, ctx);
    }
    rq->posted = 0;
    rq->ep     = NULL;
} /* evpl_libfabric_rq_release */

static void
evpl_libfabric_srq_open(struct evpl_libfabric_thread_device *tdev)
{
    struct evpl_global_config *config = evpl_shared->config;
    struct fi_rx_attr          attr;
    int                        rc;

    if (tdev->srq.ep || tdev->srq_unavailable) {
        return;
    }
    if (!config->libfabric_srq_enabled ||
        !tdev->dev->info->domain_attr->max_ep_srx_ctx) {
        tdev->srq_unavailable = 1;
        return;
    }

    attr           = *tdev->dev->info->rx_attr;
    attr.size      = config->libfabric_rq_size;
    attr.iov_limit = 1;
    tdev->srq.tdev = tdev;
    rc             = fi_srx_context(tdev->dev->domain, &attr, &tdev->srq.ep, &tdev->srq);
    if (rc == -FI_ENOSYS || rc == -FI_EOPNOTSUPP || rc == -FI_ENODATA) {
        tdev->srq_unavailable = 1;
        evpl_libfabric_debug("shared receives unavailable on %s; using private queues",
                             tdev->dev->info->domain_attr->name);
        return;
    }
    evpl_libfabric_abort_if(rc, "fi_srx_context(%s): %s",
                            tdev->dev->info->domain_attr->name, fi_strerror(-rc));
} /* evpl_libfabric_srq_open */

static void
evpl_libfabric_receive_setup(
    struct evpl              *evpl,
    struct evpl_libfabric_ep *lfep)
{
    struct evpl_libfabric_thread_device *tdev = lfep->tdev;
    int                                  rc;

    evpl_libfabric_cq_open(evpl, tdev, &lfep->recv_cq, lfep);
    /* Receive completions are mandatory. In particular tcp SRX does not
     * propagate per-post FI_COMPLETION to selectively completed endpoints. */
    rc = fi_ep_bind(lfep->ep, &lfep->recv_cq.cq->fid,
                    FI_RECV);
    evpl_libfabric_abort_if(rc, "fi_ep_bind(recv cq): %s", fi_strerror(-rc));

    if (!lfep->rdm && tdev->srq.ep) {
        rc = fi_ep_bind(lfep->ep, &tdev->srq.ep->fid, 0);
        evpl_libfabric_abort_if(rc, "fi_ep_bind(srq): %s", fi_strerror(-rc));
        lfep->rq = &tdev->srq;
        tdev->srq_users++;
    } else {
        lfep->private_rq.tdev  = tdev;
        lfep->private_rq.ep    = lfep->ep;
        lfep->private_rq.owner = lfep;
        lfep->rq               = &lfep->private_rq;
    }
} /* evpl_libfabric_receive_setup */

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

        if (!lfep->read_transfer) {
            lfep->read_transfer = evpl_libfabric_transfer_alloc(lf);
            DL_APPEND(lfep->read_transfers, lfep->read_transfer);
        }

        len = evpl_libfabric_gather(&bind->iovec_rdma_read, dgram,
                                    lfep->read_offset, dev->iov_limit,
                                    (size_t) -1, iov, desc, dev->mr_local,
                                    dev->index, &niov);

        ctx = evpl_libfabric_ctx_alloc(lf);

        ctx->op       = EVPL_LIBFABRIC_OP_READ;
        ctx->lfep     = lfep;
        ctx->transfer = lfep->read_transfer;

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
            evpl_libfabric_retry(lfep);
            break;
        }

        evpl_libfabric_abort_if(rc, "fi_readmsg: %s", fi_strerror(-rc));

        DL_APPEND(lfep->posted_sends, ctx);
        lfep->cur_rdma_reads++;
        ctx->transfer->pending++;

        lfep->read_offset += len;

        if (lfep->read_offset == dgram->length) {

            bind->iovec_rdma_read.waist =
                (bind->iovec_rdma_read.waist + dgram->niov) &
                bind->iovec_rdma_read.mask;

            bind->dgram_read.waist =
                (bind->dgram_read.waist + 1) & bind->dgram_read.mask;

            lfep->read_transfer->submitted = 1;
            lfep->read_transfer            = NULL;
            lfep->read_offset              = 0;
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
    size_t                        niov, len, cap, header_size;
    ssize_t                       rc;
    int                           k, tx_limit;

    if (unlikely(!lfep->ep || !lfep->connected)) {
        return;
    }

    dev         = lfep->tdev->dev;
    tx_limit    = evpl_shared->config->libfabric_tx_size;
    cap         = evpl_libfabric_recv_capacity();
    header_size = lfep->rdm ? sizeof(struct evpl_libfabric_rdm_header) : 0;

    evpl_libfabric_flush_rdma_reads(evpl, bind);

    while (lfep->cur_sends < tx_limit &&
           bind->dgram_send.waist != bind->dgram_send.head) {

        dgram = evpl_dgram_ring_waist(&bind->dgram_send);

        if (!lfep->send_transfer) {
            lfep->send_transfer = evpl_libfabric_transfer_alloc(lf);
            DL_APPEND(lfep->send_transfers, lfep->send_transfer);
        }

        if (dgram->dgram_type == EVPL_DGRAM_TYPE_RDMA_WRITE) {

            len = evpl_libfabric_gather(&bind->iovec_send, dgram,
                                        lfep->send_offset, dev->iov_limit,
                                        (size_t) -1, iov, desc,
                                        dev->mr_local, dev->index, &niov);

            ctx = evpl_libfabric_ctx_alloc(lf);

            ctx->op       = EVPL_LIBFABRIC_OP_SEND;
            ctx->lfep     = lfep;
            ctx->transfer = lfep->send_transfer;

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
                evpl_libfabric_retry(lfep);
                break;
            }

            evpl_libfabric_abort_if(rc, "fi_writemsg: %s", fi_strerror(-rc));

            DL_APPEND(lfep->posted_sends, ctx);
            lfep->cur_sends++;
            ctx->transfer->pending++;

            lfep->send_offset += len;

            if (lfep->send_offset == dgram->length) {

                bind->iovec_send.waist =
                    (bind->iovec_send.waist + dgram->niov) &
                    bind->iovec_send.mask;

                bind->dgram_send.waist =
                    (bind->dgram_send.waist + 1) & bind->dgram_send.mask;

                lfep->send_transfer->submitted = 1;
                lfep->send_transfer            = NULL;
                lfep->send_offset              = 0;
            }

            continue;
        }

        dest = FI_ADDR_UNSPEC;

        if (lfep->rdm) {
            dest = evpl_libfabric_peer_resolve(lf, dev, dgram->addr);
        }

        evpl_libfabric_abort_if(!lfep->stream && dgram->length > cap,
                                "datagram exceeds receive capacity");

        if (lfep->stream || dgram->niov + !!header_size <= dev->iov_limit) {

            len = evpl_libfabric_gather(&bind->iovec_send, dgram,
                                        lfep->send_offset,
                                        dev->iov_limit - !!header_size,
                                        lfep->stream ? cap : (size_t) -1,
                                        iov + !!header_size, desc + !!header_size, dev->mr_local,
                                        dev->index, &niov);

            evpl_libfabric_abort_if(!lfep->stream &&
                                    lfep->send_offset + len < dgram->length,
                                    "datagram of %u bytes cannot be sent whole "
                                    "(receive capacity %zu)",
                                    dgram->length, cap);

            ctx = evpl_libfabric_ctx_alloc(lf);

            ctx->op       = EVPL_LIBFABRIC_OP_SEND;
            ctx->lfep     = lfep;
            ctx->transfer = lfep->send_transfer;

            if (header_size) {
                struct evpl_libfabric_mr *mrset =
                    evpl_memory_framework_private(&lfep->rdm_header, EVPL_FRAMEWORK_LIBFABRIC);
                iov[0].iov_base = lfep->rdm_header.data;
                iov[0].iov_len  = header_size;
                desc[0]         = dev->mr_local ? fi_mr_desc(mrset[dev->index].mr) : NULL;
                niov++;
            }

            memset(&msg, 0, sizeof(msg));
            msg.msg_iov   = iov;
            msg.desc      = desc;
            msg.iov_count = niov;
            msg.addr      = dest;
            msg.context   = ctx;

        } else {

            /* Datagrams exceeding the provider iovec limit (including the
             * RDM envelope) must retain their boundary, so coalesce. */
            evpl_libfabric_abort_if(dgram->length > cap,
                                    "datagram of %u bytes cannot be sent whole "
                                    "(receive capacity %zu)",
                                    dgram->length, cap);

            ctx = evpl_libfabric_ctx_alloc(lf);

            ctx->op       = EVPL_LIBFABRIC_OP_SEND;
            ctx->lfep     = lfep;
            ctx->transfer = lfep->send_transfer;

            if (header_size) {
                rc = evpl_iovec_alloc(evpl, dgram->length + header_size, 8, 1, 0, &ctx->iovec);
                evpl_libfabric_abort_if(rc != 1, "RDM send buffer including header exceeds buffer size");
                memcpy(ctx->iovec.data, lfep->rdm_header.data, header_size);
            } else {
                evpl_iovec_alloc_datagram(evpl, &ctx->iovec, dgram->length);
            }

            len = 0;

            for (k = 0; k < dgram->niov; ++k) {
                cur = &bind->iovec_send.iovec[
                    (bind->iovec_send.waist + k) & bind->iovec_send.mask];

                memcpy((char *) ctx->iovec.data + header_size + len, cur->data, cur->length);
                len += cur->length;
            }

            iov[0].iov_base = ctx->iovec.data;
            iov[0].iov_len  = len + header_size;

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

        if (len + header_size <= dev->inject_size &&
            (evpl_shared->config->libfabric_inject_max == 0 ||
             len + header_size <= evpl_shared->config->libfabric_inject_max)) {
            flags |= FI_INJECT;
        }

        rc = fi_sendmsg(lfep->ep, &msg, flags);

        if (rc == -FI_EAGAIN) {
            if (ctx->iovec.ref) {
                evpl_iovec_release_internal(evpl, &ctx->iovec);
            }
            evpl_libfabric_ctx_free(lf, ctx);
            evpl_libfabric_retry(lfep);
            break;
        }

        evpl_libfabric_abort_if(rc, "fi_sendmsg: %s", fi_strerror(-rc));

        DL_APPEND(lfep->posted_sends, ctx);
        lfep->cur_sends++;
        ctx->transfer->pending++;

        lfep->send_offset += len;

        if (lfep->send_offset == dgram->length) {

            bind->iovec_send.waist =
                (bind->iovec_send.waist + dgram->niov) &
                bind->iovec_send.mask;

            bind->dgram_send.waist =
                (bind->dgram_send.waist + 1) & bind->dgram_send.mask;

            lfep->send_transfer->submitted = 1;
            lfep->send_transfer            = NULL;
            lfep->send_offset              = 0;
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

    evpl_libfabric_srq_open(tdev);
    if (tdev->srq.ep) {
        info->ep_attr->rx_ctx_cnt = FI_SHARED_CONTEXT;
    }

    rc = fi_endpoint(dev->domain, info, &lfep->ep, lfep);

    evpl_libfabric_abort_if(rc, "fi_endpoint(%s): %s",
                            dev->info->domain_attr->name, fi_strerror(-rc));

    rc = fi_ep_bind(lfep->ep, &tdev->eq->fid, 0);

    evpl_libfabric_abort_if(rc, "fi_ep_bind(eq): %s", fi_strerror(-rc));

    rc = fi_ep_bind(lfep->ep, &tdev->cq.cq->fid,
                    FI_TRANSMIT | FI_SELECTIVE_COMPLETION);

    evpl_libfabric_abort_if(rc, "fi_ep_bind(cq): %s", fi_strerror(-rc));

    evpl_libfabric_receive_setup(evpl, lfep);

    rc = fi_enable(lfep->ep);

    evpl_libfabric_abort_if(rc, "fi_enable: %s", fi_strerror(-rc));

    evpl_libfabric_fill_rq(evpl, lfep->rq);

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
    struct evpl_libfabric          *lf            = evpl_libfabric_thread(evpl);
    struct evpl_libfabric_ep       *lfep          = evpl_bind_private(bind);
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
    struct sockaddr_in                   local;
    size_t                               local_size = sizeof(local);
    struct evpl_libfabric_rdm_header     header;
    int                                  rc, devindex = -1;

    memset(lfep, 0, sizeof(*lfep));

    lfep->lf  = lf;
    lfep->rdm = 1;

    evpl_libfabric_addr_strings(bind->local, node, sizeof(node),
                                service, sizeof(service));

    hints = evpl_libfabric_hints_type(FI_EP_RDM, FI_MSG);

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

    rc = fi_ep_bind(lfep->ep, &tdev->cq.cq->fid,
                    FI_TRANSMIT | FI_SELECTIVE_COMPLETION);

    evpl_libfabric_abort_if(rc, "fi_ep_bind(cq): %s", fi_strerror(-rc));

    evpl_libfabric_receive_setup(evpl, lfep);

    rc = fi_enable(lfep->ep);

    evpl_libfabric_abort_if(rc, "fi_enable(rdm): %s", fi_strerror(-rc));

    memset(&local, 0, sizeof(local));
    rc = fi_getname(&lfep->ep->fid, &local, &local_size);
    evpl_libfabric_abort_if(rc || local_size != sizeof(local) || local.sin_family != AF_INET,
                            "RDM endpoint did not return an IPv4 listening address");
    if (local.sin_addr.s_addr == htonl(INADDR_ANY)) {
        evpl_libfabric_abort_if(!dev->info->src_addr ||
                                dev->info->src_addrlen < sizeof(local) ||
                                ((struct sockaddr_in *) dev->info->src_addr)->sin_family != AF_INET,
                                "wildcard RDM endpoint has no IPv4 domain address");
        local.sin_addr = ((struct sockaddr_in *) dev->info->src_addr)->sin_addr;
    }
    evpl_libfabric_abort_if(!local.sin_addr.s_addr || !local.sin_port,
                            "RDM endpoint has no advertisable listening address");
    header = (struct evpl_libfabric_rdm_header) {
        htonl(EVPL_LIBFABRIC_RDM_MAGIC), local.sin_addr.s_addr, local.sin_port, 0
    };
    rc = evpl_iovec_alloc(evpl, sizeof(header), 8, 1, 0, &lfep->rdm_header);
    evpl_libfabric_abort_if(rc != 1, "RDM header allocation failed");
    memcpy(lfep->rdm_header.data, &header, sizeof(header));
    evpl_address_release(bind->local);
    bind->local = evpl_address_init((struct sockaddr *) &local, sizeof(local));

    evpl_libfabric_fill_rq(evpl, lfep->rq);

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
    int                                  rc;

    if (lfep->retry_pending) {
        DL_DELETE2(lf->retry_eps, lfep, retry_prev, retry_next);
        lfep->retry_pending = 0;
    }

    lfep->closed    = 1;
    lfep->connected = 0;

    if (lfep->pep) {
        closed_fid = &lfep->pep->fid;
        fi_close(&lfep->pep->fid);
        lfep->pep = NULL;
    }

    if (lfep->ep) {
        closed_fid = &lfep->ep->fid;
        /* Drain completed shared receives before the provider can discard
         * them at endpoint close, then consume cancellation completions. */
        evpl_libfabric_poll_cq(evpl, &lfep->recv_cq, 1);
        rc = fi_close(&lfep->ep->fid);
        evpl_libfabric_abort_if(rc, "fi_close(ep): %s", fi_strerror(-rc));
        lfep->ep = NULL;
    }

    if (tdev && closed_fid) {

        /* completions already queued for this endpoint (including the
         * FI_ECANCELED entries for its posted receives) must be consumed
         * before the bind memory is recycled */
        evpl_libfabric_poll_cq(evpl, &tdev->cq, 1);
        evpl_libfabric_drain_eq(evpl, tdev, closed_fid);

        if (lfep->rq) {
            evpl_libfabric_poll_cq(evpl, &lfep->recv_cq, 1);
            evpl_libfabric_cq_close(evpl, &lfep->recv_cq);
            if (lfep->rq == &tdev->srq) {
                if (--tdev->srq_users == 0) {
                    rc = fi_close(&tdev->srq.ep->fid);
                    evpl_libfabric_abort_if(rc, "fi_close(srq): %s", fi_strerror(-rc));
                    evpl_libfabric_rq_release(evpl, &tdev->srq);
                }
            } else {
                evpl_libfabric_rq_release(evpl, &lfep->private_rq);
            }
            lfep->rq = NULL;
        }

        while (lfep->posted_sends) {
            ctx = lfep->posted_sends;
            DL_DELETE(lfep->posted_sends, ctx);
            if (ctx->op == EVPL_LIBFABRIC_OP_READ) {
                lfep->cur_rdma_reads--;
            } else {
                lfep->cur_sends--;
            }
            if (ctx->iovec.ref) {
                evpl_iovec_release_internal(evpl, &ctx->iovec);
            }
            evpl_libfabric_ctx_free(lf, ctx);
        }

        while (lfep->send_transfers) {
            struct evpl_libfabric_transfer *transfer = lfep->send_transfers;
            DL_DELETE(lfep->send_transfers, transfer);
            evpl_libfabric_transfer_free(lf, transfer);
        }
        while (lfep->read_transfers) {
            struct evpl_libfabric_transfer *transfer = lfep->read_transfers;
            DL_DELETE(lfep->read_transfers, transfer);
            evpl_libfabric_transfer_free(lf, transfer);
        }
        lfep->send_transfer = NULL;
        lfep->read_transfer = NULL;

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

    if (lfep->rdm_header.ref) {
        evpl_iovec_release_internal(evpl, &lfep->rdm_header);
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
