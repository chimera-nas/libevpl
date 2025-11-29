// SPDX-FileCopyrightText: 2025 Ben Jarvis
//
// SPDX-License-Identifier: LGPL-2.1-only

#define _GNU_SOURCE
#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include <linux/vfio.h>
#include <linux/pci.h>
#include <sys/eventfd.h>
#include <sys/mman.h>
#include <pthread.h>
#include <errno.h>
#include <sys/fcntl.h>
#include <sys/ioctl.h>
#include <utlist.h>
#include "vfio.h"
#include "core/evpl.h"
#include "core/iovec.h"
#include "core/protocol.h"
#include "core/allocator.h"
#include "core/event_fn.h"
#include "core/poll.h"
#include "core/macros.h"
#include "nvme.h"

#define VFIO_IOVA_START 0x10000000000ULL
#define VFIO_IOVA_MAX   0x20000000000ULL

#define evpl_vfio_debug(...) evpl_debug("vfio", __FILE__, __LINE__, __VA_ARGS__)
#define evpl_vfio_error(...) evpl_error("vfio", __FILE__, __LINE__, __VA_ARGS__)
#define evpl_vfio_fatal(...) evpl_fatal("vfio", __FILE__, __LINE__, __VA_ARGS__)
#define evpl_vfio_abort(...) evpl_abort("vfio", __FILE__, __LINE__, __VA_ARGS__)

#define evpl_vfio_fatal_if(cond, ...) \
        evpl_fatal_if(cond, "vfio", __FILE__, __LINE__, __VA_ARGS__)

#define evpl_vfio_abort_if(cond, ...) \
        evpl_abort_if(cond, "vfio", __FILE__, __LINE__, __VA_ARGS__)


struct evpl_vfio_callback_ctx {
    evpl_block_callback_t fn;
    void                 *arg;
};


struct evpl_vfio_mr {
    void    *buffer;
    uint64_t iova;
    uint64_t size;
};

struct evpl_vfio_queue {
    struct evpl_vfio_device       *device;
    uint32_t                       id;
    uint32_t                       size;
    uint32_t                       sizemask;
    int                            cidcount;
    union nvme_sq_entry           *sq;
    struct nvme_cq_entry          *cq;
    uint32_t                      *sq_doorbell;
    uint32_t                      *cq_doorbell;
    struct evpl_vfio_mr           *sqbuffer;
    struct evpl_vfio_mr           *cqbuffer;
    struct evpl_vfio_mr           *prplist;
    int                            sq_tail;
    int                            cq_head;
    uint16_t                       cq_phase;
    int                            eventfd;
    struct evpl_event              event;
    struct evpl_deferral           ring_sq;
    struct evpl_vfio_callback_ctx *callbacks;
    struct evpl_vfio_queue        *prev;
    struct evpl_vfio_queue        *next;
};

struct evpl_vfio_identify_ctx {
    struct evpl_vfio_device *device;
    int                      nsid;
    struct evpl_vfio_mr     *mr;
};

struct evpl_vfio_group {
    int                     fd;
    struct evpl_vfio_group *prev;
    struct evpl_vfio_group *next;
};

struct evpl_vfio_shared {
    int                     container_fd;
    uint64_t                iova_current;
    struct evpl_vfio_group *groups;
    pthread_mutex_t         lock;
};

struct evpl_vfio_device {
    int                         fd;
    uint64_t                    max_xfer_bytes;
    uint64_t                    num_sectors;
    uint32_t                    sector_size;
    uint32_t                    sector_shift;
    uint32_t                    queue_size;
    uint64_t                    max_queues;
    uint32_t                    next_ioq_id;
    char                        model[64];
    char                        serial[64];
    uint64_t                    msixsize;
    uint32_t                    sgls;
    int                         sgl_supported;
    int                         sgl_unaligned;
    uint64_t                    timeout;
    uint64_t                    max_queue_size;
    uint64_t                    dbstride;
    int                        *eventfds;
    struct evpl_vfio_shared    *vfio;
    struct vfio_device_info     device_info;
    struct nvme_controller_reg *reg;
    struct evpl_vfio_queue     *adminq;
    struct evpl_vfio_queue     *ioq;
    pthread_mutex_t             lock;
};

static void *
evpl_vfio_init(void)
{
    struct evpl_vfio_shared *shared;
    int                      container_fd;

    // Open the VFIO container
    container_fd = open("/dev/vfio/vfio", O_RDWR);
    if (container_fd < 0) {
        evpl_vfio_error("Failed to open VFIO container");
        return NULL;
    }

    // Check if VFIO is supported
    if (ioctl(container_fd, VFIO_GET_API_VERSION) != VFIO_API_VERSION) {
        close(container_fd);
        evpl_vfio_error("VFIO API version mismatch");
        return NULL;
    }

    // Initialize shared context
    shared = evpl_zalloc(sizeof(*shared));

    shared->container_fd = container_fd;
    shared->iova_current = VFIO_IOVA_START;

    pthread_mutex_init(&shared->lock, NULL);

    return shared;
} /* evpl_vfio_init */

static void
evpl_vfio_cleanup(void *framework_private)
{
    struct evpl_vfio_shared *shared = framework_private;
    struct evpl_vfio_group  *group;

    while (shared->groups) {
        group = shared->groups;
        DL_DELETE(shared->groups, group);
        close(group->fd);
        evpl_free(group);
    }

    close(shared->container_fd);
    pthread_mutex_destroy(&shared->lock);
    evpl_free(shared);
} /* evpl_vfio_cleanup */

static void *
evpl_vfio_create(
    struct evpl *evpl,
    void        *private_data)
{
    return private_data;
} /* evpl_vfio_create */

static void
evpl_vfio_destroy(
    struct evpl *evpl,
    void        *framework_private)
{
} /* evpl_vfio_destroy */

static struct evpl_vfio_mr *
evpl_vfio_register(
    struct evpl_vfio_shared *vfio,
    void                    *buffer,
    int                      size)
{
    struct vfio_iommu_type1_dma_map map = { 0 };
    struct evpl_vfio_mr            *mr;
    int                             rc;

    mr = evpl_zalloc(sizeof(*mr));

    pthread_mutex_lock(&vfio->lock);

    evpl_vfio_abort_if(vfio->iova_current + size > VFIO_IOVA_MAX,
                       "Registered maximum amount of VFIO memory");

    size = (size + 4095) & ~4095;

    vfio->iova_current = (vfio->iova_current + size - 1) & ~(size - 1);

    mr->buffer = buffer;
    mr->iova   = vfio->iova_current;
    mr->size   = size;


    vfio->iova_current += size;

    map.argsz = sizeof(map);
    map.flags = VFIO_DMA_MAP_FLAG_READ | VFIO_DMA_MAP_FLAG_WRITE;
    map.vaddr = (uint64_t) buffer;
    map.iova  = mr->iova;
    map.size  = mr->size;

    rc = ioctl(vfio->container_fd, VFIO_IOMMU_MAP_DMA, &map);


    evpl_vfio_abort_if(rc < 0, "Failed to MAP DMA memory: %s", strerror(errno));

    pthread_mutex_unlock(&vfio->lock);

    return mr;
} /* evpl_vfio_register */

static void
evpl_vfio_unregister(
    struct evpl_vfio_shared *vfio,
    struct evpl_vfio_mr     *mr)
{
    struct vfio_iommu_type1_dma_unmap unmap = { 0 };

    unmap.argsz = sizeof(unmap);
    unmap.flags = 0;
    unmap.iova  = mr->iova;
    unmap.size  = mr->size;

    ioctl(vfio->container_fd, VFIO_IOMMU_UNMAP_DMA, &unmap);

    evpl_free(mr);
} /* evpl_vfio_unregister */

static struct evpl_vfio_mr *
evpl_vfio_alloc(
    struct evpl_vfio_shared *vfio,
    int                      size)
{
    void *buffer = evpl_valloc(size, 4096);

    return evpl_vfio_register(vfio, buffer, size);
} /* evpl_vfio_alloc */

static void
evpl_vfio_free(
    struct evpl_vfio_shared *vfio,
    struct evpl_vfio_mr     *mr)
{
    void *ptr = mr->buffer;

    evpl_vfio_unregister(vfio, mr);

    evpl_free(ptr);
} /* evpl_vfio_free */

static void *
evpl_vfio_register_memory(
    void *buffer,
    int   size,
    void *buffer_private,
    void *private_data)
{
    struct evpl_vfio_shared *shared = private_data;

    if (buffer_private) {
        /* We don't need to do anything if we've already registered the memory */
        return buffer_private;
    }

    return evpl_vfio_register(shared, buffer, size);
} /* evpl_vfio_register_memory */

// Memory unregistration callback for the framework
static void
evpl_vfio_unregister_memory(
    void *buffer_private,
    void *private_data)
{
    struct evpl_vfio_shared *shared = private_data;
    struct evpl_vfio_mr     *mr     = buffer_private;

    evpl_vfio_unregister(shared, mr);
} /* evpl_vfio_unregister_memory */

static int
evpl_vfio_attach_device(
    struct evpl_vfio_shared *vfio,
    const char              *pciname)
{
    int                     pci_bus, pci_device, pci_function;
    char                    pciname_vfio[32];
    char                    iommu_group_path[256];
    char                    iommu_group_link[256];
    char                    vfio_device_path[80];
    char                   *iommu_group;
    ssize_t                 len;
    struct evpl_vfio_group *group;
    int                     device_fd;
    int                     first_group = !!(vfio->groups == NULL);
    int                     rc;

    if (sscanf(pciname, "%x:%x.%x", &pci_bus, &pci_device, &pci_function) != 3) {
        evpl_vfio_error("Invalid NVMe PCI name '%s', expected bus:device:function", pciname);
        return -1;
    }

    snprintf(pciname_vfio, sizeof(pciname_vfio), "0000:%02x:%02x.%x",
             pci_bus, pci_device, pci_function);

    snprintf(iommu_group_link, sizeof(iommu_group_link),
             "/sys/bus/pci/devices/%s/iommu_group", pciname_vfio);

    len = readlink(iommu_group_link, iommu_group_path, sizeof(iommu_group_path));

    if (len < 0) {
        evpl_vfio_error("Failed to read link '%s' :%s", iommu_group_link, strerror(errno));
        return -1;
    }

    iommu_group_path[len] = '\0';

    iommu_group = strrchr(iommu_group_path, '/');

    snprintf(vfio_device_path, sizeof(vfio_device_path), "/dev/vfio%s", iommu_group);

    group = evpl_zalloc(sizeof(*group));

    DL_APPEND(vfio->groups, group);

    group->fd = open(vfio_device_path, O_RDWR);

    evpl_vfio_abort_if(group->fd < 0, "Failed to open VFIO IOMMU device '%s': %s",
                       vfio_device_path, strerror(errno));

    rc = ioctl(group->fd, VFIO_GROUP_SET_CONTAINER, &vfio->container_fd);

    evpl_vfio_abort_if(rc, "Failed to set VFIO container");

    if (first_group) {
        rc = ioctl(vfio->container_fd, VFIO_SET_IOMMU, VFIO_TYPE1_IOMMU);
        evpl_vfio_abort_if(rc < 0, "Failed to set VFIO IOMMU to Type 1: %s", strerror(errno));
    }

    device_fd = ioctl(group->fd, VFIO_GROUP_GET_DEVICE_FD, pciname_vfio);

    evpl_vfio_abort_if(device_fd < 0, "Failed to open VFIO IOMMU NVMe device");


    return device_fd;
} /* evpl_vfio_attach_device */

static void
evpl_vfio_enable_msix(struct evpl_vfio_device *device)
{
    struct vfio_irq_set *irqs;
    int                  length, i, rc;
    int32_t             *efds;

    device->eventfds = evpl_zalloc(device->msixsize * sizeof(int));

    for (i = 0; i < device->msixsize; ++i) {
        device->eventfds[i] = eventfd(0, EFD_NONBLOCK);

        evpl_vfio_abort_if(device->eventfds[i] < 0, "Failed to create eventfd");
    }

    length = sizeof(struct vfio_irq_set) + device->msixsize * sizeof(int32_t);

    irqs = evpl_zalloc(length);

    efds = (int32_t *) irqs->data;

    memcpy(efds, device->eventfds, device->msixsize * sizeof(int));

    irqs->argsz = length;
    irqs->index = VFIO_PCI_MSIX_IRQ_INDEX;
    irqs->flags = VFIO_IRQ_SET_DATA_EVENTFD | VFIO_IRQ_SET_ACTION_TRIGGER;
    irqs->start = 0;
    irqs->count = device->msixsize;

    rc = ioctl(device->fd, VFIO_DEVICE_SET_IRQS, irqs);

    evpl_vfio_abort_if(rc, "Failed to enable MSI-X on device: %s", strerror(errno));

    evpl_free(irqs);

} /* evpl_vfio_enable_msix */

static struct evpl_vfio_queue *
evpl_vfio_queue_alloc(
    struct evpl_vfio_device *device,
    int                      id,
    int                      size)
{
    struct evpl_vfio_queue *queue;

    queue = evpl_zalloc(sizeof(*queue));

    queue->device      = device;
    queue->id          = id;
    queue->size        = size;
    queue->sizemask    = size - 1;
    queue->sqbuffer    = evpl_vfio_alloc(device->vfio, size * sizeof(union nvme_sq_entry));
    queue->cqbuffer    = evpl_vfio_alloc(device->vfio, size * sizeof(struct nvme_cq_entry));
    queue->prplist     = evpl_vfio_alloc(device->vfio, size << 12);
    queue->sq          = (union nvme_sq_entry *) queue->sqbuffer->buffer;
    queue->cq          = (struct nvme_cq_entry *) queue->cqbuffer->buffer;
    queue->sq_doorbell = device->reg->sq0tdbl + 2 * id * device->dbstride;
    queue->cq_doorbell = queue->sq_doorbell + device->dbstride;
    queue->callbacks   = evpl_zalloc(size * sizeof(struct evpl_vfio_callback_ctx));

    if (id > 0) {
        queue->eventfd = device->eventfds[id - 1];
    } else {
        queue->eventfd = -1;
    }

    return queue;
} /* evpl_vfio_queue_alloc */

static void
evpl_vfio_queue_close(
    struct evpl_vfio_device *device,
    struct evpl_vfio_queue  *queue)
{

    evpl_vfio_free(device->vfio, queue->sqbuffer);
    evpl_vfio_free(device->vfio, queue->cqbuffer);
    evpl_vfio_free(device->vfio, queue->prplist);
    evpl_free(queue->callbacks);
    evpl_free(queue);
} /* evpl_vfio_queue_close */

static inline int
evpl_vfio_alloc_cid(
    struct evpl_vfio_queue *queue,
    evpl_block_callback_t   callback,
    void                   *arg)
{
    int cid = queue->sq_tail;

    evpl_vfio_abort_if(queue->cidcount >= queue->size, "Queue exhausted");

    if (++queue->sq_tail == queue->size) {
        queue->sq_tail = 0;
    }

    queue->callbacks[cid].fn  = callback;
    queue->callbacks[cid].arg = arg;

    ++queue->cidcount;

    return cid;
} /* evpl_vfio_alloc_cid */

static inline void
evpl_vfio_ring_sq(struct evpl_vfio_queue *queue)
{
    *queue->sq_doorbell = queue->sq_tail;
} /* evpl_vfio_ring_sq */

static inline void
evpl_vfio_ring_cq(struct evpl_vfio_queue *queue)
{
    *queue->cq_doorbell = queue->cq_head;
} /* evpl_vfio_ring_cq */

static inline int
evpl_vfio_poll_queue(
    struct evpl            *evpl,
    struct evpl_vfio_queue *queue)
{
    struct nvme_cq_entry          *cqe;
    int                            cid, moved = 0;
    struct evpl_vfio_callback_ctx *cb;

    while (queue->cidcount) {

        cqe = &queue->cq[queue->cq_head];

        if (cqe->p == queue->cq_phase) {
            break;
        }

        moved = 1;

        cid = queue->cq_head;

        cb = &queue->callbacks[cid];

        if (cqe->sc) {
            evpl_vfio_error("cqecid %d  cs %d sct %d sc %d", cid, cqe->cs, cqe->sct, cqe->sc);
        }

        if (cb->fn) {
            cb->fn(evpl, cqe->sc ? EIO : 0, cb->arg);
        }

        --queue->cidcount;

        if (++queue->cq_head == queue->size) {
            queue->cq_head  = 0;
            queue->cq_phase = !queue->cq_phase;
        }
    }

    if (moved) {
        evpl_vfio_ring_cq(queue);
    }

    return moved;
} /* evpl_vfio_poll_queue */

static void
evpl_vfio_create_adminq(
    struct evpl_vfio_device *device,
    int                      size)
{
    struct evpl_vfio_queue      *adminq;
    union nvme_adminq_attr       aqa;
    union nvme_controller_config cc;
    union nvme_controller_status status;

    adminq = device->adminq = evpl_vfio_queue_alloc(device, 0, size);

    memset(&aqa, 0, sizeof(aqa));
    aqa.asqs = aqa.acqs = adminq->size - 1;

    device->reg->aqa.value = aqa.value;
    device->reg->asq       = adminq->sqbuffer->iova;
    device->reg->acq       = adminq->cqbuffer->iova;

    memset(&cc, 0, sizeof(cc));

    cc.iosqes = 6;
    cc.iocqes = 4;
    cc.mps    = 0; /* 4K */
    cc.en     = 1;

    /* submit it */
    device->reg->cc.value = cc.value;

    while (1) {
        status.value = device->reg->csts.value;
        if (status.rdy) {
            break;
        }
        sched_yield();
    }

} /* evpl_vfio_create_adminq */

static struct evpl_vfio_queue *
evpl_vfio_create_ioq(
    struct evpl             *evpl,
    struct evpl_vfio_device *device,
    int                      size)
{
    struct nvme_admin_create_sq *csq_cmd;
    struct nvme_admin_create_cq *ccq_cmd;
    int                          cid;
    struct evpl_vfio_queue      *ioq;
    int                          id;

    pthread_mutex_lock(&device->lock);

    evpl_vfio_abort_if(device->next_ioq_id >= device->msixsize,
                       "Too many VFIO device queues, exceeded msixsize.  Consider reducing thread count.");

    id = device->next_ioq_id++;

    ioq = evpl_vfio_queue_alloc(device, id, size);

    cid = evpl_vfio_alloc_cid(device->adminq, NULL, 0);

    ccq_cmd = &device->adminq->sq[cid].create_cq;

    /* create the cq */
    memset(ccq_cmd, 0, sizeof(*ccq_cmd));
    ccq_cmd->common.opc  = NVME_ADMIN_CREATE_IO_CQ;
    ccq_cmd->common.cid  = cid;
    ccq_cmd->common.prp1 = ioq->cqbuffer->iova;
    ccq_cmd->pc          = 1;
    ccq_cmd->qid         = ioq->id;
    ccq_cmd->qsize       = ioq->size - 1;
    ccq_cmd->ien         = ioq->id > 0 ? 1 : 0;
    ccq_cmd->iv          = ioq->id - 1;

    /* create the sq */
    cid = evpl_vfio_alloc_cid(device->adminq, NULL, 0);

    csq_cmd = &device->adminq->sq[cid].create_sq;

    memset(csq_cmd, 0, sizeof(*csq_cmd));
    csq_cmd->common.opc  = NVME_ADMIN_CREATE_IO_SQ;
    csq_cmd->common.cid  = cid;
    csq_cmd->common.prp1 = ioq->sqbuffer->iova;
    csq_cmd->pc          = 1;
    csq_cmd->qprio       = 2;
    csq_cmd->qid         = ioq->id;
    csq_cmd->cqid        = ioq->id;
    csq_cmd->qsize       = ioq->size - 1;

    evpl_vfio_ring_sq(device->adminq);

    while (device->adminq->cidcount > 0) {
        evpl_vfio_poll_queue(evpl, device->adminq);
    }

    pthread_mutex_unlock(&device->lock);

    return ioq;
} /* evpl_vfio_create_ioq */

static void
evpl_vfio_identify(
    struct evpl             *evpl,
    struct evpl_vfio_device *device,
    struct evpl_vfio_mr     *mr,
    int                      nsid,
    evpl_block_callback_t    callback,
    void                    *arg)
{
    struct nvme_admin_identify *cmd;
    int                         cid;

    cid = evpl_vfio_alloc_cid(device->adminq, callback, arg);

    cmd = &device->adminq->sq[cid].identify;

    memset(cmd, 0, sizeof(*cmd));
    cmd->common.opc  = NVME_ADMIN_IDENTIFY;
    cmd->common.cid  = cid;
    cmd->common.nsid = nsid;
    cmd->common.prp1 = mr->iova;
    cmd->common.prp2 = 0;
    cmd->cns         = nsid == 0 ? 1 : 0;

    evpl_vfio_ring_sq(device->adminq);

    while (device->adminq->cidcount > 0) {
        evpl_vfio_poll_queue(evpl, device->adminq);
    }
} /* evpl_vfio_identify */

static void
evpl_vfio_get_features(
    struct evpl_vfio_device *device,
    int                      feature,
    evpl_block_callback_t    callback,
    void                    *arg)
{
    int                             cid;
    struct nvme_admin_get_features *cmd;

    cid = evpl_vfio_alloc_cid(device->adminq, callback, arg);
    cmd = &device->adminq->sq[cid].get_features;

    memset(cmd, 0, sizeof(*cmd));
    cmd->common.opc  = NVME_ADMIN_GET_FEATURES;
    cmd->common.cid  = cid;
    cmd->common.nsid = 0;
    cmd->common.prp1 = 0;
    cmd->common.prp2 = 0;
    cmd->fid         = feature;

    evpl_vfio_ring_sq(device->adminq);
} /* evpl_nvme_get_features */

static void
evpl_vfio_identify_ctrl(
    struct evpl *evpl,
    int          status,
    void        *arg)
{
    struct evpl_vfio_identify_ctx *ctx = (struct evpl_vfio_identify_ctx *) arg;
    struct evpl_vfio_device       *dev = ctx->device;
    struct nvme_identify_ctlr     *identify;
    size_t                         model_len, serial_len;

    identify = (struct nvme_identify_ctlr *) ctx->mr->buffer;

    dev->max_xfer_bytes = 4096 << identify->mdts;

    memcpy(dev->model, identify->mn, sizeof(identify->mn));
    dev->model[sizeof(identify->mn)] = '\0';
    model_len                        = strlen(dev->model);
    while (model_len > 0 && dev->model[model_len - 1] == ' ') {
        dev->model[--model_len] = '\0';
    }

    memcpy(dev->serial, identify->sn, sizeof(identify->sn));
    dev->serial[sizeof(identify->sn)] = '\0';
    serial_len                        = strlen(dev->serial);

    while (serial_len > 0 && dev->serial[serial_len - 1] == ' ') {
        dev->serial[--serial_len] = '\0';
    }

    /* Record and report SGL capabilities */
    dev->sgls          = identify->sgls;
    dev->sgl_supported = (dev->sgls & 0x3) != 0;
    dev->sgl_unaligned = (dev->sgls & 0x3) == 0x1;

} /* evpl_vfio_identify_ctrl */

static void
evpl_vfio_identify_ns(
    struct evpl *evpl,
    int          status,
    void        *arg)
{
    struct evpl_vfio_identify_ctx *ctx = (struct evpl_vfio_identify_ctx *) arg;
    struct evpl_vfio_device       *dev = ctx->device;
    struct nvme_identify_ns       *nsid;

    nsid = (struct nvme_identify_ns *) ctx->mr->buffer;


    dev->num_sectors  = nsid->ncap;
    dev->sector_shift = nsid->lbaf[nsid->flbas & 0xF].lbads;
    dev->sector_size  = 1 << dev->sector_shift;
} /* evpl_vfio_identify_ns */

static void
evpl_vfio_get_max_queues(
    struct evpl *evpl,
    int          status,
    void        *arg)
{
    struct evpl_vfio_device       *device = (struct evpl_vfio_device *) arg;
    struct nvme_feature_num_queues nq;

    nq.val = status;

    device->max_queues = nq.nsq + 1;

    if (nq.ncq + 1 < device->max_queues) {
        device->max_queues = nq.ncq + 1;
    }
} /* evpl_vfio_get_max_queues */

static inline void
evpl_vfio_prepare_sgls(
    struct evpl_vfio_device *device,
    struct evpl_vfio_queue  *queue,
    uint32_t                 cid,
    struct nvme_command_rw  *cmd,
    const struct evpl_iovec *iov,
    int                      niov)
{
    struct nvme_sgl_desc *list;
    struct evpl_vfio_mr  *mr;
    uint64_t              addr, total_len = 0;
    int                   i;

    if (niov == 1) {
        mr = evpl_memory_framework_private(&iov[0], EVPL_FRAMEWORK_VFIO);

        cmd->common.psdt       = 1;
        cmd->common.sgl.addr   = mr->iova + (iov[0].data - mr->buffer);
        cmd->common.sgl.length = iov[0].length;
        memset(cmd->common.sgl.rsvd, 0, sizeof(cmd->common.sgl.rsvd));
        cmd->common.sgl.type = NVME_SGL_FMT_DATA_DESC;

        evpl_vfio_abort_if(!device->sgl_unaligned && (cmd->common.sgl.addr & 7),
                           "Device requires alignment and SGL address is not DWORD‑aligned");
        evpl_vfio_abort_if(!device->sgl_unaligned && (cmd->common.sgl.length & 7),
                           "Device requires alignment and SGL length is not DWORD‑aligned");


        total_len += iov[0].length;
    } else {

        evpl_vfio_abort_if(
            niov * sizeof(struct nvme_sgl_desc) > 4096,
            "Too many iovecs (%d) for one‑page SGL list", niov);

        list = (struct nvme_sgl_desc *) (queue->prplist->buffer + (cid << 12));

        for (i = 0; i < niov; ++i) {
            mr = evpl_memory_framework_private(&iov[i], EVPL_FRAMEWORK_VFIO);

            addr = mr->iova + (iov[i].data - mr->buffer);

            list[i].addr   = addr;
            list[i].length = iov[i].length;
            memset(list[i].rsvd, 0, sizeof(list[i].rsvd));
            list[i].type = NVME_SGL_FMT_DATA_DESC;

            evpl_vfio_abort_if(!device->sgl_unaligned && (addr & 7),
                               "Device requires alignment and SGL address is not DWORD‑aligned");
            evpl_vfio_abort_if(!device->sgl_unaligned && (iov[i].length & 7),
                               "Device requires alignment and SGL length is not DWORD‑aligned");

            total_len += iov[i].length;
        }

        cmd->common.psdt       = 1;
        cmd->common.sgl.addr   = queue->prplist->iova + (cid << 12);
        cmd->common.sgl.length = niov * sizeof(struct nvme_sgl_desc);
        memset(cmd->common.sgl.rsvd, 0, sizeof(cmd->common.sgl.rsvd));
        cmd->common.sgl.type = NVME_SGL_FMT_LAST_SEG_DESC;
    }

    evpl_vfio_abort_if(total_len > device->max_xfer_bytes, "NVMe I/O length %lu exceeds max_xfer_bytes %lu",
                       total_len, device->max_xfer_bytes);

    cmd->nlb = (total_len >> device->sector_shift) - 1;
} /* evpl_vfio_prepare_sgls */

static inline void
evpl_vfio_prepare_prplist(
    struct evpl_vfio_device *device,
    struct evpl_vfio_queue  *queue,
    uint32_t                 cid,
    struct nvme_command_rw  *cmd,
    const struct evpl_iovec *iov,
    int                      niov)
{
    struct evpl_vfio_mr *mr;
    uint64_t            *prpe, *prpc, prpv, end, total_len = 0;
    int                  i, j = 0;

    cmd->common.psdt = 0;
    cmd->common.prp1 = 0;
    cmd->common.prp2 = 0;

    prpe = (uint64_t *) (queue->prplist->buffer + (cid << 12));
    prpc = prpe;

    for (i = 0; i < niov; ++i) {

        total_len += iov[i].length;

        mr = evpl_memory_framework_private(&iov[i], EVPL_FRAMEWORK_VFIO);

        prpv = mr->iova + (iov[i].data - mr->buffer);
        end  = prpv + iov[i].length;

        evpl_vfio_abort_if((prpv & 4095) && j > 0, "PRP2+ is not page aligned");

        while (prpv < end) {
            if (j == 0) {
                cmd->common.prp1 = prpv;
            } else if (j == 1) {
                cmd->common.prp2 = prpv;
            } else if (j == 2) {
                *prpc = cmd->common.prp2;
                prpc++;
                cmd->common.prp2 = queue->prplist->iova + (cid << 12);

                *prpc = prpv;
                prpc++;

            } else {
                *prpc = prpv;
                prpc++;
            }

            j++;

            if (prpv & 4095) {
                prpv += 4096 - (prpv & 4095);
            } else {
                prpv += 4096;
            }
        }
    }

    evpl_vfio_abort_if(total_len > device->max_xfer_bytes, "NVMe I/O length %lu exceeds max_xfer_bytes %lu",
                       total_len, device->max_xfer_bytes);

    cmd->nlb = (total_len >> device->sector_shift) - 1;
} /* evpl_vfio_prepare_prplist */

static inline void
evpl_vfio_prepare_payload(
    struct evpl_vfio_device *device,
    struct evpl_vfio_queue  *queue,
    uint32_t                 cid,
    struct nvme_command_rw  *cmd,
    const struct evpl_iovec *iov,
    int                      niov)
{
    if (device->sgl_supported) {
        evpl_vfio_prepare_sgls(device, queue, cid, cmd, iov, niov);
    } else {
        evpl_vfio_prepare_prplist(device, queue, cid, cmd, iov, niov);
    }
} /* evpl_vfio_prepare_payload */

static void
evpl_vfio_read(
    struct evpl             *evpl,
    struct evpl_block_queue *bqueue,
    struct evpl_iovec       *iov,
    int                      niov,
    uint64_t                 offset,
    evpl_block_callback_t    callback,
    void                    *private_data)
{
    struct evpl_vfio_queue  *queue  = bqueue->private_data;
    struct evpl_vfio_device *device = queue->device;
    struct nvme_command_rw  *cmd;
    int                      cid;

    evpl_activity(evpl);

    cid = evpl_vfio_alloc_cid(queue, callback, private_data);

    cmd = &queue->sq[cid].rw;

    cmd->common.opc    = NVME_CMD_READ;
    cmd->common.fuse   = 0;
    cmd->common.rsvd   = 0;
    cmd->common.psdt   = 0;
    cmd->common.cid    = cid;
    cmd->common.cdw2_3 = 0;
    cmd->common.mptr   = 0;
    cmd->common.nsid   = 1;
    cmd->slba          = offset >> device->sector_shift;
    cmd->rsvd12        = 0;
    cmd->prinfo        = 0;
    cmd->fua           = 0;
    cmd->lr            = 0;
    cmd->dsm           = 0;
    cmd->rsvd13[0]     = 0;
    cmd->rsvd13[1]     = 0;
    cmd->rsvd13[2]     = 0;
    cmd->eilbrt        = 0;
    cmd->elbat         = 0;
    cmd->elbatm        = 0;

    evpl_vfio_prepare_payload(device, queue, cid, cmd, iov, niov);

    evpl_defer(evpl, &queue->ring_sq);
} /* evpl_vfio_read */

static void
evpl_vfio_write(
    struct evpl             *evpl,
    struct evpl_block_queue *bqueue,
    const struct evpl_iovec *iov,
    int                      niov,
    uint64_t                 offset,
    int                      sync,
    evpl_block_callback_t    callback,
    void                    *private_data)
{
    struct evpl_vfio_queue  *queue  = bqueue->private_data;
    struct evpl_vfio_device *device = queue->device;
    struct nvme_command_rw  *cmd;
    int                      cid;

    evpl_activity(evpl);


    cid = evpl_vfio_alloc_cid(queue, callback, private_data);

    cmd = &queue->sq[cid].rw;

    cmd->common.opc    = NVME_CMD_WRITE;
    cmd->common.fuse   = 0;
    cmd->common.rsvd   = 0;
    cmd->common.psdt   = 0;
    cmd->common.cid    = cid;
    cmd->common.cdw2_3 = 0;
    cmd->common.mptr   = 0;
    cmd->common.nsid   = 1;
    cmd->slba          = offset >> device->sector_shift;
    cmd->rsvd12        = 0;
    cmd->prinfo        = 0;
    cmd->fua           = !!sync;
    cmd->lr            = 0;
    cmd->dsm           = 0;
    cmd->rsvd13[0]     = 0;
    cmd->rsvd13[1]     = 0;
    cmd->rsvd13[2]     = 0;
    cmd->eilbrt        = 0;
    cmd->elbat         = 0;
    cmd->elbatm        = 0;

    evpl_vfio_prepare_payload(device, queue, cid, cmd, iov, niov);

    evpl_defer(evpl, &queue->ring_sq);

} /* evpl_vfio_write */

static void
evpl_vfio_flush(
    struct evpl             *evpl,
    struct evpl_block_queue *bqueue,
    evpl_block_callback_t    callback,
    void                    *private_data)
{
    struct evpl_vfio_queue *queue = bqueue->private_data;
    struct nvme_command_rw *cmd;
    int                     cid;

    evpl_activity(evpl);


    cid = evpl_vfio_alloc_cid(queue, callback, private_data);

    cmd = &queue->sq[cid].rw;

    cmd->common.opc    = NVME_CMD_FLUSH;
    cmd->common.fuse   = 0;
    cmd->common.rsvd   = 0;
    cmd->common.psdt   = 0;
    cmd->common.cid    = cid;
    cmd->common.cdw2_3 = 0;
    cmd->common.mptr   = 0;
    cmd->common.nsid   = 1;
    cmd->slba          = 0;
    cmd->rsvd12        = 0;
    cmd->prinfo        = 0;
    cmd->fua           = 0;
    cmd->lr            = 0;
    cmd->dsm           = 0;
    cmd->rsvd13[0]     = 0;
    cmd->rsvd13[1]     = 0;
    cmd->rsvd13[2]     = 0;
    cmd->eilbrt        = 0;
    cmd->elbat         = 0;
    cmd->elbatm        = 0;
    cmd->nlb           = 0;
    cmd->common.prp1   = 0;
    cmd->common.prp2   = 0;

    evpl_defer(evpl, &queue->ring_sq);
} /* evpl_vfio_flush */

static void
evpl_vfio_close_queue(
    struct evpl             *evpl,
    struct evpl_block_queue *bqueue)
{
    struct evpl_vfio_queue *queue = bqueue->private_data;

    evpl_vfio_queue_close(
        queue->device,
        queue);

    evpl_free(bqueue);
} /* evpl_vfio_close_queue */

static void
evpl_vfio_event_callback(
    struct evpl       *evpl,
    struct evpl_event *event)
{
    struct evpl_vfio_queue *queue = container_of(event, struct evpl_vfio_queue, event);
    uint64_t                value;
    ssize_t                 len;

    len = read(event->fd, &value, sizeof(value));

    if (len != sizeof(value)) {
        evpl_event_mark_unreadable(evpl, event);
        return;
    }

    evpl_vfio_poll_queue(evpl, queue);
} /* evpl_vfio_event_callback */

static void
evpl_vfio_defer_ring_sq(
    struct evpl *evpl,
    void        *private_data)
{
    struct evpl_vfio_queue *queue = private_data;

    evpl_vfio_ring_sq(queue);
} /* evpl_vfio_defer_ring_sq */

static void
evpl_vfio_poll_cq(
    struct evpl *evpl,
    void        *private_data)
{
    struct evpl_vfio_queue *queue = private_data;

    evpl_vfio_poll_queue(evpl, queue);
} /* evpl_vfio_poll_cq */

static struct evpl_block_queue *
evpl_vfio_open_queue(
    struct evpl              *evpl,
    struct evpl_block_device *bdev)
{
    struct evpl_vfio_device *device = bdev->private_data;
    struct evpl_block_queue *bqueue;
    struct evpl_vfio_queue  *queue;

    bqueue = evpl_zalloc(sizeof(*bqueue));

    queue = evpl_vfio_create_ioq(evpl, device, device->queue_size);

    bqueue->private_data = queue;
    bqueue->close_queue  = evpl_vfio_close_queue;
    bqueue->read         = evpl_vfio_read;
    bqueue->write        = evpl_vfio_write;
    bqueue->flush        = evpl_vfio_flush;

    evpl_add_event(evpl, &queue->event, queue->eventfd,
                   evpl_vfio_event_callback, NULL, NULL);

    evpl_event_read_interest(evpl, &queue->event);

    evpl_deferral_init(&queue->ring_sq, evpl_vfio_defer_ring_sq, queue);

    evpl_add_poll(evpl, NULL, NULL, evpl_vfio_poll_cq, queue);

    return bqueue;
} /* evpl_vfio_open_queue */

static void
evpl_vfio_close_device(struct evpl_block_device *bdev)
{
    struct evpl_vfio_device *dev = bdev->private_data;
    int                      i;

    evpl_vfio_queue_close(
        dev,
        dev->adminq);


    for (i = 0; i < dev->msixsize; ++i) {
        close(dev->eventfds[i]);
    }

    evpl_free(dev->eventfds);

    close(dev->fd);

    evpl_free(dev);
    evpl_free(bdev);
} /* evpl_vfio_close_device */


static struct evpl_block_device *
evpl_vfio_open_device(
    const char *uri,
    void       *private_data)
{
    struct evpl_vfio_shared      *vfio = private_data;
    struct evpl_block_device     *bdev;
    struct evpl_vfio_device      *dev;
    int                           rc;
    union nvme_controller_cap     cap;
    struct evpl_vfio_identify_ctx ctrl_id_ctx, ns_id_ctx;
    struct vfio_region_info       memory_region;
    uint8_t                       region_config[256];
    uint16_t                     *cmd;
    uint8_t                       u8;
    struct evpl_vfio_mr          *inquiry_mr;

    bdev = evpl_zalloc(sizeof(*bdev));

    dev = evpl_zalloc(sizeof(*dev));

    pthread_mutex_init(&dev->lock, NULL);

    dev->next_ioq_id = 1;

    bdev->private_data = dev;
    bdev->open_queue   = evpl_vfio_open_queue;
    bdev->close_device = evpl_vfio_close_device;

    dev->vfio = vfio;

    dev->fd = evpl_vfio_attach_device(vfio, uri);

    evpl_vfio_abort_if(dev->fd < 0, "Failed to open VFIO IOMMU NVMe device");

    dev->device_info.argsz = sizeof(dev->device_info);

    rc = ioctl(dev->fd, VFIO_DEVICE_GET_INFO, &dev->device_info);

    evpl_vfio_abort_if(rc < 0, "Failed to get NVMe device info");

    memory_region.argsz = sizeof(memory_region);
    memory_region.index = VFIO_PCI_CONFIG_REGION_INDEX;

    rc = ioctl(dev->fd, VFIO_DEVICE_GET_REGION_INFO, &memory_region);

    evpl_vfio_abort_if(rc < 0, "Failed to get VFIO region info");

    rc = pread(dev->fd, region_config, sizeof(region_config), memory_region.offset);

    evpl_vfio_abort_if(rc != sizeof(region_config), "Failed to read VFIO region config");

    cmd = (uint16_t *) (region_config + PCI_COMMAND);

    *cmd |= PCI_COMMAND_MASTER | PCI_COMMAND_MEMORY | PCI_COMMAND_INTX_DISABLE;

    rc = pwrite(dev->fd, cmd, sizeof(*cmd), memory_region.offset + PCI_COMMAND);

    evpl_vfio_abort_if(rc != sizeof(*cmd), "Failed to write VFIO region config");

    for (u8 = region_config[PCI_CAPABILITY_LIST] ; u8 ; u8 = region_config[u8 + 1]) {
        if (region_config[u8] == PCI_CAP_ID_MSIX) {
            uint16_t *msixflags = (uint16_t *) (region_config + u8 + PCI_MSIX_FLAGS);
            dev->msixsize = (*msixflags & PCI_MSIX_FLAGS_QSIZE) + 1;
        }
    }

    dev->reg = mmap(0, sizeof(*dev->reg), PROT_READ | PROT_WRITE, MAP_SHARED | MAP_LOCKED, dev->fd, 0);

    evpl_vfio_abort_if(dev->reg == NULL, "Failed to memory map NVMe controller registers");

    cap.value = dev->reg->cap.value;

    dev->timeout        = cap.to;
    dev->max_queue_size = cap.mqes + 1;
    dev->dbstride       = 1 << cap.dstrd;

    evpl_vfio_enable_msix(dev);

    evpl_vfio_create_adminq(dev, 512);

    inquiry_mr = evpl_vfio_alloc(dev->vfio, 4096);

    ctrl_id_ctx.device = dev;
    ctrl_id_ctx.nsid   = 0;
    ctrl_id_ctx.mr     = inquiry_mr;

    evpl_vfio_identify(NULL, dev, ctrl_id_ctx.mr, 0,
                       evpl_vfio_identify_ctrl, &ctrl_id_ctx);

    ns_id_ctx.device = dev;
    ns_id_ctx.nsid   = 1;
    ns_id_ctx.mr     = inquiry_mr;

    evpl_vfio_identify(NULL, dev, ns_id_ctx.mr, 1,
                       evpl_vfio_identify_ns, &ns_id_ctx);

    evpl_vfio_get_features(dev, NVME_FEATURE_NUM_QUEUES,
                           evpl_vfio_get_max_queues, dev);

    while (dev->adminq->cidcount > 0) {
        evpl_vfio_poll_queue(NULL, dev->adminq);
    }

    dev->queue_size = 1;

    while ((dev->queue_size << 1) <= dev->max_queue_size && dev->queue_size <= 1024) {
        dev->queue_size <<= 1;
    }

    while (dev->adminq->cidcount > 0) {
        evpl_vfio_poll_queue(NULL, dev->adminq);
    }

    bdev->size             = dev->num_sectors * dev->sector_size;
    bdev->max_request_size = dev->max_xfer_bytes;

    evpl_vfio_debug("NVMe controller %s [%s] SGLs=%d SGLa=%d max_queues=%d max_xfer_size=%d",
                    dev->model, dev->serial, dev->sgls, dev->sgl_unaligned,
                    dev->max_queues, dev->max_xfer_bytes);

    evpl_vfio_free(dev->vfio, inquiry_mr);

    return bdev;
} /* evpl_vfio_open_device */

struct evpl_framework      evpl_framework_vfio = {
    .id                = EVPL_FRAMEWORK_VFIO,
    .name              = "vfio",
    .init              = evpl_vfio_init,
    .create            = evpl_vfio_create,
    .destroy           = evpl_vfio_destroy,
    .cleanup           = evpl_vfio_cleanup,
    .register_memory   = evpl_vfio_register_memory,
    .unregister_memory = evpl_vfio_unregister_memory
};

struct evpl_block_protocol evpl_block_protocol_vfio = {
    .id          = EVPL_BLOCK_PROTOCOL_VFIO,
    .name        = "vfio",
    .framework   = &evpl_framework_vfio,
    .open_device = evpl_vfio_open_device,
};
