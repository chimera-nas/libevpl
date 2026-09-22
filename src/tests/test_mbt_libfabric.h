// SPDX-FileCopyrightText: 2026 Ben Jarvis
// SPDX-License-Identifier: LGPL-2.1-only

/* A real tcp-provider domain borrowed by the model adapter. Only wait-object
 * negotiation is interposed; traffic and the model's byte/callback oracle are
 * unchanged. Register cleanup before evpl_init to check that evpl returns the
 * domain with no live children and does not close caller-owned objects. */
#include <rdma/fabric.h>
#include <rdma/fi_domain.h>
#include <rdma/fi_eq.h>
#include "evpl/evpl_libfabric.h"

static struct fi_info      *mbt_fi_info;
static struct fid_fabric   *mbt_fabric;
static struct fid_domain   *mbt_domain;
static struct fi_ops_domain mbt_domain_ops, *mbt_real_domain_ops;
static struct fi_ops_fabric mbt_fabric_ops, *mbt_real_fabric_ops;
static int                  mbt_wait_mode;
static atomic_int           mbt_cqs, mbt_eqs;

static int
mbt_cq_open(
    struct fid_domain *domain,
    struct fi_cq_attr *attr,
    struct fid_cq    **cq,
    void              *context)
{
    if (attr->wait_obj != mbt_wait_mode) {
        return -FI_ENOSYS;
    }
    int rc = mbt_real_domain_ops->cq_open(domain, attr, cq, context);
    if (!rc) {
        atomic_fetch_add(&mbt_cqs, 1);
    }
    return rc;
} // mbt_cq_open

static int
mbt_eq_open(
    struct fid_fabric *fabric,
    struct fi_eq_attr *attr,
    struct fid_eq    **eq,
    void              *context)
{
    struct fi_eq_attr copy = *attr;

    if (mbt_wait_mode == FI_WAIT_NONE && attr->wait_obj == FI_WAIT_UNSPEC) {
        copy.wait_obj = FI_WAIT_NONE;
    } else if (attr->wait_obj != mbt_wait_mode) {
        return -FI_ENOSYS;
    }
    int               rc = mbt_real_fabric_ops->eq_open(fabric, &copy, eq, context);
    if (!rc) {
        atomic_fetch_add(&mbt_eqs, 1);
    }
    return rc;
} // mbt_eq_open

static void
mbt_fabric_close(void)
{
    evpl_test_abort_if(!atomic_load(&mbt_cqs) || !atomic_load(&mbt_eqs),
                       "model never opened queues in the requested wait mode");
    mbt_domain->ops = mbt_real_domain_ops;
    mbt_fabric->ops = mbt_real_fabric_ops;
    evpl_test_abort_if(fi_close(&mbt_domain->fid), "borrowed domain has live children");
    evpl_test_abort_if(fi_close(&mbt_fabric->fid), "borrowed fabric close failed");
    fi_freeinfo(mbt_fi_info);
} // mbt_fabric_close

static void
mbt_fabric_setup(struct evpl_global_config *config)
{
    const char *mode = getenv("EVPL_TEST_MBT_FABRIC_WAIT");

    if (!mode) {
        return;
    }
    evpl_test_abort_if(strcmp(mode, "fd") && strcmp(mode, "pollfd") && strcmp(mode, "none"),
                       "unknown MBT wait mode");
    mbt_wait_mode = !strcmp(mode, "fd") ? FI_WAIT_FD :
        !strcmp(mode, "pollfd") ? FI_WAIT_POLLFD : FI_WAIT_NONE;
    struct fi_info *hints = fi_allocinfo();
    evpl_test_abort_if(!hints, "fi_allocinfo failed");
    hints->ep_attr->type          = FI_EP_MSG;
    hints->caps                   = FI_MSG | FI_RMA;
    hints->addr_format            = FI_SOCKADDR_IN;
    hints->mode                   = FI_CONTEXT | FI_CONTEXT2;
    hints->domain_attr->mr_mode   = FI_MR_LOCAL | FI_MR_VIRT_ADDR | FI_MR_ALLOCATED | FI_MR_PROV_KEY;
    hints->domain_attr->threading = FI_THREAD_SAFE;
    hints->fabric_attr->prov_name = strdup("tcp");
    evpl_test_abort_if(fi_getinfo(FI_VERSION(1, 17), test_mbt_address(), NULL,
                                  FI_SOURCE, hints, &mbt_fi_info), "external provider lookup failed");
    fi_freeinfo(hints);
    evpl_test_abort_if(fi_fabric(mbt_fi_info->fabric_attr, &mbt_fabric, NULL), "fi_fabric failed");
    evpl_test_abort_if(fi_domain(mbt_fabric, mbt_fi_info, &mbt_domain, NULL), "fi_domain failed");
    mbt_real_domain_ops    = mbt_domain->ops;
    mbt_domain_ops         = *mbt_real_domain_ops;
    mbt_domain_ops.cq_open = mbt_cq_open;
    mbt_domain->ops        = &mbt_domain_ops;
    mbt_real_fabric_ops    = mbt_fabric->ops;
    mbt_fabric_ops         = *mbt_real_fabric_ops;
    mbt_fabric_ops.eq_open = mbt_eq_open;
    mbt_fabric->ops        = &mbt_fabric_ops;
    atexit(mbt_fabric_close);
    evpl_global_config_set_libfabric_external_domain(config, mbt_fabric, mbt_domain, mbt_fi_info);
} // mbt_fabric_setup
