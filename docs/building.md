---
title: Building
layout: default
nav_order: 5
has_children: true
permalink: /build
---

# Building

For native MSVC builds on x64 or ARM64, see [Windows support](windows.md).

There are no packages for libevpl in upstream linux distributions yet. 

For now, there are a set of Dockerfiles in the project root that illustrate the required build dependencies for each distribution.

## Ubuntu 22.04

{% highlight dockerfile %}
{% include_relative Dockerfile.ubuntu22.04 %}
{% endhighlight %}

## Ubuntu 24.04

{% highlight dockerfile %}
{% include_relative Dockerfile.ubuntu24.04 %}
{% endhighlight %}

## Ubuntu 25.10

{% highlight dockerfile %}
{% include_relative Dockerfile.ubuntu25.10 %}
{% endhighlight %}

## Rocky Linux 9

{% highlight dockerfile %}
{% include_relative Dockerfile.rocky9 %}
{% endhighlight %}

## Rocky Linux 10

{% highlight dockerfile %}
{% include_relative Dockerfile.rocky10 %}
{% endhighlight %}

## Model-based test coverage

Pull requests run an additional Clang `Coverage` build in the Linux devcontainer.
It reuses the generated Core, HTTP and RPC2 conformance corpus and runs the C
trace replays labeled `mbt`. The separate `quint` label checks the specifications
themselves; it does not execute libevpl C code.

The job summary and `mbt-coverage` artifact contain:

* Function, line and branch coverage grouped by library component.
* Coverage of added or modified executable lines, with links to uncovered lines
  in the tested merge commit.
* The LLVM JSON summary, changed-file LCOV data, selected test list and JUnit results.

The report counts first-party library sources, excluding tests, dependencies and
build-generated files. Compiled but unexecuted library code remains in the totals.
The Linux coverage build enables libfabric and SPDK and runs this matrix in
addition to the existing native replays:

| Model replay | Native event loops | SPDK polling | SPDK interrupt |
|---|---|---|---|
| Core API programs | Existing transports/block backends; libfabric MSG streams and RDM datagrams | SPDK TCP or libfabric MSG/RDM with malloc bdev, plus existing inproc/Unix/UDP transports | — |
| HTTP server and client | Existing socket TCP cases | Socket TCP and SPDK TCP | Socket TCP and SPDK TCP |
| RPC2 server/value cases | Existing transports; libfabric MSG streams and messages | Socket TCP, SPDK TCP, both libfabric MSG modes | Same as polling |
| RPC2 client wire cases | Existing socket TCP cases | Socket TCP and SPDK TCP | Socket TCP and SPDK TCP |

With epoll and select available CI registers 44 MBT replays (16 existing and
28 additional); builds with MIT Kerberos add four authentication replays.
The `mbt_libfabric` and `mbt_spdk` labels select the added backend
cases; combined cases carry both labels. Registration follows compiled features,
so builds without either dependency keep their native coverage.

CI also configures `EVPL_RDMA_TEST_IP=192.0.2.1`, adding six `mbt_rdma`
replays: core RC streams/UD datagrams and RPC2 RC streams/messages, each with
epoll and select. They run in a privileged container inside a KVM guest with
Soft-RoCE (`rdma_rxe`), sharing the guest's network namespace and RDMA devices.
The ordinary container runs the other 44 replays. The guest also runs the
existing RDMA integration tests plus read/write, receive-error and ring-growth
regressions, but their profiles
do not enter the model-only report.

The core corpus includes separate UD traces with scalar and vector sends up to
the guest's 4096-byte RDMA MTU; the existing UDP traces retain their 8 KiB
payloads. RC receives are sized for the model's largest 128 KiB send. Native
replays retain their smaller buffers and scatter/gather coverage.

The guest runs the **same container image and compiled binaries**. Its model
profiles live in a separate directory so guest PIDs cannot collide with host
PIDs. LLVM merges both batches before calculating function, line, branch and
changed-line coverage; percentages and file denominators are never added.
CI requires the six guest replays and independently checks that guest model
profiles executed the RDMA backend before publishing a combined report.

`scripts/run_rdma_vm.sh` requires a Linux x86-64 host with working `/dev/kvm`,
Docker and passwordless sudo. It downloads a checksum-verified Ubuntu cloud
image, installs a generic guest kernel and Docker, then boots that kernel and
verifies RDMA CM with `rping`. The guest and temporary disk are removed on exit;
its serial log and JUnit results are retained in the coverage artifact. The
devcontainer uses rdma-core 65.0 because the older RXE provider in Ubuntu 24.04
has upstream-fixed extended-CQ polling and inline/SG-list length bugs.
The workflow's `platform=mbt` dispatch runs just corpus generation and coverage for
development. KVM is required: the lane fails rather than silently skipping RDMA
or falling back to CPU emulation.

SPDK replays attach evpl contexts to manually driven SPDK threads and progress
through `spdk_thread_poll`; listener/service threads run on the test reactor pool.
CTest reserves two worker slots per SPDK replay for the driver and reactors.
They need no hugepages or storage hardware: block programs use a malloc bdev.
Libfabric uses the software TCP provider (TCP/RxM for RDM), so these runs exercise
integration, framing, completion and teardown paths, not hardware RDMA behavior.
RPC2's raw malformed-wire phase applies only to socket/SPDK TCP, while its
libfabric message cases exercise RPC-over-RDMA chunks through the software provider.

The core model advances virtual time and therefore runs SPDK in polling mode.
Programs containing `OpAddPoll` remain in the native matrix: their oracle assumes
native spin grace and activity reported only by the modeled application. SPDK
has no native spin grace, and RDMA/libfabric report their own I/O activity. Backend
core runs report these omissions explicitly and retain every assertion in the
other programs. HTTP and RPC2 use real time and cover both SPDK modes.

Platform-specific or disabled code absent from the coverage mapping is reported
as **not measured**. Lines without executable coverage mappings do not enter the
changed-line denominator. Deletions do not count. These are code coverage metrics,
not measurements of model state or transition coverage, and do not impose a
minimum coverage threshold.

To reproduce the MBT-only measurement in a Linux devcontainer with Quint installed:

```sh
make coverage CTEST_ARGS_COVERAGE="-L mbt --output-on-failure --no-tests=error"
```

For the CI report, configure and build with `-DCMAKE_BUILD_TYPE=Coverage` and
`-DCMAKE_C_COMPILER=clang`, then run from the source root (use absolute paths):

```sh
git -c core.quotePath=false diff --no-renames -U0 origin/main...HEAD > /tmp/pr.diff
bash scripts/run_mbt_coverage.sh /build /tmp/mbt-report /tmp/pr.diff libfabric spdk
```

The script requires all five replay families, clears previous profiles and fails
on test failures or missing coverage data. Optional trailing backend names require
their matrix entries, including combined libfabric/SPDK cases when both are named,
and nonzero executed lines in libfabric, the SPDK core, TCP and block integration.
CI requires both backends plus the guest RDMA batch. It uses
`MBT_COVERAGE_PHASE=run` for the ordinary batch, runs `scripts/run_rdma_vm.sh`,
and then uses `MBT_COVERAGE_PHASE=report` with the additional `rdma` requirement
to export the merged report. This is an execution guard, not a percentage target.
The script defaults to two CTest worker slots; set `CTEST_PARALLEL_LEVEL` to
override this on a dedicated runner. CI uses the PR merge tree and its first
parent for the diff, so line numbers match the code actually measured.

A separate `workflow_run` workflow publishes one sticky PR comment, including for
forks. The build has a read-only token; the commenter never executes PR code and
checks that the report still matches the open PR head. The commenter must first
land on the default branch, so the PR introducing it has a job summary/artifact
but will not yet receive an automatic comment.
