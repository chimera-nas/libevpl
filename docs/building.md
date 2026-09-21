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

With epoll and select available this registers 48 MBT tests (20 existing and 28
additional). The `mbt_libfabric` and `mbt_spdk` labels select the added backend
cases; combined cases carry both labels. Registration follows compiled features,
so builds without either dependency keep their native coverage.

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
has no native spin grace, and libfabric reports its own I/O activity. Backend
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
CI requires both backends. This is an execution guard, not a percentage target.
The script defaults to two CTest worker slots; set `CTEST_PARALLEL_LEVEL` to
override this on a dedicated runner. CI uses the PR merge tree and its first
parent for the diff, so line numbers match the code actually measured.

A separate `workflow_run` workflow publishes one sticky PR comment, including for
forks. The build has a read-only token; the commenter never executes PR code and
checks that the report still matches the open PR head. The commenter must first
land on the default branch, so the PR introducing it has a job summary/artifact
but will not yet receive an automatic comment.
