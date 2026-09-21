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
The build enables libfabric and SPDK, but the current model replays use native
backends; their inclusion does not imply those integrations are exercised by MBT.
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
bash scripts/run_mbt_coverage.sh /build /tmp/mbt-report /tmp/pr.diff
```

The script requires all five replay families, clears previous profiles and fails
on test failures or missing coverage data. CI uses the PR merge tree and its first
parent for the diff, so line numbers match the code actually measured.

A separate `workflow_run` workflow publishes one sticky PR comment, including for
forks. The build has a read-only token; the commenter never executes PR code and
checks that the report still matches the open PR head. The commenter must first
land on the default branch, so the PR introducing it has a job summary/artifact
but will not yet receive an automatic comment.
