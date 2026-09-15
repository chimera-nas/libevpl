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