---
title: Echo Server (Stream)
layout: default
parent: Examples
nav_order: 1
permalink: /examples/echo-stream
---

# Echo Server with Stream Semantics

This example demonstrates a simple echo server and client using stream semantics where data is received in arbitrary chunks.

## Source Code

{% highlight c %}
{% include_relative echo_stream.c %}
{% endhighlight %}

## See Also

- [Event Loop API](/api/core) - Event loop management
- [Binds API](/api/bind) - Network connections and I/O
- [Echo Server (Message)](/examples/echo-message) - Message-based alternative
