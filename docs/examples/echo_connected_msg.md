---
title: Echo Server (Message)
layout: default
parent: Examples
nav_order: 2
permalink: /examples/echo-message
---

# Echo Server with Message Semantics

This example demonstrates an echo server using message semantics with a segmentation callback to frame messages with 4-byte length headers.

## Source Code

{% highlight c %}
{% include_relative echo_connected_msg.c %}
{% endhighlight %}

## See Also

- [Event Loop API](/api/core) - Event loop management
- [Binds API](/api/bind) - Network connections and I/O
- [Echo Server (Stream)](/examples/echo-stream) - Stream-based alternative
