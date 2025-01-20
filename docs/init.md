---
title: Library Initialization
layout: default
nav_order: 1
parent: API
permalink: /api/init
---

The libevpl library will automatically initialize itself on first use.   Explicit initialization is required only if you wish to precisely control when it happens or if you wish to override default global configuration settings.

First, create an evpl_config instance:

```c
struct evpl_config *config = evpl_config_init();
```

Then set any desired configuration settings:

```c
evpl_config_set_rdmacm_datagram_size_override(config, 1024);
```

The library may then be initialized with automatic on-exit cleanup:

```c
evpl_init_auto(config);
```

or with explicit cleanup:

```c
evpl_init(config);
// the rest of your code
evpl_cleanup();
exit(0);
```
