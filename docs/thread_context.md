<!--
SPDX-FileCopyrightText: 2025 Ben Jarvis

SPDX-License-Identifier: Unlicense
-->

---
title: Thread Context
layout: default
nav_order: 2
parent: API
permalink: /api/thread-context
---

Each thread that will utilize libevpl must first create an evpl context:

```c
struct evpl *evpl = evpl_create();
```

The first created context will automatically initialize the library if not already initialized explicitly.

The evpl thread context is not thread-safe and therefore must be created, used, and destroyed within the same thread.

The context can be destroyed as follows:

```c
evpl_destroy(evpl);
```


