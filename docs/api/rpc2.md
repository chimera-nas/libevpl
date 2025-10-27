---
title: ONC RPC2
layout: default
parent: Protocols 
nav_order: 2
permalink: /api/protocols/rpc2
---

# RPC2

Provides ONC RPC (Open Network Computing Remote Procedure Call) support, primarily designed for NFS (Network File System) implementations.

## Overview

ONC RPC (also known as Sun RPC or RPC2) is the foundation for NFS and other distributed services. libevpl's RPC2 support provides:

- **ONC RPC server** - Handle RPC requests and replies
- **XDR encoding** - External Data Representation for platform-independent serialization
- **Program registration** - Register RPC programs with procedures
- **Multi-protocol** - Support TCP, UDP, and RDMA transports
- **RDMA optimization** - RPC-over-RDMA with read/write chunks for zero-copy
- **Multi-threaded** - Thread pool support for scalability

**Use case:** Building high-performance NFS servers and other RPC-based services.

## Types

### Core Types

#### `struct evpl_rpc2_server`

Opaque structure representing an RPC2 server (global, shared across threads).

#### `struct evpl_rpc2_thread`

Opaque structure representing an RPC2 thread context (per event loop).

#### `struct evpl_rpc2_request`

Opaque structure representing an individual RPC request.

#### `struct evpl_rpc2_conn`

Structure representing an RPC connection:

```c
struct evpl_rpc2_conn {
    enum evpl_protocol_id protocol;        // Transport protocol
    struct evpl_rpc2_thread *thread;       // Thread handling this connection
    struct evpl_rpc2_server *server;       // Server instance
    struct evpl_rpc2_msg    *recv_msg;     // Current receive message
    uint32_t                 next_xid;     // Next transaction ID
    void                    *private_data; // User context
};
```

### Program Definition

#### `struct evpl_rpc2_program`

Structure defining an RPC program:

```c
struct evpl_rpc2_program {
    uint32_t  program;        // RPC program number
    uint32_t  version;        // Program version
    uint32_t  maxproc;        // Maximum procedure number
    uint32_t  reserve;        // Reserved

    struct prometheus_histogram_series **metrics;  // Metrics (optional)
    const char                         **procs;    // Procedure names
    void                                *program_data;  // Program context

    // Dispatch callbacks
    int (*call_dispatch)(struct evpl *evpl,
                        struct evpl_rpc2_conn *conn,
                        struct evpl_rpc2_msg *msg,
                        xdr_iovec *iov, int niov, int length,
                        void *private_data);

    int (*reply_dispatch)(struct evpl *evpl,
                         struct evpl_rpc2_msg *msg,
                         xdr_iovec *iov, int niov, int length);
};
```

#### `struct evpl_rpc2_msg`

Structure representing an RPC message (internal details):

```c
struct evpl_rpc2_msg {
    uint32_t              xid;              // Transaction ID
    uint32_t              proc;             // Procedure number
    uint32_t              rdma;             // RDMA enabled
    uint32_t              rdma_credits;     // RDMA credits
    uint32_t              request_length;   // Request size
    uint32_t              reply_length;     // Reply size
    struct evpl_iovec    *req_iov;          // Request buffers
    struct evpl_iovec    *reply_iov;        // Reply buffers
    int                   req_niov;         // Number of request buffers
    int                   reply_niov;       // Number of reply buffers
    struct evpl_bind     *bind;             // Connection
    struct evpl_rpc2_conn *conn;            // RPC connection
    // ... additional internal fields
};
```

### Callback Types

#### `evpl_rpc2_dispatch_callback_t`

```c
typedef void (*evpl_rpc2_dispatch_callback_t)(
    struct evpl_rpc2_thread  *thread,
    struct evpl_rpc2_request *request,
    void                     *private_data);
```

Callback for dispatching RPC requests (currently not exposed in public API).

## Functions

### Server Management

#### `evpl_rpc2_init`

```c
struct evpl_rpc2_server *evpl_rpc2_init(
    struct evpl_rpc2_program **programs,
    int                        nprograms);
```

Initialize an RPC2 server with a set of programs.

**Parameters:**
- `programs` - Array of RPC program pointers
- `nprograms` - Number of programs

**Returns:** RPC2 server, or `NULL` on failure

---

#### `evpl_rpc2_start`

```c
void evpl_rpc2_start(
    struct evpl_rpc2_server *server,
    int                      protocol,
    struct evpl_endpoint    *endpoint);
```

Start listening for RPC requests on an endpoint.

**Parameters:**
- `server` - RPC2 server
- `protocol` - Transport protocol (TCP, UDP, RDMA)
- `endpoint` - Network endpoint to bind

---

#### `evpl_rpc2_attach`

```c
struct evpl_rpc2_thread *evpl_rpc2_attach(
    struct evpl             *evpl,
    struct evpl_rpc2_server *server,
    void                    *private_data);
```

Attach an RPC2 server to an event loop (create thread context).

**Parameters:**
- `evpl` - Event loop
- `server` - RPC2 server
- `private_data` - Thread-specific context

**Returns:** RPC2 thread handle

---

#### `evpl_rpc2_detach`

```c
void evpl_rpc2_detach(struct evpl_rpc2_thread *thread);
```

Detach an RPC2 thread from an event loop.

**Parameters:**
- `thread` - RPC2 thread to detach

---

#### `evpl_rpc2_stop`

```c
void evpl_rpc2_stop(struct evpl_rpc2_server *server);
```

Stop an RPC2 server (stop accepting new connections).

**Parameters:**
- `server` - RPC2 server to stop

---

#### `evpl_rpc2_destroy`

```c
void evpl_rpc2_destroy(struct evpl_rpc2_server *server);
```

Destroy an RPC2 server and free resources.

**Parameters:**
- `server` - RPC2 server to destroy

**Note:** Must detach all threads and stop the server first.

---

## Protocol Support

| Transport | Typical Use | Performance |
|-----------|------------|-------------|
| **TCP** | Standard NFS | Good latency, reliable |
| **UDP** | Legacy NFS v2/v3 | Lower latency, lossy |
| **RDMA RC** | High-performance NFS | Ultra-low latency, zero-copy |

## See Also

- [Threading API](/api/threading) - Multi-threaded RPC servers
- [RDMA API](/api/rdma) - RPC-over-RDMA optimization
- [Memory API](/api/memory) - Zero-copy buffer management
- [Architecture](/architecture) - Understanding RPC protocol module
- **RFC 5531** - RPC: Remote Procedure Call Protocol Specification Version 2
- **RFC 5666** - Remote Direct Memory Access Transport for RPC
- **RFC 1813** - NFS Version 3 Protocol Specification
