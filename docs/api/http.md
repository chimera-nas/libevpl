---
title: HTTP
layout: default
parent: Protocols 
nav_order: 1
permalink: /api/protocols/http
---

# HTTP

Provides high-performance HTTP/1.1 server functionality built on libevpl.

The libevpl HTTP server is very minimalist in its current form, but it allows HTTP to be transmitted
over arbitrary supported protocols possibly with zero-copy transfer.

## Overview

libevpl's HTTP support provides:

- **HTTP/1.1 server** - Handle GET, POST, PUT, DELETE, HEAD requests
- **Streaming** - Support for chunked transfer encoding and content-length
- **Zero-copy** - Use iovecs for efficient data transfer
- **Header manipulation** - Add custom request/response headers
- **Multiple protocols** - Run HTTP over TCP, XLIO, or RDMA

**Supported methods:** GET, HEAD, POST, PUT, DELETE

## Types

### `struct evpl_http_agent`

Opaque structure representing an HTTP agent (per event loop).

### `struct evpl_http_server`

Opaque structure representing an HTTP server attached to a listener.

### `struct evpl_http_request`

Opaque structure representing an individual HTTP request/response.

### `enum evpl_http_notify_type`

HTTP event notifications:

| Type | Description |
|------|-------------|
| `EVPL_HTTP_NOTIFY_RECEIVE_DATA` | Request body data available |
| `EVPL_HTTP_NOTIFY_RECEIVE_COMPLETE` | Request fully received |
| `EVPL_HTTP_NOTIFY_WANT_DATA` | Server ready for more response data |
| `EVPL_HTTP_NOTIFY_RESPONSE_COMPLETE` | Response fully sent |

### `enum evpl_http_request_type`

HTTP request methods:

- `EVPL_HTTP_REQUEST_TYPE_GET`
- `EVPL_HTTP_REQUEST_TYPE_HEAD`
- `EVPL_HTTP_REQUEST_TYPE_POST`
- `EVPL_HTTP_REQUEST_TYPE_PUT`
- `EVPL_HTTP_REQUEST_TYPE_DELETE`
- `EVPL_HTTP_REQUEST_TYPE_UNKNOWN`

### Callback Types

#### `evpl_http_notify_callback_t`

```c
typedef void (*evpl_http_notify_callback_t)(
    struct evpl                *evpl,
    struct evpl_http_agent     *agent,
    struct evpl_http_request   *request,
    enum evpl_http_notify_type  notify_type,
    enum evpl_http_request_type request_type,
    const char                 *uri,
    void                       *notify_data,
    void                       *private_data);
```

Callback invoked for HTTP events on a specific request.

**Parameters:**
- `evpl` - Event loop
- `agent` - HTTP agent
- `request` - HTTP request
- `notify_type` - Type of notification
- `request_type` - HTTP method (GET, POST, etc.)
- `uri` - Request URI
- `notify_data` - Request-specific data (from dispatch callback)
- `private_data` - User context (from dispatch callback)

#### `evpl_http_dispatch_callback_t`

```c
typedef void (*evpl_http_dispatch_callback_t)(
    struct evpl                 *evpl,
    struct evpl_http_agent      *agent,
    struct evpl_http_request    *request,
    evpl_http_notify_callback_t *notify_callback,
    void                       **notify_data,
    void                        *private_data);
```

Callback invoked when a new HTTP request arrives (routing/dispatch).

**Parameters:**
- `evpl` - Event loop
- `agent` - HTTP agent
- `request` - New HTTP request
- `notify_callback` - [OUT] Set notification callback for this request
- `notify_data` - [OUT] Set request-specific context
- `private_data` - Server context

## Functions

### Agent Management

#### `evpl_http_init`

```c
struct evpl_http_agent *evpl_http_init(struct evpl *evpl);
```

Create an HTTP agent for an event loop.

**Parameters:**
- `evpl` - Event loop

**Returns:** HTTP agent, or `NULL` on failure

**Note:** One agent per event loop.

---

#### `evpl_http_destroy`

```c
void evpl_http_destroy(struct evpl_http_agent *agent);
```

Destroy an HTTP agent. All servers must be detached first.

**Parameters:**
- `agent` - Agent to destroy

---

### Server Management

#### `evpl_http_attach`

```c
struct evpl_http_server *evpl_http_attach(
    struct evpl_http_agent       *agent,
    struct evpl_listener         *listener,
    evpl_http_dispatch_callback_t dispatch_callback,
    void                         *private_data);
```

Attach an HTTP server to a listener.

**Parameters:**
- `agent` - HTTP agent
- `listener` - Network listener
- `dispatch_callback` - Request dispatch callback
- `private_data` - Server context

**Returns:** HTTP server handle, or `NULL` on failure

---

#### `evpl_http_server_destroy`

```c
void evpl_http_server_destroy(
    struct evpl_http_agent  *agent,
    struct evpl_http_server *server);
```

Detach and destroy an HTTP server.

**Parameters:**
- `agent` - HTTP agent
- `server` - Server to destroy

---

### Request Information

#### `evpl_http_request_type`

```c
enum evpl_http_request_type evpl_http_request_type(
    struct evpl_http_request *request);
```

Get the HTTP method of a request.

**Returns:** Request type enum

---

#### `evpl_http_request_type_to_string`

```c
const char *evpl_http_request_type_to_string(
    struct evpl_http_request *request);
```

Get the HTTP method as a string.

**Returns:** Method string ("GET", "POST", etc.)

---

#### `evpl_http_request_url`

```c
const char *evpl_http_request_url(
    struct evpl_http_request *request,
    int                      *len);
```

Get the request URI.

**Parameters:**
- `request` - HTTP request
- `len` - [OUT] URI length (optional, can be `NULL`)

**Returns:** URI string

---

#### `evpl_http_request_header`

```c
const char *evpl_http_request_header(
    struct evpl_http_request *request,
    const char               *name);
```

Get a request header value.

**Parameters:**
- `request` - HTTP request
- `name` - Header name (case-insensitive)

**Returns:** Header value, or `NULL` if not present

---

### Request Body

#### `evpl_http_request_get_data_avail`

```c
uint64_t evpl_http_request_get_data_avail(
    struct evpl_http_request *request);
```

Get the number of bytes available to read from request body.

**Returns:** Available bytes

---

#### `evpl_http_request_get_datav`

```c
int evpl_http_request_get_datav(
    struct evpl              *evpl,
    struct evpl_http_request *request,
    struct evpl_iovec        *iov,
    int                       length);
```

Read request body data into iovecs.

**Parameters:**
- `evpl` - Event loop
- `request` - HTTP request
- `iov` - [OUT] Iovec to receive data
- `length` - Maximum bytes to read

**Returns:** Number of bytes read

---

### Response Headers

#### `evpl_http_request_add_header`

```c
void evpl_http_request_add_header(
    struct evpl_http_request *request,
    const char               *name,
    const char               *value);
```

Add a response header.

**Parameters:**
- `request` - HTTP request
- `name` - Header name
- `value` - Header value

---

### Response Body

#### `evpl_http_server_set_response_length`

```c
void evpl_http_server_set_response_length(
    struct evpl_http_request *request,
    uint64_t                  content_length);
```

Set the response Content-Length.

**Parameters:**
- `request` - HTTP request
- `content_length` - Response body size in bytes

**Note:** Call before sending data.

---

#### `evpl_http_server_set_response_chunked`

```c
void evpl_http_server_set_response_chunked(
    struct evpl_http_request *request);
```

Enable chunked transfer encoding for the response.

**Parameters:**
- `request` - HTTP request

**Use case:** When response size is not known in advance.

---

#### `evpl_http_request_add_datav`

```c
void evpl_http_request_add_datav(
    struct evpl_http_request *request,
    struct evpl_iovec        *iov,
    int                       niov);
```

Add response body data.

**Parameters:**
- `request` - HTTP request
- `iov` - Iovecs containing response data
- `niov` - Number of iovecs

---

#### `evpl_http_server_dispatch_default`

```c
void evpl_http_server_dispatch_default(
    struct evpl_http_request *request,
    int                       status);
```

Send a default response with a status code.

**Parameters:**
- `request` - HTTP request
- `status` - HTTP status code (200, 404, 500, etc.)

**Use case:** Quick responses for errors or simple status pages.

---


## See Also

- [Binds & Connections API](/api/binds) - Underlying network I/O
- [Memory API](/api/memory) - Buffer management
- [Threading API](/api/threading) - Multi-threaded servers
- [Examples](/examples) - Complete HTTP server examples (coming soon)
