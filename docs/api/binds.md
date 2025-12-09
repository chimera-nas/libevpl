---
title: Binds
layout: default
parent: Core
nav_order: 4
permalink: /api/binds
---

# Binds & Connections

Provides functions for creating network connections, binding to addresses, listening for incoming connections, and performing I/O operations.

## Types

### `struct evpl_bind`

Opaque structure representing a network connection or socket binding. This is the primary abstraction for network I/O.

### `struct evpl_listener`

Opaque structure representing a server that accepts incoming connections.

### `struct evpl_listener_binding`

Opaque structure representing the attachment of a listener to a specific thread.  Multiple threads may be attached to the same listener to facilitate distribution of incoming connections to threads.

### `struct evpl_notify`

Structure passed to notify callbacks containing event information:

```c
struct evpl_notify {
    unsigned int notify_type;        // Type of notification
    int          notify_status;      // Status code (0 = success)
    union {
        struct {                     // For EVPL_NOTIFY_RECV_MSG
            struct evpl_iovec   *iovec;
            unsigned int         niov;
            unsigned int         length;
            struct evpl_address *addr;
        } recv_msg;
        struct {                     // For EVPL_NOTIFY_SENT
            unsigned long bytes;
            unsigned long msgs;
        } sent;
    };
};
```

**Notification types:**
- `EVPL_NOTIFY_CONNECTED` - Connection established
- `EVPL_NOTIFY_DISCONNECTED` - Connection closed or failed
- `EVPL_NOTIFY_RECV_DATA` - Stream data available to read
- `EVPL_NOTIFY_RECV_MSG` - Datagram message received
- `EVPL_NOTIFY_SENT` - Send operation completed, not emitted unless explicitly requested


## Protocol Queries

### `evpl_protocol_lookup`

```c
int evpl_protocol_lookup(enum evpl_protocol_id *id, const char *name);
```

Look up a protocol ID by name.

**Parameters:**
- `id` - Output: protocol ID
- `name` - Protocol name string

**Returns:** 0 on success, -1 if protocol not found

**Supported names:**
- `"STREAM_SOCKET_TCP"` → `EVPL_STREAM_SOCKET_TCP`
- `"DATAGRAM_SOCKET_UDP"` → `EVPL_DATAGRAM_SOCKET_UDP`
- `"STREAM_XLIO_TCP"` → `EVPL_STREAM_XLIO_TCP`
- `"STREAM_RDMACM_RC"` → `EVPL_STREAM_RDMACM_RC`
- `"DATAGRAM_RDMACM_RC"` → `EVPL_DATAGRAM_RDMACM_RC`
- `"DATAGRAM_RDMACM_UD"` → `EVPL_DATAGRAM_RDMACM_UD`

---

### `evpl_protocol_is_stream`

```c
int evpl_protocol_is_stream(enum evpl_protocol_id protocol);
```

Check if a protocol is stream-based (vs datagram-based).

**Parameters:**
- `protocol` - Protocol to check

**Returns:** 1 if stream protocol, 0 if datagram protocol

---

## Callback Types


### `evpl_protocol_is_stream`

```c
int evpl_protocol_is_stream(enum evpl_protocol_id protocol);
```

Check if a protocol is stream-based (vs datagram-based).

**Parameters:**
- `protocol` - Protocol to check

**Returns:** 1 if stream protocol, 0 if datagram protocol

---



### `evpl_protocol_is_stream`

```c
int evpl_protocol_is_stream(enum evpl_protocol_id protocol);
```

Check if a protocol is stream-based (vs datagram-based).

**Parameters:**
- `protocol` - Protocol to check

**Returns:** 1 if stream protocol, 0 if datagram protocol

---


### `evpl_notify_callback_t`

```c
typedef void (*evpl_notify_callback_t)(
    struct evpl        *evpl,
    struct evpl_bind   *bind,
    struct evpl_notify *notify,
    void               *private_data);
```

Callback invoked when I/O events occur on a bind.

**Parameters:**
- `evpl` - Event loop
- `bind` - Connection that generated the event
- `notify` - Event details
- `private_data` - User-provided context

### `evpl_segment_callback_t`

```c
typedef int (*evpl_segment_callback_t)(
    struct evpl      *evpl,
    struct evpl_bind *bind,
    void             *private_data);
```

Callback that must be provided when using a stream protocol as a datagram protocol.  The callback should peek at the available received data, parse the next protocol-specific header that determines the length of the next message, and then return that length inclusive of the header.  This allows libevpl to segment the stream into messages as intended by the protocol.   It is not necessary to wait for a whole message to be received before returning its length.   If there is not enough data available to determine the length of the next message, for instance if only a fragment of the next header has been received, the callback should return zero.  If the callback determines that something illegal has been received, such as invalid header, it can return -1 and the connection will be closed.

**Parameters:**
- `evpl` - Event loop
- `bind` - Connection
- `private_data` - User-provided context

**Returns:** Desired receive segment size, 0 if more data required to find out, -1 if connection should be closed

### `evpl_attach_callback_t`

```c
typedef void (*evpl_attach_callback_t)(
    struct evpl             *evpl,
    struct evpl_bind        *bind,
    evpl_notify_callback_t  *notify_callback,
    evpl_segment_callback_t *segment_callback,
    void                   **conn_private_data,
    void                    *private_data);
```

Callback invoked when a listener accepts a new connection.

**Parameters:**
- `evpl` - Event loop
- `bind` - New connection
- `notify_callback` - [OUT] Set the notify callback for this connection
- `segment_callback` - [OUT] Set the segment callback (required only for stream protocols used as datagram protocols)
- `conn_private_data` - [OUT] Set private data for this connection
- `private_data` - Thread private data that was provided to evpl_listener_attach()

## Listener Functions

### `evpl_listener_create`

```c
struct evpl_listener *evpl_listener_create(void);
```

Create a listener that can accept incoming connections.  One or more threads must be attached to the listener to receive the incoming connections.

A listener can listen on one or more ports with potentially different protocols.

**Returns:** Listener handle, or `NULL` on failure

### `evpl_listener_destroy`

```c
void evpl_listener_destroy(struct evpl_listener *listener);
```

Destroy a listener. Must be detached from all event loops first.

**Parameters:**
- `listener` - Listener to destroy

### `evpl_listen`

```c
void evpl_listen(
    struct evpl_listener *listener,
    enum evpl_protocol_id protocol,
    struct evpl_endpoint *endpoint);
```

Start listening for incoming connections on an endpoint.  Threads should be attached to the listener before starting to listen.

**Parameters:**
- `listener` - Listener
- `protocol` - Protocol to use (e.g., `EVPL_STREAM_SOCKET_TCP`)
- `endpoint` - Local address and port to bind

### `evpl_listener_attach`

```c
struct evpl_listener_binding *evpl_listener_attach(
    struct evpl           *evpl,
    struct evpl_listener  *listener,
    evpl_attach_callback_t attach_callback,
    void                  *private_data);
```

Attach a listener to thread. When connections arrive, the attach callback is invoked.

**Parameters:**
- `evpl` - Event loop
- `listener` - Listener to attach
- `attach_callback` - Called for each new connection
- `private_data` - Passed to attach callback

**Returns:** Binding handle

### `evpl_listener_detach`

```c
void evpl_listener_detach(
    struct evpl                  *evpl,
    struct evpl_listener_binding *binding);
```

Detach a listener from an event loop.  This will prevent the thread from receiving new connections but will not affect already established connections.

**Parameters:**
- `evpl` - Event loop
- `binding` - Binding to remove

## Connection Functions

### `evpl_connect`

```c
struct evpl_bind *evpl_connect(
    struct evpl            *evpl,
    enum evpl_protocol_id   protocol_id,
    struct evpl_endpoint   *local_endpoint,
    struct evpl_endpoint   *remote_endpoint,
    evpl_notify_callback_t  notify_callback,
    evpl_segment_callback_t segment_callback,
    void                   *private_data);
```

Initiate a connection to a remote endpoint (client-side).

**Parameters:**
- `evpl` - Event loop
- `protocol_id` - Protocol to use
- `local_endpoint` - Local address to bind (or `NULL` for automatic)
- `remote_endpoint` - Remote address to connect to
- `notify_callback` - Callback for I/O events
- `segment_callback` - Callback for segment size (or `NULL`)
- `private_data` - User context passed to callbacks

**Returns:** Bind handle, or `NULL` on failure

**Note:** Connection is asynchronous. `EVPL_NOTIFY_CONNECTED` or `EVPL_NOTIFY_DISCONNECTED` will be delivered via the callback.

### `evpl_bind`

```c
struct evpl_bind *evpl_bind(
    struct evpl           *evpl,
    enum evpl_protocol_id  protocol,
    struct evpl_endpoint  *endpoint,
    evpl_notify_callback_t callback,
    void                  *private_data);
```

Create a datagram socket bound to a local endpoint (for UDP-style protocols).

**Parameters:**
- `evpl` - Event loop
- `protocol` - Datagram protocol (e.g., `EVPL_DATAGRAM_SOCKET_UDP`)
- `endpoint` - Local address and port
- `callback` - Notify callback
- `private_data` - User context

**Returns:** Bind handle, or `NULL` on failure

### `evpl_close`

```c
void evpl_close(struct evpl *evpl, struct evpl_bind *bind);
```

Close a connection or socket immediately, but asynchronously. Pending outgoing data may not be sent.

**Parameters:**
- `evpl` - Event loop
- `bind` - Connection to close

**Note:** A `EVPL_NOTIFY_DISCONNECTED` callback will be delivered.

### `evpl_finish`

```c
void evpl_finish(struct evpl *evpl, struct evpl_bind *bind);
```

Gracefully close a stream connection after all pending sends complete.

**Parameters:**
- `evpl` - Event loop
- `bind` - Connection to finish

**Note:** A `EVPL_NOTIFY_DISCONNECTED` callback will be delivered after closure.

## Send Functions

### `evpl_send`

```c
void evpl_send(
    struct evpl      *evpl,
    struct evpl_bind *bind,
    const void       *buffer,
    unsigned int      length);
```

Send arbitrary data on a stream connection by copying it into evpl.  This API is provided for convenience but should not be used in performance-sensitive context because it requires an internal memory copy.

**Parameters:**
- `evpl` - Event loop
- `bind` - Connection
- `buffer` - Data to send
- `length` - Number of bytes

**Note:** Data is copied to internal buffers. Returns immediately; completion signaled via `EVPL_NOTIFY_SENT`.

### `evpl_sendv`

```c
void evpl_sendv(
    struct evpl       *evpl,
    struct evpl_bind  *bind,
    struct evpl_iovec *iovecs,
    int                nbufvecs,
    int                length,
    unsigned int       flags);
```

Send data from multiple buffers allocated from evpl previously.  This allows zero-copy with supported underlying protocols.

**Parameters:**
- `evpl` - Event loop
- `bind` - Connection
- `iovecs` - Array of iovec structures
- `nbufvecs` - Number of iovecs
- `length` - Total bytes to send
- `flags` - Send flags (see below)

**Flags:**
- `EVPL_SEND_FLAG_TAKE_REF` - Transfer ownership of a reference to the iovecs to libevpl. When set, libevpl takes ownership and will decrement the reference count when the send completes. When not set, libevpl adds its own reference and the caller retains ownership.

### `evpl_sendto`

```c
void evpl_sendto(
    struct evpl         *evpl,
    struct evpl_bind    *bind,
    struct evpl_address *address,
    const void          *buffer,
    unsigned int         length);
```

Send a datagram to a specific address.  This API is provided for convenience but should not be used in performance-sensitive context because it requires an internal memory copy.

**Parameters:**
- `evpl` - Event loop
- `bind` - Datagram socket
- `address` - Destination address
- `buffer` - Data to send
- `length` - Message length

**Example:**
```c
// Received address from a previous recv_msg
evpl_sendto(evpl, bind, notify->recv_msg.addr, reply, reply_len);
```

### `evpl_sendtoep`

```c
void evpl_sendtoep(
    struct evpl          *evpl,
    struct evpl_bind     *bind,
    struct evpl_endpoint *endpoint,
    const void           *buffer,
    unsigned int          length);
```

Send a datagram to an endpoint (address + port).  This API is provided for convenience but should not be used in performance-sensitive context because it requires an internal memory copy.

**Parameters:**
- `evpl` - Event loop
- `bind` - Datagram socket
- `endpoint` - Destination
- `buffer` - Data
- `length` - Message length

### `evpl_sendtov`

```c
void evpl_sendtov(
    struct evpl         *evpl,
    struct evpl_bind    *bind,
    struct evpl_address *address,
    struct evpl_iovec   *iovecs,
    int                  nbufvecs,
    int                  length,
    unsigned int         flags);
```

Scatter-gather version of `evpl_sendto` that sends data from multiple buffers to a specific address.

**Parameters:**
- `evpl` - Event loop
- `bind` - Datagram socket
- `address` - Destination address
- `iovecs` - Array of iovec structures
- `nbufvecs` - Number of iovecs
- `length` - Total bytes to send
- `flags` - Send flags (see `evpl_sendv` for flag descriptions)

**Note:** This allows zero-copy with supported underlying protocols.

### `evpl_sendtoepv`

```c
void evpl_sendtoepv(
    struct evpl          *evpl,
    struct evpl_bind     *bind,
    struct evpl_endpoint *endpoint,
    struct evpl_iovec    *iovecs,
    int                   nbufvecs,
    int                   length,
    unsigned int          flags);
```

Scatter-gather version of `evpl_sendtoep` that sends data from multiple buffers to an endpoint.

**Parameters:**
- `evpl` - Event loop
- `bind` - Datagram socket
- `endpoint` - Destination endpoint
- `iovecs` - Array of iovec structures
- `nbufvecs` - Number of iovecs
- `length` - Total bytes to send
- `flags` - Send flags (see `evpl_sendv` for flag descriptions)

**Note:** This allows zero-copy with supported underlying protocols.

## Receive Functions

### `evpl_recv`

```c
int evpl_recv(
    struct evpl      *evpl,
    struct evpl_bind *bind,
    void             *buffer,
    int               maxlength,
    unsigned int      flags);
```

Receive data from a stream connection and remove it from the receive buffer.  This API is provided for convenience but should not be used in performance-sensitive context because it requires an internal memory copy.

**Parameters:**
- `evpl` - Event loop
- `bind` - Connection
- `buffer` - Destination buffer
- `maxlength` - Maximum bytes to receive
- `flags` - Receive flags (see below)

**Flags:**
- `EVPL_RECV_FLAG_ALL_OR_NONE` - Only receive if at least `maxlength` bytes are available; otherwise return 0
- `0` - Receive up to `maxlength` bytes, returning whatever is available (partial reads allowed)

**Returns:** Number of bytes received, or -1 on error

**Note:** Generally this would be called when notify callback is made with `EVPL_NOTIFY_RECV_DATA` notify type.

### `evpl_recvv`

```c
int evpl_recvv(
    struct evpl       *evpl,
    struct evpl_bind  *bind,
    struct evpl_iovec *iovecs,
    int                maxiovecs,
    int                maxlength,
    int               *length);
```

Receive data into multiple buffers (scatter-gather).  Ownership of the referenced iovecs is transferred to the application.   It is the applications responsible to ultimately release the iovecs.

This API is zero-copy with supported underlying protocols.

**Parameters:**
- `evpl` - Event loop
- `bind` - Connection
- `iovecs` - Array of iovec structures to fill
- `maxiovecs` - Maximum number of iovecs to fill
- `maxlength` - Maximum bytes to receive
- `length` - [OUT, optional] If not NULL, receives the actual number of bytes read

**Returns:** Number of iovecs filled, or -1 on error (e.g., insufficient buffer space in `iovecs` array)

### `evpl_peek`

```c
int evpl_peek(
    struct evpl      *evpl,
    struct evpl_bind *bind,
    void             *buffer,
    int               length);
```

Read data from receive buffer without removing it from the receive ring.  Useful for segmenting stream into messages.
Performs a memory copy so not performant for large lengths.

**Parameters:**
- `evpl` - Event loop
- `bind` - Connection
- `buffer` - Destination
- `length` - Bytes to peek

**Returns:** Number of bytes peeked

### `evpl_consume`

```c
int evpl_consume(
    struct evpl      *evpl,
    struct evpl_bind *bind,
    int               length);
```

Discard 'length' bytes of received data without inspecting it.

**Parameters:**
- `evpl` - Event loop
- `bind` - Connection
- `length` - Bytes to discard

**Returns:** 0 on success, -1 if less than length bytes available to consume

## Query Functions

### `evpl_bind_get_local_address`

```c
void evpl_bind_get_local_address(
    struct evpl_bind *bind,
    char             *str,
    int               len);
```

Get the local address of a bind as a string.

**Parameters:**
- `bind` - Connection
- `str` - Output buffer
- `len` - Buffer size

### `evpl_bind_get_remote_address`

```c
void evpl_bind_get_remote_address(
    struct evpl_bind *bind,
    char             *str,
    int               len);
```

Get the remote address of a connection as a string.

### `evpl_bind_get_protocol`

```c
enum evpl_protocol_id evpl_bind_get_protocol(struct evpl_bind *bind);
```

Get the protocol used by a bind.

**Returns:** Protocol ID

## Advanced Functions

### `evpl_bind_request_send_notifications`

```c
void evpl_bind_request_send_notifications(
    struct evpl      *evpl,
    struct evpl_bind *bind);
```

Request `EVPL_NOTIFY_SENT` notifications for send completions. By default, send notifications are not delivered.

**Parameters:**
- `evpl` - Event loop
- `bind` - Connection

## See Also

- [Endpoints API](/api/endpoints) - Address and port management
- [Memory API](/api/memory) - Buffer and iovec management
- [Core API](/api/core) - Event loop management
- [Getting Started](/getting-started) - Echo server example
