---
title: Network Endpoints
layout: default
nav_order: 4
parent: API
permalink: /api/endpoint
---

# Network Endpoints

The endpoint API provides functionality for managing network endpoints in the EVPL library. An endpoint represents a network address and port combination that can be used for network communication.

## API Functions

### Creating an Endpoint

```c
struct evpl_endpoint *evpl_endpoint_create(const char *address, int port);
```

Creates a new endpoint with the specified address and port.

**Parameters:**
- `address`: The network address (e.g., "127.0.0.1" or "example.com")
- `port`: The port number

**Returns:**
- A pointer to the newly created endpoint structure
- NULL if creation fails

### Closing an Endpoint

```c
void evpl_endpoint_close(struct evpl_endpoint *endpoint);
```

Closes and frees an endpoint.

**Parameters:**
- `endpoint`: The endpoint to close

### Getting Endpoint Information

```c
const char *evpl_endpoint_address(const struct evpl_endpoint *ep);
```

Returns the address string of an endpoint.

**Parameters:**
- `ep`: The endpoint to query

**Returns:**
- The address string

```c
int evpl_endpoint_port(const struct evpl_endpoint *ep);
```

Returns the port number of an endpoint.

**Parameters:**
- `ep`: The endpoint to query

**Returns:**
- The port number

## Usage Example

```c
// Create an endpoint
struct evpl_endpoint *ep = evpl_endpoint_create("127.0.0.1", 8080);
if (!ep) {
    // Handle error
}

// Use the endpoint
const char *addr = evpl_endpoint_address(ep);
int port = evpl_endpoint_port(ep);

// Clean up when done
evpl_endpoint_close(ep);
```

## Notes

- Endpoints should be closed when they are no longer needed
- The address string is limited to 256 characters
