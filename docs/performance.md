---
title: Performance
layout: default
nav_order: 3
permalink: /performance
---

More comprehensive benchmark results will be available soon, but in the meantime here's a few examples.

These results are generated from sister project [Flowbench](https://github.com/chimera-nas/flowbench) which is a network benchmarking tool capable of using libevpl.

## RDMA RC 1-thread ping-pong RPC with queue depth 16, 64-byte requests:

A single thread using RDMA RC can achieve over 2 million RPCs per second at average latency of 6.3uS

```
Flow: Sent: 1.30 GB (1.04 Gbps) [2.04 Mops/s], Recv: 1.30 GB (1.04 Gbps) [2.04 Mops/s] | Latency: Min: 2624ns, Max: 1303897ns, Avg: 6397ns
```

## RDMA RC 64-threads ping-pong RPC with queue depth 16, 64-byte requests:

Scaling up to 64 thread achieves 69 million RPCs per second, avg latency increases to only 6.7uS

```
Flow: Sent: 45.23 GB (35.81 Gbps) [69.95 Mops/s], Recv: 46.16 GB (36.55 Gbps) [71.29 Mops/s] | Latency: Min: 2313ns, Max: 5889650ns, Avg: 6741ns
```

## RDMA RC 1-thread streaming requests with queue depth 16, 128kb requests:

A single thread streaming 128kb requests at queue depth 16 nearly saturates 400GbE ethernet

```
Flow: Sent: 489.74 GB (391.67 Gbps) [373.53 Kops/s], Recv: 0.00 B (0.00 bps) [0.00 ops/s]
```

## XLIO TCP 1-thread ping-pong RPC with queue depth 8, 64-byte requests:

A single thread driving a single TCP socket is capable of performing nearly a million 64-byte RPCs with average latency of only 11uS.

```
Flow: Sent: 588.43 MB (470.65 Mbps) [919.25 Kops/s], Recv: 588.43 MB (470.65 Mbps) [919.25 Kops/s] | Latency: Min: 4587ns, Max: 2990063491ns, Avg: 11165ns
```

## XLIO TCP 16-threads ping-pong RPC with queue depth 8, 64-byte requests:

Sixteen threads increases total RPCs to 6.7 million.

```
Flow: Sent: 4.36 GB (3.48 Gbps) [6.79 Mops/s], Recv: 4.36 GB (3.48 Gbps) [6.79 Mops/s] | Latency: Min: 6710ns, Max: 2977527053ns, Avg: 19016ns
```

## XLIO TCP 1-thread streaming requests with queue depth 32, 128kb requests:

Single TCP socket, single thread achieves 230 Gbps streaming.

```
Flow: Sent: 288.52 GB (230.77 Gbps) [220.08 Kops/s], Recv: 0.00 B (0.00 bps) [0.00 ops/s]
```

## XLIO TCP 4-threads streaming requests with queue depth 32, 128kb requests:

Increase to just four sockets, four cores and we can saturate 400GbE.

```
Flow: Sent: 495.67 GB (396.41 Gbps) [378.04 Kops/s], Recv: 0.00 B (0.00 bps) [0.00 ops/s]
```
