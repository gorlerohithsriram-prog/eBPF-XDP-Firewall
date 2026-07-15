# eBPF XDP Firewall Architecture

## Overview

The eBPF XDP Firewall is divided into two major components:

1. User Space
2. Kernel Space

The user-space application allows administrators to configure firewall rules, while the eBPF program running inside the Linux kernel performs high-speed packet filtering.

---

## High-Level Architecture

```
                +---------------------------+
                |        User Space         |
                |  CLI (fw)                 |
                |  Config Parser            |
                +------------+--------------+
                             |
                             | libbpf
                             |
                +------------v--------------+
                |      eBPF Maps            |
                +------------+--------------+
                             |
                +------------v--------------+
                |      XDP Program          |
                | Ethernet Parsing          |
                | IPv4 Parsing              |
                | TCP / UDP Parsing         |
                | Rule Checking             |
                +------------+--------------+
                             |
                  +----------+----------+
                  |                     |
               XDP_PASS             XDP_DROP
                  |                     |
                  v                     X
        Linux Networking Stack      Packet Dropped
```
---
### Packet Processing Flow

1. A packet arrives at the network interface.
2. The XDP program executes before the Linux networking stack.
3. Ethernet and IPv4 headers are parsed.
4. Firewall rules stored in eBPF maps are checked.
5. The packet is either passed to the networking stack or dropped immediately.

## Components

### User Space

Responsibilities:

- Load the eBPF program using libbpf
- Attach XDP to a network interface
- Read configuration files
- Update eBPF maps
- Provide a command-line interface

---

### eBPF Maps

Maps act as shared memory between user space and kernel space.
Rules can be added, removed, or modified at runtime without recompiling or reloading the eBPF program.

Used for:

- Blocked IPs
- Allowed IPs
- TCP rules
- UDP rules
- Packet counters

---

### XDP Program

The XDP program executes before packets enter the Linux networking stack.

Responsibilities:

- Parse packet headers
- Apply firewall rules
- Update counters
- Return `XDP_PASS` for allowed traffic
- Return `XDP_DROP` for blocked traffic

---

## Design Goals

- High Performance
- Runtime Configurability
- Simple Rule Management
- Low Latency
- Modular Design
- Easy Extension
- Dynamic Rule Updates
