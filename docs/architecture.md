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
                |                           |
                |  CLI (fw)                 |
                |  Config Parser            |
                |  Statistics Viewer        |
                +------------+--------------+
                             |
                             | libbpf
                             |
                +------------v--------------+
                |      eBPF Maps            |
                |---------------------------|
                | Blocked IP Map            |
                | Allowed IP Map            |
                | Blocked TCP Port Map      |
                | Allowed TCP Port Map      |
                | Blocked UDP Port Map      |
                | Allowed UDP Port Map      |
                | Statistics Map            |
                | Rate Counter Map          |
                +------------+--------------+
                             |
                             |
                +------------v--------------+
                |      XDP Program          |
                |---------------------------|
                | Ethernet Parsing          |
                | IPv4 Parsing              |
                | TCP/UDP Parsing           |
                | Rule Checking             |
                | Statistics Update         |
                | Adaptive Auto-Block       |
                +------------+--------------+
                             |
                             |
                    Incoming Network Packet
```

---

## Components

### User Space

Responsibilities:

- Load the eBPF program
- Attach XDP to a network interface
- Read configuration files
- Update eBPF maps
- Display statistics
- Provide a command-line interface

---

### eBPF Maps

Maps act as shared memory between user space and kernel space.

Used for:

- Blocked IPs
- Allowed IPs
- TCP rules
- UDP rules
- Packet counters
- Statistics

---

### XDP Program

The XDP program executes before packets enter the Linux networking stack.

Responsibilities:

- Parse packet headers
- Apply firewall rules
- Update counters
- Drop malicious packets
- Pass legitimate traffic

---

## Design Goals

- High Performance
- Runtime Configurability
- Simple Rule Management
- Low Latency
- Modular Design
- Easy Extension
