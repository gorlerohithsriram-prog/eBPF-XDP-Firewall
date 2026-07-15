# Packet Flow

## Overview

This document explains how an incoming packet travels through the firewall.

---

## Packet Processing Flow

```
Internet
    │
    ▼
Network Interface Card (NIC)
    │
    ▼
Device Driver
    │
    ▼
XDP Hook
    │
    ▼
Ethernet Header Parsing
    │
    ▼
IPv4 Header Parsing
    │
    ▼
TCP / UDP Header Parsing
    │
    ▼
Firewall Rule Evaluation
    │
    ├─────────────┐
    │             │
 PASS          DROP
    │             │
    ▼             ▼
Linux Stack    Packet Discarded
```

---

## Processing Steps

### Step 1

Packet arrives at the NIC.

---

### Step 2

The device driver invokes the XDP program.

---

### Step 3

The Ethernet header is parsed.

The firewall checks:

- EtherType

---

### Step 4

If the packet is IPv4,

The IPv4 header is parsed.

Information extracted:

- Source IP
- Destination IP
- Protocol

---

### Step 5

If TCP,

Extract:

- Source Port
- Destination Port

If UDP,

Extract:

- Source Port
- Destination Port

---

### Step 6

The firewall evaluates rules.

Priority:

1. Allow IP
2. Block IP
3. Allow TCP Port
4. Block TCP Port
5. Allow UDP Port
6. Block UDP Port

### Rule Lookup

Firewall rules are stored in eBPF maps.

The XDP program performs map lookups to determine whether the packet's source IP address or destination port matches any configured allow or block rules.

---

### Step 7

Based on the rule evaluation, the XDP program returns one of the following actions:

- `XDP_PASS` – The packet is forwarded to the Linux networking stack.
- `XDP_DROP` – The packet is discarded immediately by the network driver.
