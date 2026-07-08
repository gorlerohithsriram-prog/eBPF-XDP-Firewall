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

---

### Step 7

Statistics are updated.

Counters include:

- Processed Packets
- Passed Packets
- Dropped Packets
- Rate Violations
- Automatic Blocks

---

### Step 8

If Adaptive Auto-Block is enabled,

The packet rate is checked.

If threshold exceeded,

The source IP is automatically inserted into the blocked IP map.

---

### Step 9

The XDP program returns:

- XDP_PASS
- XDP_DROP
