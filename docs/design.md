# Design Document

## Objective

The objective of this project is to build a high-performance configurable firewall using eBPF and XDP.

Unlike traditional firewalls, packet filtering is performed before packets enter the Linux networking stack.

---

# Design Principles

The firewall follows five design principles.

## 1. Performance

Packet filtering occurs at the XDP layer.

This minimizes CPU overhead and reduces packet processing latency.

---

## 2. Runtime Configurability

Firewall rules should be modified without recompiling the eBPF program.

This is achieved using eBPF maps.

---

## 3. Separation of Responsibilities

User Space

Responsible for:

- Configuration
- CLI
- Loading eBPF program
- Updating maps

Kernel Space

Responsible for:

- Packet parsing
- Rule evaluation
- Packet filtering
- Statistics

---

## 4. Rule Priority

Rule evaluation follows:

Allow IP
↓

Block IP
↓

Allow TCP Port
↓

Block TCP Port
↓

Allow UDP Port
↓

Block UDP Port
↓

Default PASS

This avoids ambiguity.

---

## 5. Adaptive Auto-Block

The firewall monitors packet rate.

If an IP exceeds a configurable threshold,

The firewall automatically inserts the IP into the blocked map.

Advantages:

- Automatic attack mitigation
- No administrator intervention
- Dynamic protection

---

## Data Structures

The firewall uses multiple eBPF hash maps.

Examples:

- Allowed IP Map
- Blocked IP Map
- TCP Port Map
- UDP Port Map
- Statistics Map
- Rate Counter Map

---

## Why eBPF Maps?

eBPF maps allow:

- Runtime updates
- Shared kernel/user memory
- Fast lookups
- Persistent rule storage while the program is attached

---

## Why XDP?

Advantages:

- Earliest packet processing
- High throughput
- Low latency
- Reduced CPU utilization

---

## Future Improvements

- IPv6
- CIDR support
- Stateful firewall
- GUI
- REST API
- Dashboard
