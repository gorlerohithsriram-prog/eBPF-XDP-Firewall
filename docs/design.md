# eBPF XDP Firewall Design

## Overview

The eBPF XDP Firewall is designed as a modular packet filtering system using Linux eBPF and XDP. The project separates user-space management from kernel-space packet processing, allowing firewall rules to be updated dynamically without recompiling or reloading the eBPF program.

The design focuses on:

- High performance
- Modular architecture
- Runtime configurability
- Simple command-line management
- Easy future extension

---

# Design Objectives

The primary objectives of the project are:

- Filter packets at the earliest point in the Linux networking stack.
- Support dynamic firewall rule updates.
- Minimize packet processing latency.
- Keep kernel-space logic lightweight.
- Separate policy management from packet filtering.

---

# System Architecture

The project consists of two major components:

```
                +-----------------------+
                |      User Space       |
                |-----------------------|
                | CLI (fw)              |
                | Config Parser         |
                | libbpf                |
                +-----------+-----------+
                            |
                            |
                      eBPF Maps
                            |
                +-----------v-----------+
                |     Kernel Space      |
                |-----------------------|
                | XDP Firewall Program  |
                +-----------+-----------+
                            |
                    Incoming Packets
```

---

# User Space Design

The user-space application is implemented in:

```
loader/fw.c
```

Responsibilities include:

- Loading the eBPF program
- Attaching XDP to a network interface
- Detaching the firewall
- Reading configuration files
- Updating eBPF maps
- Providing a command-line interface

The user-space application never processes packets directly.

Instead, it manages firewall rules stored in eBPF maps.

---

# Kernel Space Design

The kernel-space component is implemented in:

```
bpf/firewall.bpf.c
```

Responsibilities include:

- Parsing Ethernet headers
- Parsing IPv4 headers
- Parsing TCP headers
- Parsing UDP headers
- Looking up firewall rules
- Returning XDP_PASS or XDP_DROP

Because the program executes inside the XDP hook, unwanted packets are discarded before entering the Linux networking stack.

---

# eBPF Maps

The firewall stores rules inside eBPF maps.

The current implementation uses:

- Blocked IP map
- Allowed IP map
- Blocked TCP port map
- Allowed TCP port map
- Blocked UDP port map
- Allowed UDP port map

These maps allow firewall rules to be modified dynamically without recompiling the kernel program.

---

# Packet Processing Logic

Each incoming packet follows the same processing sequence.

1. Receive packet.
2. Verify Ethernet header.
3. Verify IPv4 packet.
4. Parse transport protocol.
5. Check allow IP rules.
6. Check block IP rules.
7. Check allow TCP/UDP port rules.
8. Check block TCP/UDP port rules.
9. Return XDP_PASS or XDP_DROP.

This design keeps packet processing deterministic and easy to understand.

---

# Rule Priority

Rules are evaluated in the following order:

1. Allow IP
2. Block IP
3. Allow TCP Port
4. Block TCP Port
5. Allow UDP Port
6. Block UDP Port
7. Default PASS

This priority ensures that allow rules are evaluated before block rules.

---

# Configuration Design

Firewall rules can be loaded from a configuration file.

Example:

```text
allow_ip=192.168.1.10
block_ip=192.168.1.20

allow_tcp=22
block_tcp=80

allow_udp=53
block_udp=69
```

The configuration parser validates every rule before updating the corresponding eBPF map.

---

# Error Handling

The user-space application performs validation before updating firewall rules.

Examples include:

- Invalid IPv4 address
- Invalid port number
- Missing command arguments
- Missing configuration file
- Unknown command
- Unknown configuration directive
- Invalid network interface

Meaningful error messages are displayed to help users identify problems quickly.

---

# Folder Organization

```
eBPF-XDP-Firewall/

├── bpf/
│   └── firewall.bpf.c

├── loader/
│   └── fw.c

├── config/
│   ├── firewall.conf
│   ├── example.conf
│   └── minimal.conf

├── docs/
│   ├── architecture.md
│   ├── design.md
│   ├── packet-flow.md
│   ├── limitations.md
│   └── user-guide.md

├── Makefile
├── README.md
└── LICENSE
```

This modular organization separates kernel code, user-space code, configuration files, and documentation.

---

# Design Advantages

The current design provides several benefits:

- High-performance packet filtering using XDP.
- Runtime rule updates through eBPF maps.
- Clear separation between user space and kernel space.
- Modular and maintainable source code.
- Easy to extend with additional firewall features.

---

# Future Improvements

The modular design allows additional features to be added without major architectural changes.

Possible enhancements include:

- IPv6 support
- CIDR-based filtering
- Stateful connection tracking
- Rule expiration
- Persistent rule storage
- REST API
- Web dashboard
- GeoIP filtering
- DNS filtering
- Advanced traffic analysis

---

# Conclusion

The eBPF XDP Firewall is designed as a modular, configurable, and high-performance firewall built on Linux eBPF and XDP. By separating user-space rule management from kernel-space packet processing and using eBPF maps for communication, the design achieves efficient packet filtering while remaining simple, extensible, and suitable for learning modern Linux networking concepts.
