# eBPF XDP Firewall User Guide

## Introduction

Welcome to the **eBPF XDP Firewall**.

This guide explains how to build, load, configure, and use the firewall. The firewall uses Linux eBPF and XDP to filter packets at the earliest point in the networking stack, providing high-performance packet filtering with runtime configurable rules.

---

# Table of Contents

1. Overview
2. System Requirements
3. Building the Project
4. Loading the Firewall
5. Firewall Commands
6. Configuration File
7. Rule Processing Order
8. Packet Processing
9. Example Workflow
10. Troubleshooting
11. Frequently Asked Questions

---

# 1. Overview

The firewall provides:

- Dynamic IP blocking
- Dynamic IP allowlist
- TCP port filtering
- UDP port filtering
- Runtime rule updates
- Configuration file support
- XDP-based packet filtering
- High-performance packet processing

The firewall evaluates every incoming packet and decides whether it should be passed to the Linux networking stack or dropped immediately.

---

# 2. System Requirements

The project requires:

- Linux kernel with eBPF/XDP support
- clang
- LLVM
- libbpf
- bpftool
- iproute2
- make
- Root (sudo) privileges

---

# 3. Building the Project

Clone the repository.

```bash
git clone https://github.com/gorlerohithsriram-prog/eBPF-XDP-Firewall.git
cd eBPF-XDP-Firewall
```

Compile the project.

```bash
make
```

If compilation succeeds, the following files will be generated:

- fw
- firewall.bpf.o
- firewall.skel.h

---

# 4. Loading the Firewall

Attach the firewall to a network interface.

Example:

```bash
sudo ./fw load enp0s3
```

Replace `enp0s3` with your network interface if different.

Successful output:

```text
Firewall attached to enp0s3 successfully.
```

To unload the firewall:

```bash
sudo ./fw unload
```

---

# 5. Firewall Commands

## Block an IP

```bash
sudo ./fw block 192.168.1.100
```

Blocks packets originating from the specified IPv4 address.

---

## Remove a Blocked IP

```bash
sudo ./fw unblock 192.168.1.100
```

Removes the IP from the blocked list.

---

## Allow an IP

```bash
sudo ./fw allow 192.168.1.50
```

Adds the IP address to the allow list.

---

## Remove an Allowed IP

```bash
sudo ./fw unallow 192.168.1.50
```

Removes the IP from the allow list.

---

## Block a TCP Port

```bash
sudo ./fw block-tcp 80
```

Blocks incoming TCP packets destined for port 80.

---

## Remove a Blocked TCP Port

```bash
sudo ./fw unblock-tcp 80
```

Removes the TCP port from the blocked list.

---

## Allow a TCP Port

```bash
sudo ./fw allow-tcp 22
```

Allows incoming TCP packets destined for port 22.

---

## Remove an Allowed TCP Port

```bash
sudo ./fw unallow-tcp 22
```

Removes the TCP port from the allow list.

---

## Block a UDP Port

```bash
sudo ./fw block-udp 53
```

Blocks incoming UDP packets destined for port 53.

---

## Remove a Blocked UDP Port

```bash
sudo ./fw unblock-udp 53
```

Removes the UDP port from the blocked list.

---

## Allow a UDP Port

```bash
sudo ./fw allow-udp 53
```

Allows incoming UDP packets destined for port 53.

---

## Remove an Allowed UDP Port

```bash
sudo ./fw unallow-udp 53
```

Removes the UDP port from the allow list.

---

## Apply Configuration File

```bash
sudo ./fw apply config/firewall.conf
```

Reads the configuration file and updates all firewall rules.

---

## Display Help

```bash
sudo ./fw help
```

Displays all supported commands.

---

# 6. Configuration File

Example:

```text
# IP Rules
allow_ip=192.168.1.10
block_ip=192.168.1.20

# TCP Rules
allow_tcp=22
block_tcp=80

# UDP Rules
allow_udp=53
block_udp=69
```

Supported directives:

| Directive | Description |
|------------|-------------|
| allow_ip | Allow an IPv4 address |
| block_ip | Block an IPv4 address |
| allow_tcp | Allow a TCP destination port |
| block_tcp | Block a TCP destination port |
| allow_udp | Allow a UDP destination port |
| block_udp | Block a UDP destination port |

Lines beginning with `#` are treated as comments.

Blank lines are ignored.

---

# 7. Rule Processing Order

Packets are evaluated in the following order:

1. Allow IP
2. Block IP
3. Allow TCP Port
4. Block TCP Port
5. Allow UDP Port
6. Block UDP Port
7. Pass packet

This rule priority ensures predictable firewall behaviour.

---

# 8. Packet Processing

For every incoming packet:

1. Packet reaches the network interface.
2. XDP program executes.
3. Ethernet header is parsed.
4. IPv4 header is parsed.
5. Firewall rules stored in eBPF maps are checked.
6. Matching packets are dropped.
7. Remaining packets are passed to the Linux networking stack.

---

# 9. Example Workflow

Load the firewall.

```bash
sudo ./fw load enp0s3
```

Block an IP.

```bash
sudo ./fw block 192.168.1.50
```

Block TCP port 80.

```bash
sudo ./fw block-tcp 80
```

Allow SSH.

```bash
sudo ./fw allow-tcp 22
```

Apply configuration.

```bash
sudo ./fw apply config/firewall.conf
```

Unload the firewall.

```bash
sudo ./fw unload
```

---

# 10. Troubleshooting

## Firewall does not load

Possible reasons:

- Interface name is incorrect.
- Root privileges are missing.
- Kernel does not support XDP.
- Firewall is already attached.

---

## Invalid IP Address

Example:

```text
Invalid IPv4 address
```

Verify that the IP address follows the format:

```text
A.B.C.D
```

---

## Invalid Port

Example:

```text
Invalid Port
```

Valid port numbers range from **1 to 65535**.

---

## Configuration File Cannot Be Opened

Example:

```text
Failed to open config file
```

Verify that the file path is correct.

---

## Unknown Command

Example:

```text
Error: Unknown command
```

Run:

```bash
sudo ./fw help
```

to view all supported commands.

---

# 11. Frequently Asked Questions

## Why use XDP?

XDP processes packets before they enter the Linux networking stack, providing very low latency and high throughput.

---

## Why use eBPF maps?

eBPF maps allow firewall rules to be modified at runtime without recompiling or reloading the kernel program.

---

## Does the firewall support IPv6?

No.

The current implementation supports IPv4 only.

---

## Can firewall rules be updated without recompiling?

Yes.

Rules are stored in eBPF maps and can be updated dynamically through the CLI or configuration file.

---

## Does the firewall maintain connection state?

No.

Each packet is evaluated independently.

---

# Best Practices

- Keep frequently used rules inside a configuration file.
- Test new firewall rules in a controlled environment.
- Verify the correct network interface before loading the firewall.
- Keep the project updated with future enhancements.

---

# Conclusion

The eBPF XDP Firewall demonstrates how Linux eBPF and XDP can be used to build a high-performance, configurable packet filtering system. The project provides runtime rule management through eBPF maps while maintaining a simple command-line interface suitable for learning modern Linux networking and firewall design.
