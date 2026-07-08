# User Guide

# eBPF XDP Firewall User Guide

## Introduction

Welcome to the **eBPF XDP Firewall**.

This guide explains how to install, configure, and use the firewall. It is intended for users who want to manage firewall rules without modifying the source code.

---

# Table of Contents

1. Overview
2. System Requirements
3. Building the Project
4. Loading the Firewall
5. Firewall Commands
6. Configuration File
7. Rule Priority
8. Adaptive Auto-Block
9. Viewing Statistics
10. Example Workflow
11. Troubleshooting
12. Frequently Asked Questions

---

# 1. Overview

The firewall is built using **eBPF** and **XDP**, allowing packets to be filtered at the earliest point in the Linux networking stack.

Features include:

* Dynamic IP blocking
* Dynamic IP allowlist
* TCP port filtering
* UDP port filtering
* Runtime rule updates
* Configuration file support
* Live statistics
* Adaptive Auto-Block
* Command-line interface

---

# 2. System Requirements

The project requires:

* Linux with eBPF/XDP support
* clang
* LLVM
* libbpf
* bpftool
* iproute2
* make
* Root (sudo) privileges for loading the firewall

---

# 3. Building the Project

Clone the repository.

```bash
git clone <repository-url>
cd ebpf-firewall
```

Compile the project.

```bash
make
```

If compilation completes successfully, the firewall executable and eBPF object file will be generated.

---

# 4. Loading the Firewall

Attach the firewall to a network interface.

```bash
sudo ./fw load eth0
```

Expected output:

```text
Firewall Loaded Successfully

Interface : eth0

Mode : XDP
```

To unload the firewall:

```bash
sudo ./fw unload
```

---

# 5. Firewall Commands

## Block an IP

```bash
./fw block-ip 192.168.1.10
```

Blocks all packets originating from the specified IPv4 address.

---

## Allow an IP

```bash
./fw allow-ip 192.168.1.10
```

Allows packets from the specified IP even if a conflicting block rule exists.

---

## Remove a Blocked IP

```bash
./fw unblock-ip 192.168.1.10
```

Removes the IP from the blocked list.

---

## Remove an Allowed IP

```bash
./fw unallow-ip 192.168.1.10
```

Removes the IP from the allowlist.

---

## Block a TCP Port

```bash
./fw block-tcp 80
```

Blocks incoming TCP traffic on port 80.

---

## Allow a TCP Port

```bash
./fw allow-tcp 22
```

Allows incoming TCP traffic on port 22.

---

## Block a UDP Port

```bash
./fw block-udp 53
```

Blocks incoming UDP traffic on port 53.

---

## Allow a UDP Port

```bash
./fw allow-udp 53
```

Allows incoming UDP traffic on port 53.

---

## Show Statistics

```bash
./fw stats
```

Displays packet processing statistics.

---

## Apply Configuration File

```bash
./fw apply config/firewall.conf
```

Reads firewall rules from a configuration file and updates the eBPF maps.

---

## Display Help

```bash
./fw help
```

Shows all available commands.

---

# 6. Configuration File

Example:

```text
allow_ip=192.168.1.5

block_ip=192.168.1.20

allow_tcp=22

block_tcp=80

block_udp=53

rate_limit=500

auto_block=true
```

Explanation:

| Directive  | Description                                 |
| ---------- | ------------------------------------------- |
| allow_ip   | Allow traffic from an IP                    |
| block_ip   | Block traffic from an IP                    |
| allow_tcp  | Allow a TCP destination port                |
| block_tcp  | Block a TCP destination port                |
| allow_udp  | Allow a UDP destination port                |
| block_udp  | Block a UDP destination port                |
| rate_limit | Maximum packets per second before detection |
| auto_block | Enable or disable Adaptive Auto-Block       |

---

# 7. Rule Priority

Rules are evaluated in the following order:

1. Allow IP
2. Block IP
3. Allow TCP Port
4. Block TCP Port
5. Allow UDP Port
6. Block UDP Port
7. Default PASS

This priority ensures predictable firewall behavior.

---

# 8. Adaptive Auto-Block

Adaptive Auto-Block is the firewall's unique feature.

Workflow:

1. Count packets received from each source IP.
2. Compare the packet rate with the configured threshold.
3. If the threshold is exceeded:

   * Automatically add the IP to the blocked map.
   * Update firewall statistics.
   * Drop future packets from that IP.

This allows the firewall to react automatically to suspicious traffic.

---

# 9. Viewing Statistics

Run:

```bash
./fw stats
```

Example output:

```text
Firewall Statistics

Processed Packets : 10542

Passed Packets    : 9810

Dropped Packets   : 732

Rate Violations   : 5

Automatic Blocks  : 2
```

---

# 10. Example Workflow

Load the firewall.

```bash
sudo ./fw load eth0
```

Apply a configuration file.

```bash
./fw apply config/firewall.conf
```

Block an IP address.

```bash
./fw block-ip 192.168.1.50
```

View current statistics.

```bash
./fw stats
```

Unload the firewall.

```bash
sudo ./fw unload
```

---

# 11. Troubleshooting

## Firewall does not load

Possible causes:

* Root privileges are missing.
* Interface name is incorrect.
* Kernel does not support XDP/eBPF.

---

## Invalid IP Address

Example:

```text
Error:

Invalid IPv4 address.
```

Verify that the address follows the format:

```
A.B.C.D
```

---

## Configuration File Not Found

Example:

```text
Error:

Unable to locate configuration file.
```

Verify the file path before running the command.

---

## Rule Already Exists

Example:

```text
Warning:

Rule already exists.
```

Duplicate rules are ignored.

---

## Statistics Do Not Change

Possible causes:

* Firewall is not attached.
* No traffic is reaching the selected interface.
* Rules are not being matched.

---

# 12. Frequently Asked Questions

### Why use XDP?

XDP processes packets before they enter the Linux networking stack, allowing unwanted traffic to be dropped earlier and reducing processing overhead.

---

### Why use eBPF maps?

eBPF maps allow firewall rules and statistics to be updated dynamically from user space without recompiling the kernel program.

---

### Does the firewall support IPv6?

No. The current implementation supports IPv4 only.

---

### Can rules be modified without recompiling?

Yes. Rules are updated through eBPF maps using the CLI or a configuration file.

---

### What makes this firewall unique?

The firewall includes an **Adaptive Auto-Block** feature that automatically detects high packet rates from a source IP and blocks that IP without requiring manual intervention.

---

# Best Practices

* Keep configuration files under version control.
* Review firewall statistics regularly.
* Use the configuration file for permanent rules.
* Use CLI commands for temporary changes.
* Test new rules in a controlled environment before deploying them.

---

# Conclusion

The eBPF XDP Firewall provides a configurable, high-performance packet filtering solution using Linux eBPF and XDP. Its modular architecture, runtime configurability, and Adaptive Auto-Block feature make it suitable for learning modern Linux networking while demonstrating practical firewall design principles.
