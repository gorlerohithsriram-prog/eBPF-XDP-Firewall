# eBPF-XDP-Firewall

## Overview
A high-performance firewall built using XDP and eBPF that supports dynamic IP filtering, port filtering, runtime configuration, live statistics, and adaptive automatic blocking of suspicious traffic.

Example:
Traditional firewalls process packets after they enter the Linux networking stack. XDP allows packets to be processed directly inside the network driver, reducing latency and improving throughput.

This project demonstrates how eBPF and XDP can be used to build a configurable firewall capable of dynamically updating rules without recompilation.

## Features
✔ XDP Packet Processing
✔ Dynamic IP Blocking
✔ Dynamic IP Allowlist
✔ TCP Port Filtering
✔ UDP Port Filtering
✔ Runtime Rule Updates
✔ Configuration File Support
✔ Statistics Monitoring
✔ Adaptive Auto-Block
✔ Error Handling
✔ Command Line Interface

## Technologies used
- C
- linux
- eBPF

## Packet Flow
  Internet -> NIC -> XDP Hook -> Firewall -> PASS / DROP -> Linux Network Stack

## Requirements
  Linux Kernel with eBPF/XDP support
  clang
  LLVM
  libbpf
  bpftool
  iproute2
  Make

## Statistics
| Statistic   | Meaning                 |
| ----------- | ----------------------- |
| Processed   | Total packets inspected |
| Passed      | Packets allowed         |
| Dropped     | Packets blocked         |
| Violations  | Rate-limit breaches     |
| Auto Blocks | Automatic block events  |

## Error handling
✔ Invalid IP
✔ Invalid Port
✔ Duplicate Rule
✔ Unknown Directive
✔ Missing Config
✔ Missing Interface
✔ Firewall Already Loaded
✔ Firewall Not Loaded
✔ Map Full

## Limitations
  Currently supports IPv4 only.
  No IPv6 support.
  No CIDR matching.
  No GUI.
  No Web Dashboard.
  
## Future work
  IPv6 support
  CIDR rules
  REST API
  Web dashboard
  Rule expiration
  DNS/domain filtering
  GeoIP blocking
  Machine-learning-based anomaly detection
