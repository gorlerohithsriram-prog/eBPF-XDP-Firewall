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

## Packet Flow
  Internet -> NIC -> XDP Hook -> Firewall -> PASS / DROP -> Linux Network Stack

## Requirements
  Linux Kernel with eBPF/XDP support<br>
  clang<br>
  LLVM<br>
  libbpf<br>
  bpftool<br>
  iproute2<br>
  Make<br>

## CLI Commands
| Command      | Description                      |
| ------------ | -------------------------------- |
| `load`       | Attach firewall                  |
| `unload`     | Remove firewall                  |
| `block-ip`   | Block an IP                      |
| `allow-ip`   | Allow an IP                      |
| `block-tcp`  | Block TCP port                   |
| `allow-tcp`  | Allow TCP port                   |
| `stats`      | Show statistics                  |
| `apply`      | Apply configuration              |
| `rate-limit` | Set threshold                    |
| `auto-block` | Enable/disable adaptive blocking |
| `help`       | Show usage                       |

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
✔ Firewall Already Loaded
✔ Firewall Not Loaded

## folder structure
| Folder     | Purpose                      |
| ---------- | ---------------------------- |
| `bpf/`     | eBPF/XDP program             |
| `loader/`  | User-space CLI               |
| `config/`  | Firewall configuration files |
| `docs/`    | Documentation                |

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
