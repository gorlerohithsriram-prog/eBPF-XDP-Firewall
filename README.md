# eBPF-XDP-Firewall

A high-performance configurable firewall built using Linux eBPF and XDP.

## Overview

The eBPF-XDP-Firewall is a high-performance packet filtering system built using Linux eBPF and XDP. It supports dynamic IP filtering, TCP/UDP port filtering, runtime rule updates using eBPF maps, configuration file support, and adaptive automatic blocking of suspicious traffic.

Unlike traditional firewalls that process packets after they enter the Linux networking stack, XDP processes packets directly in the network driver, reducing latency and improving throughput.

This project demonstrates how eBPF and XDP can be used to build a configurable firewall whose rules can be updated dynamically without recompiling the kernel program.

## Technologies Used
- C
- Linux eBPF
- XDP (Express Data Path)
- libbpf
- bpftool
- clang / LLVM
- Make
  
## Features
✔ XDP Packet Processing
✔ Dynamic IP Blocking
✔ Dynamic IP Allowlist
✔ TCP Port Filtering
✔ UDP Port Filtering
✔ Runtime Rule Updates
✔ Configuration File Support
✔ Adaptive Auto-Block

## Folder Structure

```text
ebpf-firewall/
│
├── bpf/
│   └── firewall.bpf.c
│
├── loader/
│   └── fw.c
│
├── config/
│   ├── firewall.conf
│   ├── example.conf
│   └── minimal.conf
│
├── docs/
│   ├── architecture.md
│   ├── packet-flow.md
│   ├── design.md
│   ├── limitations.md
│   └── screenshots/
│   └── user-guide.md
|
├── Makefile
├── README.md
├── LICENSE
```
| Folder     | Purpose                      |
| ---------- | ---------------------------- |
| `bpf/`     | eBPF/XDP program             |
| `loader/`  | User-space CLI               |
| `config/`  | Firewall configuration files |
| `docs/`    | Documentation                |

## Packet Flow
```text
  Internet
      │
      ▼
  Network Interface (NIC)
      │
      ▼
  XDP Hook
      │
      ▼
  Firewall Rules
      │
   ┌──┴──┐
   │     │
  PASS  DROP
   │
   ▼
  Linux Networking Stack

```
## Requirements
- Linux Kernel with eBPF/XDP support
- clang
- LLVM
- libbpf
- bpftool
- iproute2
- make

## Build
```bash
git clone https://github.com/gorlerohithsriram-prog/eBPF-XDP-Firewall.git
cd eBPF-XDP-Firewall
make
```

## Usage

### 1. Build the Project

```bash
make
```

---

### 2. Load the Firewall

Replace `enp0s3` with your network interface if different.

```bash
sudo ./fw load enp0s3
```

---

### 3. Block an IP Address

```bash
sudo ./fw block 192.168.1.100
```

---

### 4. Allow an IP Address

```bash
sudo ./fw allow 192.168.1.100
```

---

### 5. Block a TCP Port

```bash
sudo ./fw block-tcp 80
```

---

### 6. Allow a TCP Port

```bash
sudo ./fw allow-tcp 22
```

---

### 7. Block a UDP Port

```bash
sudo ./fw block-udp 53
```

---

### 8. Apply a Configuration File

```bash
sudo ./fw apply config/firewall.conf
```

---

### 9. Display Help

```bash
sudo ./fw help
```

---

### 10. Unload the Firewall

```bash
sudo ./fw unload
```

## CLI Commands
| Command            | Description              |
| ------------------ | ------------------------ |
| `./fw load`        | Attach firewall          |
| `./fw unload`      | Detach firewall          |
| `./fw block`       | Block an IP              |
| `./fw unblock`     | Remove blocked IP        |
| `./fw allow`       | Allow an IP              |
| `./fw unallow`     | Remove allowed IP        |
| `./fw block-tcp`   | Block TCP port           |
| `./fw unblock-tcp` | Remove blocked TCP port  |
| `./fw allow-tcp`   | Allow TCP port           |
| `./fw unallow-tcp` | Remove allowed TCP port  |
| `./fw block-udp`   | Block UDP port           |
| `./fw unblock-udp` | Remove blocked UDP port  |
| `./fw allow-udp`   | Allow UDP port           |
| `./fw unallow-udp` | Remove allowed UDP port  |
| `./fw apply`       | Apply configuration file |
| `./fw help`        | Display help             |

## Error handling
✔ Invalid IP
✔ Invalid Port
✔ Unknown Directive
✔ Missing Config
✔ Firewall Already Loaded
✔ Firewall Not Loaded

## Limitations
  Currently supports IPv4 only.
  No IPv6 support.
  No CIDR matching.
  No GUI.
  No Web Dashboard.
  No Stateful Connection Tracking.
  
## Future Work
- IPv6 support
- CIDR rules
- REST API
- Web dashboard
- Rule expiration
- DNS/domain filtering
- GeoIP blocking
- Machine-learning-based anomaly detection

## License
This project is licensed under the MIT License. See the LICENSE file for details.
