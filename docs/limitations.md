# Current Limitations

Although the firewall successfully demonstrates high-performance packet filtering using eBPF and XDP, it has several limitations.

---

## IPv4 Only

Currently, only IPv4 packets are processed.

IPv6 support is not implemented.

---

## No CIDR Support

Only individual IP addresses can be blocked or allowed.

Examples:

Supported:

192.168.1.10

Not Supported:

192.168.1.0/24

---

## Stateless Firewall

The firewall does not maintain connection state.

Each packet is evaluated independently.

---

## No DNS Filtering

Domain names cannot be filtered.

Only IP addresses are supported.

---

## No GeoIP Filtering

Traffic cannot be filtered based on country or region.

---

## No Web Dashboard

The firewall is managed only through the command-line interface.

---

## Limited Protocol Support

Currently supported:

- IPv4
- TCP
- UDP

Other protocols are not evaluated.

---

## Basic Rate Limiting

Adaptive Auto-Block uses a simple packet-rate threshold.

More advanced traffic analysis techniques are not implemented.

---

## Future Enhancements

Possible future work includes:

- IPv6 support
- CIDR matching
- Stateful inspection
- Time-based rules
- Rule expiration
- REST API
- Web dashboard
- GeoIP filtering
- Machine learning-based anomaly detection
- Persistent storage across reboots
