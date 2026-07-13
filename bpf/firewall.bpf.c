// firewall.bpf.c
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/in.h>
#include <linux/tcp.h>
#include <linux/udp.h>

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#define RATE_LIMIT 20
#define ONE_SECOND_NS 1000000000ULL

enum stats_index {
    STAT_TOTAL_PACKETS = 0,
    STAT_PASSED_PACKETS,
    STAT_DROPPED_PACKETS,
    STAT_BLOCKED_IP_HITS,
    STAT_BLOCKED_TCP_PORT_HITS,
    STAT_BLOCKED_UDP_PORT_HITS,
    STAT_ALLOWED_IP_HITS,
    STAT_ALLOWED_TCP_PORT_HITS,
    STAT_ALLOWED_UDP_PORT_HITS,
    STAT_MAX
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, __u32);
    __type(value, __u8);
} blocked_ips SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, __u32);
    __type(value, __u8);
} allowed_ips SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, __u16);
    __type(value, __u8);
} blocked_tcp_ports SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, __u16);
    __type(value, __u8);
} allowed_tcp_ports SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, __u16);
    __type(value, __u8);
} blocked_udp_ports SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, __u16);
    __type(value, __u8);
} allowed_udp_ports SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, STAT_MAX);
    __type(key, __u32);
    __type(value, __u64);
} firewall_stats SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 4096);
    __type(key, __u32);
    __type(value, __u64);
} packet_count SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 4096);
    __type(key, __u32);
    __type(value, __u64);
} last_seen SEC(".maps");

static __always_inline int is_ipv4(struct ethhdr *eth)
{
    return eth->h_proto == bpf_htons(ETH_P_IP);
}

static __always_inline int allow_ip(struct iphdr *ip)
{
    __u8 *allowed;

    allowed = bpf_map_lookup_elem(&allowed_ips, &ip->saddr);

    if (allowed)
        return 1;

    return 0;
}

static __always_inline int block_ip(struct iphdr *ip)
{
    __u8 *blocked;

    blocked = bpf_map_lookup_elem(&blocked_ips, &ip->saddr);

    if (blocked)
        return 1;

    return 0;
}

static __always_inline int allow_tcp_port(__u16 port)
{
    __u8 *allowed;

    allowed = bpf_map_lookup_elem(&allowed_tcp_ports, &port);

    return allowed != NULL;
}

static __always_inline int block_tcp_port(__u16 port)
{
    __u8 *blocked;

    blocked = bpf_map_lookup_elem(&blocked_tcp_ports, &port);

    return blocked != NULL;
}

static __always_inline int allow_udp_port(__u16 port)
{
    __u8 *allowed;

    allowed = bpf_map_lookup_elem(&allowed_udp_ports, &port);

    return allowed != NULL;
}

static __always_inline int block_udp_port(__u16 port)
{
    __u8 *blocked;

    blocked = bpf_map_lookup_elem(&blocked_udp_ports, &port);

    return blocked != NULL;
}

static __always_inline void increment_stat(__u32 index)
{
    __u64 *value;

    value = bpf_map_lookup_elem(&firewall_stats, &index);

    if (value)
        (*value)++;
}

SEC("xdp")
int firewall(struct xdp_md *ctx)
{
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    struct ethhdr *eth = data;

    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    if (!is_ipv4(eth))
        return XDP_PASS;

    struct iphdr *ip = (void *)(eth + 1);

    increment_stat(STAT_TOTAL_PACKETS);

    if ((void *)(ip + 1) > data_end)
        return XDP_PASS;

    __u32 src_ip = ip->saddr;
    __u64 now = bpf_ktime_get_ns();

    __u64 *count = bpf_map_lookup_elem(&packet_count, &src_ip);
    __u64 *last  = bpf_map_lookup_elem(&last_seen, &src_ip);

    if (!count || !last)
    {
        __u64 one = 1;

        bpf_map_update_elem(&packet_count, &src_ip, &one, BPF_ANY);
        bpf_map_update_elem(&last_seen, &src_ip, &now, BPF_ANY);
    }
    else
    {
        (*count)++;

        if (now - *last >= ONE_SECOND_NS)
        {
            if (*count > RATE_LIMIT)
            {
                __u8 blocked = 1;

                bpf_map_update_elem(&blocked_ips,
                                    &src_ip,
                                    &blocked,
                                    BPF_ANY);

                increment_stat(STAT_BLOCKED_IP_HITS);

                bpf_printk("Auto blocked IP due to rate limit");
            }

            *count = 1;
            *last = now;
        }
    }
    if (allow_ip(ip))
    {
        increment_stat(STAT_ALLOWED_IP_HITS);
        increment_stat(STAT_PASSED_PACKETS);

        bpf_printk("Allowed Source IP\n");
        return XDP_PASS;
    }

    if (block_ip(ip))
    {
        increment_stat(STAT_BLOCKED_IP_HITS);
        increment_stat(STAT_DROPPED_PACKETS);
        bpf_printk("Blocked Source IP\n");
        return XDP_DROP;
    }
    
    if (ip->protocol == IPPROTO_TCP)
{
    struct tcphdr *tcp = (void *)(ip + 1);

    if ((void *)(tcp + 1) > data_end)
        return XDP_PASS;

    __u16 port = bpf_ntohs(tcp->dest);

    if (allow_tcp_port(port))
    {
        increment_stat(STAT_ALLOWED_TCP_PORT_HITS);
        increment_stat(STAT_PASSED_PACKETS);

        bpf_printk("Allowed TCP Port\n");
        return XDP_PASS;
    }

    if (block_tcp_port(port))
    {
        increment_stat(STAT_BLOCKED_TCP_PORT_HITS);
        increment_stat(STAT_DROPPED_PACKETS);
        bpf_printk("Blocked TCP Port\n");
        return XDP_DROP;
    }
}
    if (ip->protocol == IPPROTO_UDP)
{
    struct udphdr *udp = (void *)(ip + 1);

    if ((void *)(udp + 1) > data_end)
        return XDP_PASS;

    __u16 port = bpf_ntohs(udp->dest);

    if (allow_udp_port(port))
    {
        increment_stat(STAT_ALLOWED_UDP_PORT_HITS);
        increment_stat(STAT_PASSED_PACKETS);

        bpf_printk("Allowed UDP Port\n");
        return XDP_PASS;
    }

    if (block_udp_port(port))
    {
        increment_stat(STAT_BLOCKED_UDP_PORT_HITS);
        increment_stat(STAT_DROPPED_PACKETS);

        bpf_printk("Blocked UDP Port\n");
        return XDP_DROP;
    }
}
    increment_stat(STAT_PASSED_PACKETS);
    
    return XDP_PASS;
}
char LICENSE[] SEC("license") = "GPL";
