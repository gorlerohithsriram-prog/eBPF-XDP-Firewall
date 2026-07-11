// firewall.bpf.c

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

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

    if ((void *)(ip + 1) > data_end)
        return XDP_PASS;

    if (allow_ip(ip))
    {
        bpf_printk("Allowed Source IP\n");
        return XDP_PASS;
    }

    if (block_ip(ip))
    {
        bpf_printk("Blocked Source IP\n");
        return XDP_DROP;
    }

    return XDP_PASS;
}
char LICENSE[] SEC("license") = "GPL";
