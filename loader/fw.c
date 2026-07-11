#include "../bpf/firewall.skel.h"
#include <net/if.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <arpa/inet.h>

#include <bpf/libbpf.h>
#include <bpf/bpf.h>

#define BLOCK_MAP_PATH "/sys/fs/bpf/blocked_ips"
#define ALLOW_MAP_PATH "/sys/fs/bpf/allowed_ips"

#define VALUE_PRESENT 1

static struct firewall_bpf *skel = NULL;
static struct bpf_link *xdp_link = NULL;

static const char *iface = "enp0s3";

static void print_help(void)
{
    printf("\n");
    printf("eBPF Firewall\n\n");

    printf("Usage:\n");
    printf(" sudo ./fw load\n");
    printf(" sudo ./fw unload\n");
    printf(" sudo ./fw block <ip>\n");
    printf(" sudo ./fw unblock <ip>\n");
    printf(" sudo ./fw allow <ip>\n");
    printf(" sudo ./fw unallow <ip>\n");
    printf(" sudo ./fw status\n");
    printf(" sudo ./fw help\n");
}

int cmd_load(void)
{
    int err;

    skel = firewall_bpf__open();

    if (!skel)
    {
        fprintf(stderr, "Failed to open BPF skeleton\n");
        return 1;
    }

    err = firewall_bpf__load(skel);

    if (err)
    {
        fprintf(stderr, "Failed to load BPF program\n");
        firewall_bpf__destroy(skel);
        skel = NULL;
        return 1;
    }

    printf("Firewall program loaded successfully.\n");

    return 0;
}

int main(int argc, char *argv[])
{
    if (argc < 2)
    {
        print_help();
        return 1;
    }

    if (!strcmp(argv[1], "help"))
    {
        print_help();
        return 0;
    }

    if (!strcmp(argv[1], "load"))
    {
    return cmd_load();
    }

    if (!strcmp(argv[1], "unload"))
    {
        printf("Unloading firewall...\n");
        return 0;
    }

    if (!strcmp(argv[1], "status"))
    {
        printf("Firewall Status\n");
        return 0;
    }

    if (!strcmp(argv[1], "block"))
    {
        if (argc != 3)
        {
            printf("Usage: sudo ./fw block <ip>\n");
            return 1;
        }

        printf("Blocking %s\n", argv[2]);
        return 0;
    }

    if (!strcmp(argv[1], "unblock"))
    {
        if (argc != 3)
        {
            printf("Usage: sudo ./fw unblock <ip>\n");
            return 1;
        }

        printf("Unblocking %s\n", argv[2]);
        return 0;
    }

    if (!strcmp(argv[1], "allow"))
    {
        if (argc != 3)
        {
            printf("Usage: sudo ./fw allow <ip>\n");
            return 1;
        }

        printf("Allowing %s\n", argv[2]);
        return 0;
    }

    if (!strcmp(argv[1], "unallow"))
    {
        if (argc != 3)
        {
            printf("Usage: sudo ./fw unallow <ip>\n");
            return 1;
        }

        printf("Removing %s from allow list\n", argv[2]);
        return 0;
    }

    printf("Unknown command\n");
    print_help();

    return 1;
}
