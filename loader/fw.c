#include "../bpf/firewall.skel.h"
#include <linux/if_link.h>
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

#define BLOCK_TCP_MAP_PATH "/sys/fs/bpf/blocked_tcp_ports"
#define ALLOW_TCP_MAP_PATH "/sys/fs/bpf/allowed_tcp_ports"

#define BLOCK_UDP_MAP_PATH "/sys/fs/bpf/blocked_udp_ports"
#define ALLOW_UDP_MAP_PATH "/sys/fs/bpf/allowed_udp_ports"

#define VALUE_PRESENT 1

static struct firewall_bpf *skel = NULL;

static const char *iface = "enp0s3";

/* ---------------------- PORT VALIDATION ---------------------- */

int valid_port(int port)
{
    return (port > 0 && port <= 65535);
}

/* ---------------------- HELP ---------------------- */

static void print_help(void)
{
    printf("\n");
    printf("========== eBPF Firewall ==========\n\n");

    printf("Usage:\n");
    printf(" sudo ./fw load\n");
    printf(" sudo ./fw unload\n");
    printf(" sudo ./fw status\n\n");
    printf(" sudo ./fw apply <config-file>\n\n");

    printf("IP Commands:\n");
    printf(" sudo ./fw block <ip>\n");
    printf(" sudo ./fw unblock <ip>\n");
    printf(" sudo ./fw allow <ip>\n");
    printf(" sudo ./fw unallow <ip>\n\n");

    printf("TCP Commands:\n");
    printf(" sudo ./fw block-tcp <port>\n");
    printf(" sudo ./fw unblock-tcp <port>\n");
    printf(" sudo ./fw allow-tcp <port>\n");
    printf(" sudo ./fw unallow-tcp <port>\n\n");

    printf("UDP Commands:\n");
    printf(" sudo ./fw block-udp <port>\n");
    printf(" sudo ./fw unblock-udp <port>\n");
    printf(" sudo ./fw allow-udp <port>\n");
    printf(" sudo ./fw unallow-udp <port>\n\n");

    printf(" sudo ./fw help\n");
}

/* ---------------------- LOAD ---------------------- */

int cmd_load(void)
{
    int err;

    skel = firewall_bpf__open();
    if (!skel)
    {
        fprintf(stderr, "Failed to open BPF skeleton\n");
        return 1;
    }
    
    /* Pin all maps */

    bpf_map__set_pin_path(skel->maps.blocked_ips,
                          "/sys/fs/bpf/blocked_ips");

    bpf_map__set_pin_path(skel->maps.allowed_ips,
                          "/sys/fs/bpf/allowed_ips");

    bpf_map__set_pin_path(skel->maps.blocked_tcp_ports,
                          "/sys/fs/bpf/blocked_tcp_ports");

    bpf_map__set_pin_path(skel->maps.allowed_tcp_ports,
                          "/sys/fs/bpf/allowed_tcp_ports");

    bpf_map__set_pin_path(skel->maps.blocked_udp_ports,
                          "/sys/fs/bpf/blocked_udp_ports");

    bpf_map__set_pin_path(skel->maps.allowed_udp_ports,
                          "/sys/fs/bpf/allowed_udp_ports");

    bpf_map__set_pin_path(skel->maps.firewall_stats,
                          "/sys/fs/bpf/firewall_stats");
                          
    err = firewall_bpf__load(skel);
    if (err)
    {
        fprintf(stderr, "Failed to load BPF program\n");
        firewall_bpf__destroy(skel);
        skel = NULL;
        return 1;
    }

int ifindex = if_nametoindex(iface);

if (!ifindex)
{
    fprintf(stderr, "Invalid interface %s\n", iface);
    firewall_bpf__destroy(skel);
    return 1;
}

int prog_fd = bpf_program__fd(skel->progs.firewall);

err = bpf_xdp_attach(ifindex, prog_fd, XDP_FLAGS_UPDATE_IF_NOEXIST, NULL);

if (err)
{
    fprintf(stderr, "Failed to attach XDP to %s\n", iface);
    firewall_bpf__destroy(skel);
    return 1;
}

    printf("Firewall attached to %s successfully.\n", iface);

    return 0;
}

static int open_map(const char *path)
{
    int fd = bpf_obj_get(path);

    if (fd < 0)
        fprintf(stderr, "Failed to open map: %s\n", path);

    return fd;
}

static int update_ip_map(const char *path, const char *ip_str, int add)
{
    int fd = open_map(path);

    if (fd < 0)
        return -1;

    __u32 ip;

    if (inet_pton(AF_INET, ip_str, &ip) != 1)
    {
        printf("Invalid IPv4 address: %s\n", ip_str);
        close(fd);
        return -1;
    }

    __u8 value = VALUE_PRESENT;

    int err;

    if (add)
        err = bpf_map_update_elem(fd, &ip, &value, BPF_ANY);
    else
        err = bpf_map_delete_elem(fd, &ip);

    close(fd);

    return err;
}

static int update_port_map(const char *path, int port, int add)
{
    int fd = open_map(path);

    if (fd < 0)
        return -1;

    __u16 key = (__u16)port;
    __u8 value = VALUE_PRESENT;

    int err;

    if (add)
        err = bpf_map_update_elem(fd, &key, &value, BPF_ANY);
    else
        err = bpf_map_delete_elem(fd, &key);

    close(fd);

    return err;
}

static int apply_config(const char *filename);
static int process_config_line(char *line, int line_no);

static int apply_config(const char *filename)
{
    FILE *fp;
    char line[256];
    int line_no = 0;

    fp = fopen(filename, "r");

    if (!fp)
    {
        perror("Failed to open config file");
        return 1;
    }

    printf("Applying configuration from %s\n\n", filename);

    while (fgets(line, sizeof(line), fp))
    {
        line_no++;

        process_config_line(line, line_no);
    }

    fclose(fp);

    printf("\nConfiguration applied successfully.\n");

    return 0;
}

static int process_config_line(char *line, int line_no)
{
    char *key;
    char *value;

    /* Remove newline */
    line[strcspn(line, "\n")] = '\0';

    /* Skip empty lines */
    if (strlen(line) == 0)
        return 0;

    /* Skip comments */
    if (line[0] == '#')
        return 0;

    /* Find '=' */
    key = strtok(line, "=");
    value = strtok(NULL, "=");

    if (!key || !value)
    {
        printf("Line %d: Invalid format\n", line_no);
        return -1;
    }

    /* ---------- IP Rules ---------- */

    if (!strcmp(key, "block_ip"))
    {
        if (update_ip_map(BLOCK_MAP_PATH, value, 1) == 0)
            printf("Blocked IP %s\n", value);
        else
            printf("Failed to block IP %s\n", value);
    }

    else if (!strcmp(key, "allow_ip"))
    {
        if (update_ip_map(ALLOW_MAP_PATH, value, 1) == 0)
            printf("Allowed IP %s\n", value);
        else
            printf("Failed to allow IP %s\n", value);
    }

    /* ---------- TCP Rules ---------- */

    else if (!strcmp(key, "block_tcp"))
    {
        int port = atoi(value);

        if (!valid_port(port))
        {
            printf("Line %d: Invalid TCP port\n", line_no);
            return -1;
        }

        if (update_port_map(BLOCK_TCP_MAP_PATH, port, 1) == 0)
            printf("Blocked TCP Port %d\n", port);
        else
            printf("Failed to block TCP Port %d\n", port);
    }

    else if (!strcmp(key, "allow_tcp"))
    {
        int port = atoi(value);

        if (!valid_port(port))
        {
            printf("Line %d: Invalid TCP port\n", line_no);
            return -1;
        }

        if (update_port_map(ALLOW_TCP_MAP_PATH, port, 1) == 0)
            printf("Allowed TCP Port %d\n", port);
        else
            printf("Failed to allow TCP Port %d\n", port);
    }

    /* ---------- UDP Rules ---------- */

    else if (!strcmp(key, "block_udp"))
    {
        int port = atoi(value);

        if (!valid_port(port))
        {
            printf("Line %d: Invalid UDP port\n", line_no);
            return -1;
        }

        if (update_port_map(BLOCK_UDP_MAP_PATH, port, 1) == 0)
            printf("Blocked UDP Port %d\n", port);
        else
            printf("Failed to block UDP Port %d\n", port);
    }

    else if (!strcmp(key, "allow_udp"))
    {
        int port = atoi(value);

        if (!valid_port(port))
        {
            printf("Line %d: Invalid UDP port\n", line_no);
            return -1;
        }

        if (update_port_map(ALLOW_UDP_MAP_PATH, port, 1) == 0)
            printf("Allowed UDP Port %d\n", port);
        else
            printf("Failed to allow UDP Port %d\n", port);
    }

    else
    {
        printf("Line %d: Unknown directive '%s'\n", line_no, key);
    }

    return 0;
}

int main(int argc, char *argv[])
{
    if (argc < 2)
    {
        print_help();
        return 1;
    }

    /* HELP */

    if (!strcmp(argv[1], "help"))
    {
        print_help();
        return 0;
    }

    /* LOAD */

    if (!strcmp(argv[1], "load"))
    {
        return cmd_load();
    }

    /* UNLOAD */

    if (!strcmp(argv[1], "unload"))
    {
        printf("Unloading firewall...\n");
        return 0;
    }

    /* STATUS */

    if (!strcmp(argv[1], "status"))
    {
        printf("Firewall Status\n");
        return 0;
    }
    
    if (!strcmp(argv[1], "apply"))
    {
    if (argc != 3)
    {
        printf("Usage: sudo ./fw apply <config-file>\n");
        return 1;
    }

    return apply_config(argv[2]);
    }
    /* ---------------- IP COMMANDS ---------------- */

    if (!strcmp(argv[1], "block"))
    {
        if (argc != 3)
        {
            printf("Usage: sudo ./fw block <ip>\n");
            return 1;
        }

       if (update_ip_map(BLOCK_MAP_PATH, argv[2], 1) == 0)
       printf("Blocked IP %s\n", argv[2]);
        else
        {
            printf("Failed to block IP %s\n", argv[2]);
            return 1;
        }

         return 0;
    }

    if (!strcmp(argv[1], "unblock"))
    {
        if (argc != 3)
        {
            printf("Usage: sudo ./fw unblock <ip>\n");
            return 1;
        }

       if (update_ip_map(BLOCK_MAP_PATH, argv[2], 0) == 0)
       printf("Unblocked IP %s\n", argv[2]);
        else
        {
            printf("Failed to unblock IP %s\n", argv[2]);
            return 1;
        }

        return 0;
    }

    if (!strcmp(argv[1], "allow"))
    {
        if (argc != 3)
        {
            printf("Usage: sudo ./fw allow <ip>\n");
            return 1;
        }

        if (update_ip_map(ALLOW_MAP_PATH, argv[2], 1) == 0)
        printf("Allowed IP %s\n", argv[2]);
        else
        {
            printf("Failed to allow IP %s\n", argv[2]);
            return 1;
        }

        return 0;
    }

    if (!strcmp(argv[1], "unallow"))
    {
        if (argc != 3)
        {
            printf("Usage: sudo ./fw unallow <ip>\n");
            return 1;
        }

       if (update_ip_map(ALLOW_MAP_PATH, argv[2], 0) == 0)
       printf("Removed IP %s from allow list\n", argv[2]);
       else
       {
           printf("Failed to remove IP %s\n", argv[2]);
           return 1;
       }

      return 0;
    }

    /* ---------------- TCP COMMANDS ---------------- */

    if (!strcmp(argv[1], "block-tcp"))
    {
        if (argc != 3)
        {
            printf("Usage: sudo ./fw block-tcp <port>\n");
            return 1;
        }

        int port = atoi(argv[2]);

        if (!valid_port(port))
        {
            printf("Invalid Port\n");
            return 1;
        }

        if (update_port_map(BLOCK_TCP_MAP_PATH, port, 1) == 0)
        printf("Blocked TCP Port %d\n", port);
        else
        {
            printf("Failed to block TCP Port %d\n", port);
            return 1;
        }

        return 0;
    }

    if (!strcmp(argv[1], "unblock-tcp"))
    {
        if (argc != 3)
        {
            printf("Usage: sudo ./fw unblock-tcp <port>\n");
            return 1;
        }

        int port = atoi(argv[2]);

        if (!valid_port(port))
        {
            printf("Invalid Port\n");
            return 1;
        }

        if (update_port_map(BLOCK_TCP_MAP_PATH, port, 0) == 0)
        printf("Unblocked TCP Port %d\n", port);
        else
        {
            printf("Failed to unblock TCP Port %d\n", port);
            return 1;
        }

        return 0;
    }

    if (!strcmp(argv[1], "allow-tcp"))
    {
        if (argc != 3)
        {
            printf("Usage: sudo ./fw allow-tcp <port>\n");
            return 1;
        }

        int port = atoi(argv[2]);

        if (!valid_port(port))
        {
            printf("Invalid Port\n");
            return 1;
        }

       if (update_port_map(ALLOW_TCP_MAP_PATH, port, 1) == 0)
       printf("Allowed TCP Port %d\n", port);
      else
      {
        printf("Failed to allow TCP Port %d\n", port);
           return 1;
      }

      return 0;
    }

    if (!strcmp(argv[1], "unallow-tcp"))
    {
        if (argc != 3)
        {
            printf("Usage: sudo ./fw unallow-tcp <port>\n");
            return 1;
        }

        int port = atoi(argv[2]);

        if (!valid_port(port))
        {
            printf("Invalid Port\n");
            return 1;
        }

        if (update_port_map(ALLOW_TCP_MAP_PATH, port, 0) == 0)
        printf("Removed TCP Port %d from allow list\n", port);
        else
        {
            printf("Failed to remove TCP Port %d from allow list\n", port);
            return 1;
        }

        return 0;
    }

    /* ---------------- UDP COMMANDS ---------------- */

    if (!strcmp(argv[1], "block-udp"))
    {
        if (argc != 3)
        {
            printf("Usage: sudo ./fw block-udp <port>\n");
            return 1;
        }

        int port = atoi(argv[2]);

        if (!valid_port(port))
        {
            printf("Invalid Port\n");
            return 1;
        }

       if (update_port_map(BLOCK_UDP_MAP_PATH, port, 1) == 0)
       printf("Blocked UDP Port %d\n", port);
       else
       {
           printf("Failed to block UDP Port %d\n", port);
           return 1;
       }

       return 0;
    }

    if (!strcmp(argv[1], "unblock-udp"))
    {
        if (argc != 3)
        {
            printf("Usage: sudo ./fw unblock-udp <port>\n");
            return 1;
        }

        int port = atoi(argv[2]);

        if (!valid_port(port))
        {
            printf("Invalid Port\n");
            return 1;
        }

        if (update_port_map(BLOCK_UDP_MAP_PATH, port, 0) == 0) 
        printf("Unblocked UDP Port %d\n", port);
        else
        {
            printf("Failed to unblock UDP Port %d\n", port);
            return 1;
        }

         return 0;
    }

    if (!strcmp(argv[1], "allow-udp"))
    {
        if (argc != 3)
        {
            printf("Usage: sudo ./fw allow-udp <port>\n");
            return 1;
        }

        int port = atoi(argv[2]);

        if (!valid_port(port))
        {
            printf("Invalid Port\n");
            return 1;
        }

        if (update_port_map(ALLOW_UDP_MAP_PATH, port, 1) == 0)
        printf("Allowed UDP Port %d\n", port);
        else
        {
            printf("Failed to allow UDP Port %d\n", port);
            return 1;
        }

        return 0;
    }

    if (!strcmp(argv[1], "unallow-udp"))
    {
        if (argc != 3)
        {
            printf("Usage: sudo ./fw unallow-udp <port>\n");
            return 1;
        }

        int port = atoi(argv[2]);

        if (!valid_port(port))
        {
            printf("Invalid Port\n");
            return 1;
        }

        if (update_port_map(ALLOW_UDP_MAP_PATH, port, 0) == 0)
        printf("Removed UDP Port %d from allow list\n", port);
        else
        {
            printf("Failed to remove UDP Port %d from allow list\n", port);
            return 1;
        }

        return 0;
    }

    printf("Unknown command\n");
    print_help();

    return 1;
}
