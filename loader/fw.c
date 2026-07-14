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

static const char *iface = NULL;

int valid_port(int port)
{
    return (port > 0 && port <= 65535);
}

static void print_help(void)
{
    printf("\n");
    printf("=====================================================\n");
    printf("                eBPF XDP Firewall\n");
    printf("=====================================================\n\n");

    printf("USAGE\n");
    printf("  sudo ./fw load [interface]\n");
    printf("  sudo ./fw unload\n");
    printf("  sudo ./fw apply <config-file>\n");
    printf("  sudo ./fw help\n\n");

    printf("IP RULES\n");
    printf("  sudo ./fw block <IPv4-address>\n");
    printf("  sudo ./fw unblock <IPv4-address>\n");
    printf("  sudo ./fw allow <IPv4-address>\n");
    printf("  sudo ./fw unallow <IPv4-address>\n\n");

    printf("TCP PORT RULES\n");
    printf("  sudo ./fw block-tcp <port>\n");
    printf("  sudo ./fw unblock-tcp <port>\n");
    printf("  sudo ./fw allow-tcp <port>\n");
    printf("  sudo ./fw unallow-tcp <port>\n\n");

    printf("UDP PORT RULES\n");
    printf("  sudo ./fw block-udp <port>\n");
    printf("  sudo ./fw unblock-udp <port>\n");
    printf("  sudo ./fw allow-udp <port>\n");
    printf("  sudo ./fw unallow-udp <port>\n\n");

    printf("EXAMPLES\n");
    printf("  sudo ./fw load enp0s3\n");
    printf("  sudo ./fw load eth0\n");
    printf("  sudo ./fw block 192.168.1.100\n");
    printf("  sudo ./fw allow 192.168.1.50\n");
    printf("  sudo ./fw block-tcp 80\n");
    printf("  sudo ./fw allow-tcp 22\n");
    printf("  sudo ./fw block-udp 53\n");
    printf("  sudo ./fw apply config/firewall.conf\n\n");

    printf("=====================================================\n");
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
    fprintf(stderr,
            "Error: Network interface '%s' not found.\n",
            iface);

    firewall_bpf__destroy(skel);
    skel = NULL;

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
        fprintf(stderr,
        "Error: Invalid IPv4 address '%s'.\n",
        ip_str);
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

        if (process_config_line(line, line_no) != 0)
        {
            fprintf(stderr,
                    "Configuration contains errors.\n");
        }
    }

    fclose(fp);

    printf("\nConfiguration applied successfully.\n");

    return 0;
}

static int process_config_line(char *line, int line_no)
{
    char *key;
    char *value;

    line[strcspn(line, "\n")] = '\0';

    if (strlen(line) == 0)
        return 0;

    if (line[0] == '#')
        return 0;

    key = strtok(line, "=");
    value = strtok(NULL, "=");

    if (!key || !value)
    {
        printf("Line %d: Invalid format\n", line_no);
        return -1;
    }

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

    else if (!strcmp(key, "block_tcp"))
    {
        int port = atoi(value);

        if (!valid_port(port))
        {
            fprintf(stderr,
            "Line %d: Invalid TCP port '%s'\n",
            line_no,
            value);
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
            fprintf(stderr,
           "Line %d: Invalid TCP port '%s'\n",
            line_no,
            value);
            return -1;
        }

        if (update_port_map(ALLOW_TCP_MAP_PATH, port, 1) == 0)
            printf("Allowed TCP Port %d\n", port);
        else
            printf("Failed to allow TCP Port %d\n", port);
    }

    else if (!strcmp(key, "block_udp"))
    {
        int port = atoi(value);

        if (!valid_port(port))
        {
            fprintf(stderr,
           "Line %d: Invalid UDP port '%s'\n",
            line_no,
            value);
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
            fprintf(stderr,
            "Line %d: Invalid UDP port '%s'\n",
            line_no,
            value);
            return -1;
        }

        if (update_port_map(ALLOW_UDP_MAP_PATH, port, 1) == 0)
            printf("Allowed UDP Port %d\n", port);
        else
            printf("Failed to allow UDP Port %d\n", port);
    }

    else
    {
        fprintf(stderr,
        "Line %d: Unknown directive '%s'\n",
        line_no,
        key);
    }

    return 0;
}

int cmd_unload(void)
{
    int ifindex = if_nametoindex(iface);

    if (!ifindex)
    {
        fprintf(stderr, "Invalid interface %s\n", iface);
        return 1;
    }

    int err = bpf_xdp_detach(ifindex, XDP_FLAGS_UPDATE_IF_NOEXIST, NULL);

    if (err)
    {
        fprintf(stderr, "Failed to detach XDP from %s\n", iface);
        return 1;
    }

    printf("Firewall detached from %s successfully.\n", iface);

    return 0;
}

int main(int argc, char *argv[])
{
    if (iface == NULL)
       iface = "enp0s3";
       
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
        if (argc >= 3)
        iface = argv[2];
         return cmd_load();
    }

    if (!strcmp(argv[1], "unload"))
    {
        return cmd_unload();
    }
    
    if (!strcmp(argv[1], "apply"))
    {
    if (argc != 3)
    {
        fprintf(stderr,
        "Error: Missing configuration file.\n"
        "Usage: sudo ./fw apply <config-file>\n");
        return 1;
    }

    return apply_config(argv[2]);
    }

    if (!strcmp(argv[1], "block"))
    {
        if (argc != 3)
        {
             fprintf(stderr,
            "Error: Missing IP address.\n"
            "Usage: sudo ./fw block <IPv4-address>\n");
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
            fprintf(stderr,
            "Error: Missing IP address.\n"
            "Usage: sudo ./fw unblock <IPv4-address>\n");
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
            fprintf(stderr,
            "Error: Missing IP address.\n"
            "Usage: sudo ./fw allow <IPv4-address>\n");
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
            fprintf(stderr,
            "Error: Missing IP address.\n"
            "Usage: sudo ./fw unallow <IPv4-address>\n");
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

    if (!strcmp(argv[1], "block-tcp"))
    {
        if (argc != 3)
        {
            fprintf(stderr,
            "Error: Missing TCP port.\n"
            "Usage: sudo ./fw block-tcp <port>\n");
            return 1;
        }

        int port = atoi(argv[2]);

        if (!valid_port(port))
        {
            fprintf(stderr,
            "Error: Invalid port %d.\n"
            "Valid range is 1-65535.\n",
            port);
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
            fprintf(stderr,
            "Error: Missing TCP port.\n"
            "Usage: sudo ./fw unblock-tcp <port>\n");
            return 1;
        }

        int port = atoi(argv[2]);

        if (!valid_port(port))
        {
            fprintf(stderr,
            "Error: Invalid port %d.\n"
            "Valid range is 1-65535.\n",
            port);
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
            fprintf(stderr,
            "Error: Missing TCP port.\n"
            "Usage: sudo ./fw allow-tcp <port>\n");
            return 1;
        }

        int port = atoi(argv[2]);

        if (!valid_port(port))
        {
            fprintf(stderr,
            "Error: Invalid port %d.\n"
            "Valid range is 1-65535.\n",
            port);
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
            fprintf(stderr,
            "Error: Missing TCP port.\n"
            "Usage: sudo ./fw unallow-tcp <port>\n");
            return 1;
        }

        int port = atoi(argv[2]);

        if (!valid_port(port))
        {
            fprintf(stderr,
            "Error: Invalid port %d.\n"
            "Valid range is 1-65535.\n",
            port);
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

    if (!strcmp(argv[1], "block-udp"))
    {
        if (argc != 3)
        {
            fprintf(stderr,
            "Error: Missing UDP port.\n"
            "Usage: sudo ./fw block-udp <port>\n");
            return 1;
        }

        int port = atoi(argv[2]);

        if (!valid_port(port))
        {
            fprintf(stderr,
            "Error: Invalid port %d.\n"
            "Valid range is 1-65535.\n",
            port);
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
            fprintf(stderr,
           "Error: Missing UDP port.\n"
           "Usage: sudo ./fw unblock-udp <port>\n");
            return 1;
        }

        int port = atoi(argv[2]);

        if (!valid_port(port))
        {
            fprintf(stderr,
            "Error: Invalid port %d.\n"
            "Valid range is 1-65535.\n",
            port);
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
            fprintf(stderr,
            "Error: Missing UDP port.\n"
            "Usage: sudo ./fw allow-udp <port>\n");
            return 1;
        }

        int port = atoi(argv[2]);

        if (!valid_port(port))
        {
            fprintf(stderr,
            "Error: Invalid port %d.\n"
            "Valid range is 1-65535.\n",
            port);
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
            fprintf(stderr,
           "Error: Missing UDP port.\n"
           "Usage: sudo ./fw unallow-udp <port>\n");
            return 1;
        }

        int port = atoi(argv[2]);

        if (!valid_port(port))
        {
            fprintf(stderr,
            "Error: Invalid port %d.\n"
            "Valid range is 1-65535.\n",
            port);
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

    fprintf(stderr,
        "Error: Unknown command '%s'\n\n",
        argv[1]);

print_help();

return 1;
}
