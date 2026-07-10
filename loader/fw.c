#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void print_help(void)
{
    printf("eBPF Firewall\n\n");

    printf("Usage:\n");
    printf("  sudo ./fw load\n");
    printf("  sudo ./fw unload\n");
    printf("  sudo ./fw block <ip>\n");
    printf("  sudo ./fw unblock <ip>\n");
    printf("  sudo ./fw status\n");
    printf("  sudo ./fw help\n");
}

int cmd_load(void)
{
    printf("Loading firewall...\n");
    return 0;
}

int cmd_unload(void)
{
    printf("Unloading firewall...\n");
    return 0;
}

int cmd_block(char *ip)
{
    printf("Blocking IP: %s\n", ip);
    return 0;
}

int cmd_unblock(char *ip)
{
    printf("Unblocking IP: %s\n", ip);
    return 0;
}

int cmd_status(void)
{
    printf("Firewall Status\n");
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
        return print_help(), 0;

    if (!strcmp(argv[1], "load"))
        return cmd_load();

    if (!strcmp(argv[1], "unload"))
        return cmd_unload();

    if (!strcmp(argv[1], "status"))
        return cmd_status();

    if (!strcmp(argv[1], "block"))
    {
        if (argc != 3)
        {
            printf("Usage: sudo ./fw block <ip>\n");
            return 1;
        }

        return cmd_block(argv[2]);
    }

    if (!strcmp(argv[1], "unblock"))
    {
        if (argc != 3)
        {
            printf("Usage: sudo ./fw unblock <ip>\n");
            return 1;
        }

        return cmd_unblock(argv[2]);
    }

    printf("Unknown command\n");
    print_help();

    return 1;
}
