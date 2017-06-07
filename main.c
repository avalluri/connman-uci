#include <stdio.h>
#include <getopt.h>

#include <libubox/uloop.h>
#include <libubox/usock.h>

#include "log.h"
#include "uci_.h"
#include "ubus.h"

static
void print_usage(const char *exe) {
    fprintf(stderr, "Usage : %s [<options>]\n"
            "Options:\n"
            "   -s <socket-path> usbus socket to connect\n"
            "   -u <config-dir>  Location of UCI configuration default /etc/config.\n"
            "   -c <config-dir>  Location of connman configuration to place, default /var/lib/connman/.\n"
            "   -v               Increase verbosity, can be used more than once.\n"
            "   -h               Print this help text\n"
            "\n", exe);
}

int main(int argc, char **argv)
{
    char *ubus_socket = NULL;
    char *connman_dir = NULL;
    char *uci_dir = NULL;
    char ch;
    enum LogLevel verbose_level = LOG_ERR;



    ubus_socket = getenv("UBUS_SOCKET");

    while ((ch = getopt(argc, argv, "s:u:c:vh")) != -1) {
        switch(ch) {
        case 's':
            ubus_socket = optarg;
            break;
        case 'u':
            uci_dir = optarg;
            break;
        case 'c':
            connman_dir = optarg;
            break;
        case 'v':
            verbose_level++;
            break;
        case 'h':
            print_usage(argv[0]);
            return 0;
            break;
        default:
            WARN("Ignoring invalid argument '%c'", ch);
            break;
        }
    }

    uloop_init();
    __log_init(verbose_level);
    __ubus_init(ubus_socket);
    __uci_init(uci_dir,connman_dir);

    uloop_run();

    INFO("Cleaning up...");

    __ubus_cleanup();
    __uci_cleanup();

    uloop_done();

    return 0;
}
