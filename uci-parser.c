#include <uci.h>
#include "uci-parser.h"
#include "interface.h"
#include "gutils.h"

static struct uci_context *ctx;
static struct uci_package *network;
static struct uci_package *wireless;


int uci_config_parse_network(found_iface_cb_t iface_cb, found_device_cb_t dev_cb, void *data)
{
    struct uci_element *e;
    int ret;

    if (!network) {
        if ((ret = uci_load(ctx, "network", &network))) {
            return ret;
        }
    }

    if (!iface_cb && !dev_cb) return 0;

    uci_foreach_element(&network->sections, e) {
        struct uci_section *s = uci_to_section(e);

        if (!g_strcmp(s->type, "interface") && g_strcmp(s->e.name, "loopback") && iface_cb) {
            iface_cb(parse_interface(s), data);
        } else if (!g_strcmp(s->type, "device") && dev_cb) {
            dev_cb(NULL, data);
        }
    }

    return 0;
}

int uci_config_init(const char *config_path)
{
    int ret = 0;

    if (!(ctx = uci_alloc_context())) {
        return -1;
    }

    if ((ret = uci_set_confdir(ctx, config_path))) {
        return ret;
    }

    return 0;
}

void uci_config_cleanup()
{
    if (!ctx) return;

    if (network) uci_unload(ctx, network);
    if (wireless) uci_unload(ctx, wireless);
    uci_free_context(ctx);
}
