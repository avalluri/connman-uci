#include <libubox/blobmsg.h>
#include <uci_blob.h>

#include "interface.h"
#include "gutils.h"
#include "log.h"

enum {
    IFACE_ATTR_INTERFACE,
    IFACE_ATTR_ENABLED,
    IFACE_ATTR_IFNAME,
    IFACE_ATTR_PROTO,
    IFACE_ATTR_TYPE,
    IFACE_ATTR_STP,
    IFACE_ATTR_BRIDGE_EMPTY,
    IFACE_ATTR_IGMP_SNOOPING,
    IFACE_ATTR_MACADDR,
    IFACE_ATTR_MTU,
    IFACE_ATTR_AUTO,
    IFACE_ATTR_IPV6,
    IFACE_ATTR_FORCE_LINK,
    IFACE_ATTR_IP4TABLE,
    IFACE_ATTR_IP6TABLE,
    IFACE_ATTR_BROADCAST,
    IFACE_ATTR_DNS,
    IFACE_ATTR_METRIC,
    IFACE_ATTR_NETMASK,
    IFACE_ATTR_GATEWAY,
    IFACE_ATTR_IPADDR,
    IFACE_ATTR_IP6ADDR,
    IFACE_ATTR_IP6GW,
    IFACE_ATTR_IP6PREFIX,
    IFACE_ATTR_IP6HINT,
    IFACE_ATTR_IP6CLASS,
    IFACE_ATTR_IP6ASSIGN,
    IFACE_ATTR_IP6IFACEID,
    IFACE_ATTR_DNS_SEARCH,

    IFACE_ATTR_HOSTNAME,
    IFACE_ATTR_CLIENTID,
    IFACE_ATTR_VENDORID,
    IFACE_ATTR_PEERDNS,
    IFACE_ATTR_DEFAULTROUTE,
    IFACE_ATTR_CUSTOMROUTES,
    IFACE_ATTR_CLASSLESSROUTE,
    IFACE_ATTR_REQOPTS,
    IFACE_ATTR_SENDOPTS,
    IFACE_ATTR_ZONE,

    IFACE_ATTR_MAX
};

static
const struct blobmsg_policy iface_attrs[IFACE_ATTR_MAX] = {
    // alias
    [IFACE_ATTR_INTERFACE] = { .name = "interface", .type = BLOBMSG_TYPE_STRING },

    // common
    [IFACE_ATTR_IFNAME] = { .name = "ifname", .type = BLOBMSG_TYPE_STRING },
    [IFACE_ATTR_PROTO] = { .name = "proto", .type = BLOBMSG_TYPE_STRING },
    [IFACE_ATTR_TYPE] = { .name = "type", .type = BLOBMSG_TYPE_STRING },
    [IFACE_ATTR_STP] = { .name = "stp", .type = BLOBMSG_TYPE_BOOL },
    [IFACE_ATTR_BRIDGE_EMPTY] = { .name = "bridge_empty", .type = BLOBMSG_TYPE_BOOL },
    [IFACE_ATTR_IGMP_SNOOPING] = { .name = "igmp_snooping", .type = BLOBMSG_TYPE_BOOL },
    [IFACE_ATTR_MACADDR] = {.name = "macaddr", .type = BLOBMSG_TYPE_STRING },
    [IFACE_ATTR_MTU] = { .name = "mtu", .type = BLOBMSG_TYPE_INT32 },
    [IFACE_ATTR_AUTO] = { .name = "auto", .type = BLOBMSG_TYPE_BOOL },
    [IFACE_ATTR_IPV6] = { .name = "ipv6", .type = BLOBMSG_TYPE_BOOL },
    [IFACE_ATTR_FORCE_LINK] = { .name = "force_link", .type = BLOBMSG_TYPE_BOOL },
    [IFACE_ATTR_ENABLED] = { .name = "enabled", .type = BLOBMSG_TYPE_BOOL },
    [IFACE_ATTR_IP4TABLE] = { .name = "ip4table", .type = BLOBMSG_TYPE_STRING },
    [IFACE_ATTR_IP6TABLE] = { .name = "ip6table", .type = BLOBMSG_TYPE_STRING },

    // static + dhcp
    [IFACE_ATTR_IPADDR] = { .name = "ipaddr", .type = BLOBMSG_TYPE_ARRAY },
    [IFACE_ATTR_BROADCAST] = { .name = "broadcast", .type = BLOBMSG_TYPE_STRING },
    [IFACE_ATTR_DNS] = { .name = "dns", .type = BLOBMSG_TYPE_ARRAY },
    [IFACE_ATTR_METRIC] = { .name = "metric", .type = BLOBMSG_TYPE_INT32 },

    // static
    [IFACE_ATTR_NETMASK] = { .name = "netmask", .type = BLOBMSG_TYPE_STRING },
    [IFACE_ATTR_GATEWAY] = { .name = "gateway", .type = BLOBMSG_TYPE_STRING },
    [IFACE_ATTR_IP6ADDR] = { .name = "ip6addr", .type = BLOBMSG_TYPE_STRING },
    [IFACE_ATTR_IP6GW] = {.name = "ip6gw", .type = BLOBMSG_TYPE_STRING },
    [IFACE_ATTR_IP6PREFIX] = { .name = "ip6prefix", .type = BLOBMSG_TYPE_STRING },
    [IFACE_ATTR_IP6HINT] = { .name = "ip6hint", .type = BLOBMSG_TYPE_STRING },
    [IFACE_ATTR_IP6CLASS] = { .name = "ip6class", .type = BLOBMSG_TYPE_ARRAY },
    [IFACE_ATTR_IP6ASSIGN] = { .name = "ip6assign", .type = BLOBMSG_TYPE_INT32 },
    [IFACE_ATTR_IP6IFACEID] = { .name = "ip6ifaceid", .type = BLOBMSG_TYPE_STRING },
    [IFACE_ATTR_DNS_SEARCH] = { .name = "dns_search", .type = BLOBMSG_TYPE_ARRAY },

    //dhcp
    [IFACE_ATTR_HOSTNAME] = { .name = "hostname", .type = BLOBMSG_TYPE_STRING },
    [IFACE_ATTR_CLIENTID] = { .name = "clientid", .type = BLOBMSG_TYPE_STRING },
    [IFACE_ATTR_VENDORID] = { .name = "vendorid", .type = BLOBMSG_TYPE_STRING },
    [IFACE_ATTR_PEERDNS] = { .name = "peerdns", .type = BLOBMSG_TYPE_BOOL },
    [IFACE_ATTR_DEFAULTROUTE] = { .name = "defaultroute", .type = BLOBMSG_TYPE_BOOL },
    [IFACE_ATTR_CUSTOMROUTES] = { .name = "customroutes", .type = BLOBMSG_TYPE_STRING },
    [IFACE_ATTR_CLASSLESSROUTE] = { .name = "classlessroute", .type = BLOBMSG_TYPE_BOOL },
    [IFACE_ATTR_REQOPTS] = { .name = "reqopts", .type = BLOBMSG_TYPE_STRING },
    [IFACE_ATTR_SENDOPTS] = { .name = "sendopts", .type = BLOBMSG_TYPE_STRING },
    [IFACE_ATTR_ZONE] = { .name = "zone", .type = BLOBMSG_TYPE_STRING },
};

const struct uci_blob_param_list iface_attr_list = {
    .n_params = IFACE_ATTR_MAX,
    .params = iface_attrs
};

struct blob_buf b;

char * blobmsg_list_data(struct blob_attr *list)
{
    struct blob_attr *tmp;
    int len, i;
    char *str = NULL;
    char **str_list = g_alloc(char *, blobmsg_data_len(list));

    i = 0;
    blobmsg_for_each_attr(tmp, list, len) {
        if (blobmsg_type(tmp) != BLOBMSG_TYPE_STRING ||
            !blobmsg_check_attr(tmp, NULL))
            continue;

        str_list[i++] = blobmsg_data(tmp);
    }

    str = g_strv_join((const char **)str_list, ",");

    free(str_list);

    return str;
}

struct interface* interface_new(const char *name, struct blob_attr *tb[])
{
    struct interface *iface = NULL;

    iface = g_alloc(struct interface, 1);

    iface->ref_count++;

    iface->name = g_strdup(name);
    DBG("Interface: %s", iface->name);
    if (tb[IFACE_ATTR_IFNAME]) iface->name = g_strdup(blobmsg_data(tb[IFACE_ATTR_IFNAME]));
    if (tb[IFACE_ATTR_PROTO]) iface->proto = g_strdup(blobmsg_data(tb[IFACE_ATTR_PROTO]));
    if (tb[IFACE_ATTR_MACADDR]) iface->macaddr = g_strdup(blobmsg_data(tb[IFACE_ATTR_MACADDR]));

    iface->autostart = blobmsg_get_bool_default(tb[IFACE_ATTR_AUTO], true);
    iface->force_link = blobmsg_get_bool_default(tb[IFACE_ATTR_FORCE_LINK], false);
    iface->no_defaultroute = !blobmsg_get_bool_default(tb[IFACE_ATTR_DEFAULTROUTE], true);
    iface->no_dns = !blobmsg_get_bool_default(tb[IFACE_ATTR_PEERDNS], true);
    iface->enabled = blobmsg_get_bool_default(tb[IFACE_ATTR_ENABLED], true);
    iface->ipv6 = blobmsg_get_bool_default(tb[IFACE_ATTR_IPV6], true);
    iface->classlessroute = blobmsg_get_bool_default(tb[IFACE_ATTR_CLASSLESSROUTE], true);

    if (tb[IFACE_ATTR_IPADDR]) iface->ipaddr = g_strdup(blobmsg_data(tb[IFACE_ATTR_IPADDR]));
    if (tb[IFACE_ATTR_NETMASK]) iface->netmask = g_strdup(blobmsg_data(tb[IFACE_ATTR_NETMASK]));
    if (tb[IFACE_ATTR_GATEWAY]) iface->gateway = g_strdup(blobmsg_data(tb[IFACE_ATTR_GATEWAY]));
    if (tb[IFACE_ATTR_IP6ADDR]) iface->ip6addr = g_strdup(blobmsg_data(tb[IFACE_ATTR_IP6ADDR]));
    if (tb[IFACE_ATTR_IP6GW]) iface->ip6gw = g_strdup(blobmsg_data(tb[IFACE_ATTR_IP6GW]));
    if (tb[IFACE_ATTR_IP6HINT]) iface->ip6hint = g_strdup(blobmsg_data(tb[IFACE_ATTR_IP6HINT]));
    if (tb[IFACE_ATTR_IP6ASSIGN]) iface->ip6assign = blobmsg_get_u32(tb[IFACE_ATTR_IP6ASSIGN]);
    if (tb[IFACE_ATTR_HOSTNAME]) iface->hostname = g_strdup(blobmsg_data(tb[IFACE_ATTR_HOSTNAME]));
    if (tb[IFACE_ATTR_CLIENTID]) iface->clientid = g_strdup(blobmsg_data(tb[IFACE_ATTR_CLIENTID]));
    if (tb[IFACE_ATTR_VENDORID]) iface->vendorid = g_strdup(blobmsg_data(tb[IFACE_ATTR_VENDORID]));
    if (tb[IFACE_ATTR_METRIC]) iface->metric = blobmsg_get_u32(tb[IFACE_ATTR_METRIC]);

    iface->dns_list = tb[IFACE_ATTR_DNS] ?  blobmsg_list_data(tb[IFACE_ATTR_DNS]) : NULL;
    iface->dns_search_list = tb[IFACE_ATTR_DNS_SEARCH] ?  blobmsg_list_data(tb[IFACE_ATTR_DNS_SEARCH]) : NULL;

    return iface;
}

struct interface* parse_interface(struct uci_section *s)
{
    struct blob_attr *tb[IFACE_ATTR_MAX] = { 0 };

    blob_buf_init(&b, 0);

    uci_to_blob(&b, s, &iface_attr_list);

    blobmsg_parse(iface_attrs, IFACE_ATTR_MAX, tb, blob_data(b.head), blob_len(b.head));

    return interface_new(s->e.name, tb);
}

void interface_unref(struct interface *iface)
{
    if (!iface) return;
    if (--iface->ref_count) return;

    g_free(iface->name);
    g_free(iface->ifname);
    g_free(iface->hostname);
    g_free(iface->dns_list);
    g_free(iface->dns_search_list);
    g_free(iface);
}

int interface_dump_status(struct interface *iface, struct blob_buf *b)
{
    if (!iface || !b) return -1;

    blobmsg_add_string(b, "interface", iface->name);
    blobmsg_add_u8(b, "up", iface->state == 1);
    blobmsg_add_u8(b, "available", iface->enabled);
    blobmsg_add_u8(b, "autostart", iface->autostart);
    //blobmsg_add_u8(b, "dynamic", iface->dynamic);
    blobmsg_add_string(b, "proto", iface->proto);

    return 0;
}
