#include <libubox/blobmsg.h>
#include <uci_blob.h>

#include "interface.h"
#include "gutils.h"
#include "log.h"

/* network: interface */

#define BLOBMSG_POLICY(_n, _t) { .name = _n, .type = BLOBMSG_TYPE_ ## _t }

struct blob_buf b;

enum iface_attrs_t {
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
    [IFACE_ATTR_INTERFACE] = BLOBMSG_POLICY("interface", STRING),

    // common
    [IFACE_ATTR_IFNAME] = BLOBMSG_POLICY("ifname", STRING),
    [IFACE_ATTR_PROTO] = BLOBMSG_POLICY("proto", STRING),
    [IFACE_ATTR_TYPE] = BLOBMSG_POLICY("type",STRING),
    [IFACE_ATTR_STP] = BLOBMSG_POLICY("stp", BOOL),
    [IFACE_ATTR_BRIDGE_EMPTY] = BLOBMSG_POLICY("bridge_empty", BOOL),
    [IFACE_ATTR_IGMP_SNOOPING] = BLOBMSG_POLICY("igmp_snooping", BOOL),
    [IFACE_ATTR_MACADDR] = BLOBMSG_POLICY("macaddr", STRING),
    [IFACE_ATTR_MTU] = BLOBMSG_POLICY("mtu", INT32),
    [IFACE_ATTR_AUTO] = BLOBMSG_POLICY("auto", BOOL),
    [IFACE_ATTR_IPV6] = BLOBMSG_POLICY("ipv6", BOOL),
    [IFACE_ATTR_FORCE_LINK] = BLOBMSG_POLICY("force_link", BOOL),
    [IFACE_ATTR_ENABLED] = BLOBMSG_POLICY("enabled", BOOL),
    [IFACE_ATTR_IP4TABLE] = BLOBMSG_POLICY("ip4table", STRING),
    [IFACE_ATTR_IP6TABLE] = BLOBMSG_POLICY("ip6table", STRING),

    // static + dhcp
    [IFACE_ATTR_IPADDR] = BLOBMSG_POLICY("ipaddr", STRING),
    [IFACE_ATTR_BROADCAST] = BLOBMSG_POLICY("broadcast", STRING),
    [IFACE_ATTR_DNS] = BLOBMSG_POLICY("dns", ARRAY),
    [IFACE_ATTR_METRIC] = BLOBMSG_POLICY("metric", INT32),

    // static
    [IFACE_ATTR_NETMASK] = BLOBMSG_POLICY("netmask", STRING),
    [IFACE_ATTR_GATEWAY] = BLOBMSG_POLICY("gateway", STRING),
    [IFACE_ATTR_IP6ADDR] = BLOBMSG_POLICY("ip6addr", STRING),
    [IFACE_ATTR_IP6GW] = BLOBMSG_POLICY("ip6gw", STRING),
    [IFACE_ATTR_IP6PREFIX] = BLOBMSG_POLICY("ip6prefix", STRING),
    [IFACE_ATTR_IP6HINT] = BLOBMSG_POLICY("ip6hint", STRING),
    [IFACE_ATTR_IP6CLASS] = BLOBMSG_POLICY("ip6class", ARRAY),
    [IFACE_ATTR_IP6ASSIGN] = BLOBMSG_POLICY("ip6assign", STRING),
    [IFACE_ATTR_IP6IFACEID] = BLOBMSG_POLICY("ip6ifaceid", STRING),
    [IFACE_ATTR_DNS_SEARCH] = BLOBMSG_POLICY("dns_search", ARRAY),

    //dhcp
    [IFACE_ATTR_HOSTNAME] = BLOBMSG_POLICY("hostname", STRING),
    [IFACE_ATTR_CLIENTID] = BLOBMSG_POLICY("clientid", STRING),
    [IFACE_ATTR_VENDORID] = BLOBMSG_POLICY("vendorid", STRING),
    [IFACE_ATTR_PEERDNS] = BLOBMSG_POLICY("peerdns", BOOL),
    [IFACE_ATTR_DEFAULTROUTE] = BLOBMSG_POLICY("defaultroute", BOOL),
    [IFACE_ATTR_CUSTOMROUTES] = BLOBMSG_POLICY("customroutes", STRING),
    [IFACE_ATTR_CLASSLESSROUTE] = BLOBMSG_POLICY("classlessroute", BOOL),
    [IFACE_ATTR_REQOPTS] = BLOBMSG_POLICY("reqopts", STRING),
    [IFACE_ATTR_SENDOPTS] = BLOBMSG_POLICY("sendopts", STRING),
    [IFACE_ATTR_ZONE] = BLOBMSG_POLICY("zone", STRING),
};

const struct uci_blob_param_list iface_attr_list = {
    .n_params = IFACE_ATTR_MAX,
    .params = iface_attrs
};

/* wirelss: wifi-iface */
enum wifi_iface_attrs_t {
    WIFACE_ATTR_DEVICE,
    WIFACE_ATTR_MODE,
    WIFACE_ATTR_DISABLED,
    WIFACE_ATTR_SSID,
    WIFACE_ATTR_BSSID,
    WIFACE_ATTR_HIDDEN,
    WIFACE_ATTR_ISOLATE,
    WIFACE_ATTR_WMM,
    WIFACE_ATTR_NETWORK,
    WIFACE_ATTR_ENCRYPTION,
    WIFACE_ATTR_KEY,
    WIFACE_ATTR_KEY1,
    WIFACE_ATTR_KEY2,
    WIFACE_ATTR_KEY3,
    WIFACE_ATTR_KEY4,
    WIFACE_ATTR_MACLIST,
    WIFACE_ATTR_IAPP_INTERFACE,
    WIFACE_ATTR_RSN_PREAUTH,
    WIFACE_ATTR_MAXASSOC,
    WIFACE_ATTR_MACADDR,
    WIFACE_ATTR_WDS,

    WIFACE_ATTR_WPA_SERVER,
    WIFACE_ATTR_WPA_PORT,
    WIFACE_ATTR_WPA_KEY,
    WIFACE_ATTR_WPA_GROUP_REKEY,

    WIFACE_ATTR_WPA_EAP_TYPE,
    WIFACE_ATTR_WPA_AUTH,
    WIFACE_ATTR_WPA_IDENTITY,
    WIFACE_ATTR_WPA_PASSWORD,
    WIFACE_ATTR_WPA_CA_CERT,
    WIFACE_ATTR_WPA_CLIENT_CERT,
    WIFACE_ATTR_WPA_PRIV_KEY,
    WIFACE_ATTR_WPA_PRIV_KEY_PWD,

    WIFACE_ATTR_MAX
};

static
const struct blobmsg_policy wiface_attrs[WIFACE_ATTR_MAX] = {
    [WIFACE_ATTR_DEVICE] = BLOBMSG_POLICY("device", STRING),
    [WIFACE_ATTR_MODE]   = BLOBMSG_POLICY("mode", STRING),
    [WIFACE_ATTR_DISABLED] = BLOBMSG_POLICY("disabled", BOOL),
    [WIFACE_ATTR_SSID]   = BLOBMSG_POLICY("ssid", STRING),
    [WIFACE_ATTR_BSSID]  = BLOBMSG_POLICY("bssid", STRING),
    [WIFACE_ATTR_HIDDEN] = BLOBMSG_POLICY("hidden", BOOL),
    [WIFACE_ATTR_ISOLATE] = BLOBMSG_POLICY("isolate", BOOL),
    [WIFACE_ATTR_WMM]    = BLOBMSG_POLICY("wmm", BOOL),
    [WIFACE_ATTR_NETWORK] = BLOBMSG_POLICY("network", STRING),
    [WIFACE_ATTR_ENCRYPTION] = BLOBMSG_POLICY("encryption", STRING),
    [WIFACE_ATTR_KEY]    = BLOBMSG_POLICY("key", STRING),
    [WIFACE_ATTR_KEY1]   = BLOBMSG_POLICY("key1", STRING),
    [WIFACE_ATTR_KEY2]   = BLOBMSG_POLICY("key2", STRING),
    [WIFACE_ATTR_KEY3]   = BLOBMSG_POLICY("key3", STRING),
    [WIFACE_ATTR_KEY4]   = BLOBMSG_POLICY("key4", STRING),
    [WIFACE_ATTR_MACLIST] = BLOBMSG_POLICY("maclist", ARRAY),
    [WIFACE_ATTR_IAPP_INTERFACE] = BLOBMSG_POLICY("iapp_interface", STRING),
    [WIFACE_ATTR_RSN_PREAUTH] = BLOBMSG_POLICY("rsn_preauth", BOOL),
    [WIFACE_ATTR_MAXASSOC] = BLOBMSG_POLICY("maxassoc", INT32),
    [WIFACE_ATTR_MACADDR] = BLOBMSG_POLICY("macaddr", STRING),
    [WIFACE_ATTR_WDS]    = BLOBMSG_POLICY("wds", BOOL),
    [WIFACE_ATTR_WPA_SERVER] = BLOBMSG_POLICY("server", STRING),
    [WIFACE_ATTR_WPA_PORT] = BLOBMSG_POLICY("port", INT32),
    [WIFACE_ATTR_WPA_KEY] = BLOBMSG_POLICY("key", STRING),
    [WIFACE_ATTR_WPA_GROUP_REKEY] = BLOBMSG_POLICY("wpa_group_rekey", INT32),
    [WIFACE_ATTR_WPA_EAP_TYPE] = BLOBMSG_POLICY("eap_type", STRING),
    [WIFACE_ATTR_WPA_AUTH] = BLOBMSG_POLICY("auth", STRING),
    [WIFACE_ATTR_WPA_IDENTITY] = BLOBMSG_POLICY("identity", STRING),
    [WIFACE_ATTR_WPA_PASSWORD] = BLOBMSG_POLICY("password", STRING),
    [WIFACE_ATTR_WPA_CA_CERT] = BLOBMSG_POLICY("ca_cert", STRING),
    [WIFACE_ATTR_WPA_CLIENT_CERT] = BLOBMSG_POLICY("client_cert", STRING),
    [WIFACE_ATTR_WPA_PRIV_KEY] = BLOBMSG_POLICY("priv_key", STRING),
    [WIFACE_ATTR_WPA_PRIV_KEY_PWD] = BLOBMSG_POLICY("priv_key_pwd", STRING)
};

const struct uci_blob_param_list wiface_attr_list = {
    .n_params = WIFACE_ATTR_MAX,
    .params = wiface_attrs
};

static inline
char *blobmsg_safe_copy(struct blob_attr *attr)
{
    return attr ? g_strdup(blobmsg_data(attr)) : NULL;
}

static
char * blobmsg_list_data(struct blob_attr *list)
{
    struct blob_attr *tmp;
    int len, i;
    char *str = NULL;
    char **str_list = NULL;

    if (!list) return NULL;

    str_list = g_alloc(char *, blobmsg_data_len(list));

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

    DBG("Interface: %s", name);

    iface->name = g_strdup(name);
    iface->ifname = blobmsg_safe_copy(tb[IFACE_ATTR_IFNAME]);
    iface->proto = blobmsg_safe_copy(tb[IFACE_ATTR_PROTO]);
    iface->macaddr = blobmsg_safe_copy(tb[IFACE_ATTR_MACADDR]);

    iface->autostart = blobmsg_get_bool_default(tb[IFACE_ATTR_AUTO], true);
    iface->force_link = blobmsg_get_bool_default(tb[IFACE_ATTR_FORCE_LINK], false);
    iface->no_defaultroute = !blobmsg_get_bool_default(tb[IFACE_ATTR_DEFAULTROUTE], true);
    iface->no_dns = !blobmsg_get_bool_default(tb[IFACE_ATTR_PEERDNS], true);
    iface->enabled = blobmsg_get_bool_default(tb[IFACE_ATTR_ENABLED], true);
    iface->ipv6 = blobmsg_get_bool_default(tb[IFACE_ATTR_IPV6], true);
    iface->classlessroute = blobmsg_get_bool_default(tb[IFACE_ATTR_CLASSLESSROUTE], true);

    iface->ipaddr = blobmsg_safe_copy(tb[IFACE_ATTR_IPADDR]);
    iface->netmask = blobmsg_safe_copy(tb[IFACE_ATTR_NETMASK]);
    iface->gateway = blobmsg_safe_copy(tb[IFACE_ATTR_GATEWAY]);
    iface->ip6addr = blobmsg_safe_copy(tb[IFACE_ATTR_IP6ADDR]);
    iface->ip6gw = blobmsg_safe_copy(tb[IFACE_ATTR_IP6GW]);
    iface->ip6hint = blobmsg_safe_copy(tb[IFACE_ATTR_IP6HINT]);
    iface->ip6assign = blobmsg_safe_copy(tb[IFACE_ATTR_IP6ASSIGN]);
    iface->hostname = blobmsg_safe_copy(tb[IFACE_ATTR_HOSTNAME]);
    iface->clientid = blobmsg_safe_copy(tb[IFACE_ATTR_CLIENTID]);
    iface->vendorid = blobmsg_safe_copy(tb[IFACE_ATTR_VENDORID]);
    if (tb[IFACE_ATTR_METRIC]) iface->metric = blobmsg_get_u32(tb[IFACE_ATTR_METRIC]);

    iface->dns_list = blobmsg_list_data(tb[IFACE_ATTR_DNS]);
    iface->dns_search_list = blobmsg_list_data(tb[IFACE_ATTR_DNS_SEARCH]);

    return iface;
}

struct interface* interface_from_uci(struct uci_section *s)
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

struct wifi_interface* wifi_interface_new(const char *name, struct blob_attr *tb[])
{
    struct wifi_interface *iface = NULL;

    iface = g_alloc(struct wifi_interface, 1);

    iface->ref_count++;

    iface->name = g_strdup(name);
    DBG("Wifi Interface: %s", iface->name);
    iface->device = blobmsg_safe_copy(tb[WIFACE_ATTR_DEVICE]);
    iface->mode = blobmsg_safe_copy(tb[WIFACE_ATTR_MODE]);
    iface->ssid = blobmsg_safe_copy(tb[WIFACE_ATTR_SSID]);
    iface->bssid = blobmsg_safe_copy(tb[WIFACE_ATTR_BSSID]);
    iface->network = blobmsg_safe_copy(tb[WIFACE_ATTR_NETWORK]);
    iface->encryption = blobmsg_safe_copy(tb[WIFACE_ATTR_ENCRYPTION]);
    iface->key = blobmsg_safe_copy(tb[WIFACE_ATTR_KEY]);
    iface->wep_key[0] = blobmsg_safe_copy(tb[WIFACE_ATTR_KEY1]);
    iface->wep_key[1] = blobmsg_safe_copy(tb[WIFACE_ATTR_KEY2]);
    iface->wep_key[2] = blobmsg_safe_copy(tb[WIFACE_ATTR_KEY3]);
    iface->wep_key[3] = blobmsg_safe_copy(tb[WIFACE_ATTR_KEY4]);
    iface->macaddr = blobmsg_safe_copy(tb[WIFACE_ATTR_MACADDR]);
    iface->server = blobmsg_safe_copy(tb[WIFACE_ATTR_WPA_SERVER]);
    iface->port = blobmsg_safe_copy(tb[WIFACE_ATTR_WPA_PORT]);
    iface->wpa_group_rekey = blobmsg_safe_copy(tb[WIFACE_ATTR_WPA_GROUP_REKEY]);
    iface->eap_type = blobmsg_safe_copy(tb[WIFACE_ATTR_WPA_EAP_TYPE]);
    iface->auth = blobmsg_safe_copy(tb[WIFACE_ATTR_WPA_AUTH]);
    iface->identity = blobmsg_safe_copy(tb[WIFACE_ATTR_WPA_IDENTITY]);
    iface->password = blobmsg_safe_copy(tb[WIFACE_ATTR_WPA_PASSWORD]);
    iface->ca_cert = blobmsg_safe_copy(tb[WIFACE_ATTR_WPA_CA_CERT]);
    iface->client_cert = blobmsg_safe_copy(tb[WIFACE_ATTR_WPA_CLIENT_CERT]);
    iface->priv_key = blobmsg_safe_copy(tb[WIFACE_ATTR_WPA_PRIV_KEY]);
    iface->priv_key_pwd = blobmsg_safe_copy(tb[WIFACE_ATTR_WPA_PRIV_KEY_PWD]);

    iface->disabled = blobmsg_get_bool_default(tb[WIFACE_ATTR_DISABLED], false);
    iface->hidden = blobmsg_get_bool_default(tb[WIFACE_ATTR_HIDDEN], false);
    iface->isolate = blobmsg_get_bool_default(tb[WIFACE_ATTR_ISOLATE], false);
    iface->wmm = blobmsg_get_bool_default(tb[WIFACE_ATTR_WMM], true);

    return iface;
}

struct wifi_interface* wifi_interface_from_uci(struct uci_section *s)
{
    struct blob_attr *tb[WIFACE_ATTR_MAX] = { 0 };

    blob_buf_init(&b, 0);

    uci_to_blob(&b, s, &wiface_attr_list);

    blobmsg_parse(wiface_attrs, WIFACE_ATTR_MAX, tb, blob_data(b.head), blob_len(b.head));

    return wifi_interface_new(s->e.name, tb);
}

void wifi_interface_unref(struct wifi_interface *iface)
{
    int i;
    if (!iface) return;
    if (--iface->ref_count < 0) return;

    g_free(iface->device);
    g_free(iface->mode);
    g_free(iface->ssid);
    g_free(iface->bssid);
    g_free(iface->network);
    g_free(iface->encryption);
    g_free(iface->key);
    for (i=0; i < 4; i++)
        g_free(iface->wep_key[i]);
    g_free(iface->macaddr);
    g_free(iface->server);
    g_free(iface->port);
    g_free(iface->wpa_group_rekey);
    g_free(iface->eap_type);
    g_free(iface->auth);
    g_free(iface->identity);
    g_free(iface->password);
    g_free(iface->ca_cert);
    g_free(iface->client_cert);
    g_free(iface->priv_key);
    g_free(iface->priv_key_pwd);

    g_free(iface);
}
