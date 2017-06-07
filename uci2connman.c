#include "log.h"
#include "uci-parser.h"
#include "gutils.h"

#include <string.h>
#include <uci.h>
#include <getopt.h>

#define CONNMAN_CONF_DIR "/var/lib/connman"
#define UCI_CONF_DIR     "/etc/config"

struct generic_list {
    struct list_head head;
    void *data;
};

typedef void (*generic_list_data_free_cb_t)(void *data);
static
void generic_list_deep_free(struct list_head *list, generic_list_data_free_cb_t free_cb)
{
    struct list_head *p, *n;

    list_for_each_safe(p, n, list) {
        struct generic_list *elm = list_entry(p, struct generic_list, head);
        if (free_cb) free_cb(elm->data);
        list_del(p);
        g_free(elm);
    }
}
        

struct {
    const char *connman_dir;
    const char *uci_dir;
    enum {
        CONFIG_NONE = 0x00,
        CONFIG_WIRELESS = 0x01,
        CONFIG_NETWORK = 0x02,
        CONFIG_ALL = CONFIG_WIRELESS | CONFIG_NETWORK
    } change_flags;
    GKeyFile *settings;
    struct list_head ifaces;
    struct list_head wifaces;
} params = {
    .uci_dir = UCI_CONF_DIR,
    .connman_dir = CONNMAN_CONF_DIR,
    .ifaces = LIST_HEAD_INIT(params.ifaces),
    .wifaces = LIST_HEAD_INIT(params.wifaces),
};

static
const char *get_ipaddr(const char *ip, const char *mask, const char *gw) 
{
    static char ipaddr[256];
    int len;

    if (!ip || !mask) {
        WARN("Incomplete static configuration, missing mandatory option");
        return NULL;
    }

    len = sprintf(ipaddr, "%s/%s", ip, mask);
    if (gw)
        sprintf(ipaddr + len, "/%s", gw);

    return ipaddr;
}

static
void prepare_network_details(struct interface *iface, GKeyFileGroup *group)
{
    const char *proto = NULL;
    proto = iface->proto ? iface->proto : "dhcp";

    if (iface->enabled) {
        if (!g_strcmp(proto, "static")) {
            const char *ip = get_ipaddr(iface->ipaddr, iface->netmask, iface->gateway);
            if (!ip) goto invalid_ip;
            g_key_file_group_set(group, "IPv4",  ip);
        } else { 
            // Currently we support only 'dhcp'
            g_key_file_group_set(group, "IPv4", "dhcp");
        }
    } else {
        g_key_file_group_set(group, "IPv4", "off");
    }

    if (iface->ipv6) {
        if (!g_strcmp(proto, "static")) {
            const char *ip = get_ipaddr(iface->ip6addr, iface->ip6assign, iface->ip6gw);
            if (!ip) goto invalid_ip;
            g_key_file_group_set(group, "IPv6", ip);
        } else {
            g_key_file_group_set(group, "IPv6", "off");
        }
    }

    if (iface->macaddr) {
        g_key_file_group_set(group, "MAC", iface->macaddr);
    }

    if (iface->dns_list) {
        g_key_file_group_set(group, "Nameservers", iface->dns_list);
    }

    if (iface->dns_search_list) {
        g_key_file_group_set(group, "SearchDomains", iface->dns_search_list);
    }

    return;

invalid_ip:
    WARN("Invalid ip configuration in '%s' network interface", iface->name);
}

/*
 * [global]
 * name = <@interface[i].ifname
 * Description="UCI LAN configuration"
 * 
 * [service_<@interface[i].name>]
 * Type = ethernet
 * IPv4 = @interface[i].enable ? ( @interface[i].proto == 'static' ? 
 *      @interface[i].ipaddr + "/" + @interface[i].netmask + "/"
 *      + @interface[i].gateway : "dhcp" ) : "off"
 * IPv6 = @interface[i].ipv6 ? ( @interface[i].proto == 'static' ?
 *      @interface[i].ip6addr + "/" + @interface[i].ip6assign + "/"
 *      + @interface[i].ip6igw : "dhcp" ) : "off"
 * IPv6.Privacy = ??
 * MAC = @interface[i].macaddr
 * Nameservers = @interface[i].dns
 * SearchDomains = @interface[i].dns_search
 */
static
void update_network_config()
{
    GKeyFile *config = NULL;
    GKeyFileGroup *group = NULL;
    char *file_name = NULL;
    struct generic_list *list;

    if (list_empty(&params.ifaces)) {
        WARN("No valid network inteface configration found");
        return;
    }
    config = g_key_file_new();

    g_key_file_setv(config, "global",
                    "Name", "UCI", 
                    "Description", "UCI generated network configuration", NULL);

    list_for_each_entry(list, &params.ifaces, head) {
        struct interface *iface = list->data;
        char *group_name = g_strdup_printf("service_%s", iface->name);

        group = g_key_file_get_group(config, group_name, true);
        g_free(group_name);

        g_key_file_group_set(group, "Type", "ethernet");
        prepare_network_details(iface, group);
    }

    file_name = g_strdup_printf("%s/uci-ethernet.config", params.connman_dir);
    INFO("Writing to file :%s", file_name);
 
    if (!g_key_file_save_to_file(config, file_name)) {
        WARN("Failed to config to file: %s", strerror(errno));
    }

    g_free(file_name);
    g_key_file_unref(config);
} 
/*
 * [global]
 * name = <@interface[i].ifname
 * Description="UCI Wifi configuration"
 * 
 * [service_wifi_%d]
 * Type = wifi
 * IPv4 = @wifi-iface[i].enable ? ( @interface[i].proto == 'static' ? 
 *      @interface[i].ipaddr + "/" + @interface[i].netmask + "/"
 *      + @interface[i].gateway : "dhcp" ) : "off"
 * IPv6 = @interface[i].ipv6 ? ( @interface[i].proto == 'static' ?
 *      @interface[i].ip6addr + "/" + @interface[i].ip6assign + "/"
 *      + @interface[i].ip6igw : "dhcp" ) : "off"
 * IPv6.Privacy = ??
 * SSID = @wifi-iface[i].ssid
 * Security = @wifi.iface[i].encryption ? @wifi.iface[i].encryption : 
                @wifi-ifacei0].eap_type ? "ieee8021x" : "none"
 * EAP = @wifi-iface[i].eap_type
 * Identity = @wifi-iface[i].identity
 * Phase2 = @wifi-iface[i].auth if @wifi-iface.eap_type in ("peap", "ttls") 
 * CACertFile = @wifi-iface[i].ca_cert
 * ClientCertFile = @wifi-iface[i].client_cert
 * PrivateKeyFile = @wifi-iface[i].priv_key
 * PrivateKeyPassphrase = @wifi-iface[i].priv_key_pwd
 * Passphrase = @wifi-iface[i].key
 * Hidden = @wifi-iface[i].hidden
 * 
 */
static
void prepare_wifi_interface(struct wifi_interface *wiface, GKeyFile *config)
{
    char *grp_service = NULL;
    GKeyFileGroup *group = NULL;
    bool enabled;

    enabled = !wiface->disabled;
    if (g_key_file_get_boolean(params.settings, "Wifi", "Enable") != enabled) {
        g_key_file_set_boolean(params.settings, "Wifi", "Enable", enabled);
    }
 
    grp_service = g_strdup_printf("service_wifi_%s", wiface->name);

    group = g_key_file_get_group(config, grp_service, true);

    g_free(grp_service);

    g_key_file_group_set(group, "Type", "Wifi");
    g_key_file_group_set_boolean(group, "Hidden", wiface->hidden);

    if (wiface->network) {
        struct generic_list *elm;

        list_for_each_entry(elm, &params.ifaces, head) {
            struct interface *iface = (struct interface *)elm->data;
            if (!g_strcmp(iface->name, wiface->network)) {
                prepare_network_details(iface, group);
                break;
            }
        }
    } else {
        WARN("Incomplete wifi configuration, wifi-iface is not attached to any network interface");
    }

    if (wiface->ssid) {
        g_key_file_group_set(group, "SSID", wiface->ssid);
    }
    if (wiface->eap_type) {
        g_key_file_group_setv(group,
            "EAP", wiface->eap_type,
            "CACertFile", wiface->ca_cert,
            "ClientCertFile", wiface->client_cert,
            "Phase2", wiface->auth,
            "Identity", wiface->identity, NULL);

        if (!g_strcmp(wiface->eap_type, "tls")) {
            g_key_file_group_setv(group,
                "PrivateKeyFile", wiface->priv_key,
                "PrivateKeyPassphrase", wiface->priv_key_pwd, NULL);
        }
    }

    if (wiface->encryption) {
        const char *sec = "none";
        if (!g_str_has_prefix(wiface->encryption, "wep"))
            sec = "wep";
        else if (!g_str_has_prefix(wiface->encryption, "psk"))
            sec = "psk";
        g_key_file_group_set(group, "Security", sec);
    }
    g_key_file_group_set(group, "Passphrase", wiface->key);
#if 0
    if (iface->mode) {
        if (!g_strcmp(mode, "ap")) {
              // Tethering
        } else if(!g_strcmp(mode, "sta")) {
              // EndPoint mode
        }
    }
#endif
}

static
void update_wireless_config()
{
    GKeyFile *config = NULL;
    char *file_name = NULL;
    struct generic_list *list = NULL;

    if (list_empty(&params.wifaces)) {
        WARN("No wifi-iface sections found in wireless config");
        return ;
    }
        
    config = g_key_file_new();

    g_key_file_setv(config, "global",
                    "Name", "UCI",
                    "Description", "UCI generated wireless configuration", NULL);

    list_for_each_entry(list, &params.wifaces, head) {
        prepare_wifi_interface((struct wifi_interface *)list->data, config);
    }

    file_name = g_strdup_printf("%s/uci-wifi.config", params.connman_dir);
    INFO("Writing to file :%s", file_name);

    if (!g_key_file_save_to_file(config, file_name)) {
        WARN("Failed to config to file: %s", strerror(errno));
    }

    g_free(file_name);
    g_key_file_unref(config);
}

static
bool read_connman_settings() {
    char *file = NULL;
    bool res = true;

    params.settings = g_key_file_new();
    file = g_strdup_printf("%s/%s", params.connman_dir, "settings");

    res = g_key_file_load_from_file(params.settings, file);
    g_free(file);
    if (!res) {
        WARN("Failed to read connman settings from %s: %s", file, strerror(errno));
    }

    return res;
}

static
void handle_iface(struct interface *iface, void *data)
{
    struct generic_list *node = g_alloc(struct generic_list, 1);

    INIT_LIST_HEAD(&node->head);
    node->data = iface;
    list_add_tail(&node->head, &params.ifaces);
}


static
void handle_wiface(struct wifi_interface *wiface, void *data)
{
    struct generic_list *node = g_alloc(struct generic_list, 1);

    INIT_LIST_HEAD(&node->head);
    node->data = wiface;
    list_add_tail(&node->head, &params.wifaces);
}

static
bool init()
{
    if (params.uci_dir != UCI_CONF_DIR) {
    if (uci_config_init(params.uci_dir) != 0) {
        WARN("Failed to initialized uci");
        return false;
    }
    }

    read_connman_settings();

    uci_config_parse_network(handle_iface, NULL, NULL);
    uci_config_parse_wireless(handle_wiface, NULL, NULL);

    return true;
}

void cleanup()
{
    generic_list_deep_free(&params.ifaces, (generic_list_data_free_cb_t)interface_unref);
    generic_list_deep_free(&params.wifaces, (generic_list_data_free_cb_t)wifi_interface_unref);

    uci_config_cleanup();

    if (params.settings)
        g_key_file_unref(params.settings);
}

static
void read_changes() {
    if (params.change_flags & CONFIG_NETWORK)
        update_network_config();

    if (params.change_flags & CONFIG_WIRELESS)
        update_wireless_config();
}

static
void print_usage(const char *exe) {
    fprintf(stderr, "Usage : %s [<options>]\n"
            "Options:\n"
            "   -u <config-dir>  Location of UCI configuration default /etc/config.\n"
            "   -c <config-dir>  Location of connman configuration to place, default /var/lib/connman/.\n"
            "   -n               Read changed network configuration.\n"
            "   -w               Read changed wireless configuration.\n"
            "   -v               Increase verbosity, can be used more than once.\n"
            "   -h               Print this help text\n"
            "\n", exe);
}

int main(int argc, char **argv)
{
    char ch;
    enum LogLevel verbose_level = LOG_WARN;

    while ((ch = getopt(argc, argv, "u:c:nwvh")) != -1) {
        switch(ch) {
        case 'u':
            params.uci_dir = optarg;
            break;
        case 'c':
            params.connman_dir = optarg;
            break;
        case 'n':
            params.change_flags |= CONFIG_NETWORK;
            break;
        case 'w':
            params.change_flags |= CONFIG_WIRELESS;
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

    log_init("connmandupd", verbose_level);

    if (params.change_flags == CONFIG_NONE) {
        fprintf(stderr, "No changes to read.\n");
        cleanup();
        return 0;
    }

    init();

    read_changes();

    cleanup();

    return 0;
}
