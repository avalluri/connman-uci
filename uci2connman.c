#include "log.h"
#include "uci-parser.h"

#include <string.h>
#include <uci.h>
#include <glib.h>
#include <getopt.h>

#define CONNMAN_CONF_DIR "/var/lib/connman"

struct {
    char *connman_dir;
    char *uci_dir;
    enum {
        CONFIG_NONE = 0x00,
        CONFIG_WIRELESS = 0x01,
        CONFIG_NETWORK = 0x02,
        CONFIG_ALL = CONFIG_WIRELESS | CONFIG_NETWORK
    } change_flags;
    struct uci_context *uci;
    GKeyFile *settings;
} params = {
    .connman_dir = CONNMAN_CONF_DIR,
} ;


static
GHashTable* uci_interface_to_table(struct uci_context *uci, struct uci_list *list) {
    GHashTable *table = g_hash_table_new_full(g_str_hash, g_str_equal, NULL, g_free);
    struct uci_element *e = NULL;

    uci_foreach_element(list, e) {
        struct uci_option *o = uci_to_option(e);
        INFO("  %s =  %s", o->e.name, o->v.string);

        switch (o->type) {
        case UCI_TYPE_STRING:
            g_hash_table_insert(table, o->e.name, g_strdup(o->v.string));
            break;
        case UCI_TYPE_LIST:
            //list to string !!!
            break;
        }
    }

    return table;
}

static
const char *get_ipaddr(GHashTable *table, const char *ipkey, const char *maskkey, const char *gwkey) 
{
    static char ipaddr[256];
    int len;
    const char *ip = NULL;
    const char *mask = NULL;
    const char *gw = NULL;

    ip = (const char *)g_hash_table_lookup(table, ipkey);
    mask = (const char *)g_hash_table_lookup(table, maskkey);
    gw = (const char *)g_hash_table_lookup(table, gwkey);
    if (!ip || !mask) {
        WARN("Incomplete static configuration, missing mandatory '%s' option",
             ip ? maskkey: ipkey);
        return NULL;
    }

    len = sprintf(ipaddr, "%s/%s", ip, mask);
    if (gw)
        sprintf(ipaddr + len, "/%s", gw);

    return ipaddr;
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
void prepare_interface(struct interface *iface, void *data)
{

   struct uci_package *p = NULL;
    struct uci_element *e = NULL;
    struct uci_ptr ptr = { .package = "network" };
    GKeyFile *config = NULL; 
    int n_services = 0;
    int ret = 0;


    if (uci_load(params.uci, ptr.package, &p)) {
        return params.uci->err;
    }

    if (uci_list_empty(&p->sections)) {
        WARN("No sections found in network config");
        ret = -1;
        goto end;
    }

    config = g_key_file_new();

    g_key_file_set_value(config, "global", "Name", "UCI");
    g_key_file_set_value(config, "global", "Description", "UCI generated network configuration");

    uci_foreach_element(&p->sections, e) {
        GHashTable *table = NULL;
        const char *proto = NULL;
        struct uci_section *s = uci_to_section(e);
        char *grp_service = NULL;

        if (g_strcmp0(s->type, "interface"))
            continue;
        if (!g_strcmp0(s->e.name, "loopback"))
            continue;

        n_services++;

        INFO("section name: %s, type: %s", s->e.name, s->type);

        grp_service = g_strdup_printf("service_%s", s->e.name);

        g_key_file_set_value(config, grp_service, "Type", "ethernet");

        table = uci_interface_to_table(params.uci, &s->options);

        proto = g_hash_table_contains(table, "proto") ?
                g_hash_table_lookup(table, "proto") : "dhcp";

        if (!g_hash_table_contains(table, "enabled") ||
            !g_strcmp0(g_hash_table_lookup(table, "enabled"), "1")) {
            if (!g_strcmp0(proto, "static")) {
                const char *ip = get_ipaddr(table, "ipaddr", "netmask", "gateway");
                if (!ip) goto end;
                g_key_file_set_value(config, grp_service, "IPv4",  ip);
            } else { 
                // Currently we support only 'dhcp'
                g_key_file_set_value(config, grp_service, "IPv4", "dhcp");
            }
        } else {
            g_key_file_set_value(config, grp_service, "IPv4", "off");
        }

        if (!g_hash_table_contains(table, "ipv6") ||
            !g_strcmp0(g_hash_table_lookup(table, "ipv6"), "1")) {
            if (!g_strcmp0(proto, "static")) {
                const char *ip = get_ipaddr(table, "ip6addr", "ip6assign", "ip6gw");
                if (!ip) goto end;
                g_key_file_set_value(config, grp_service, "IPv6", ip);
            } else {
                g_key_file_set_value(config, grp_service, "IPv6", "off");
            }
        }

        if (g_hash_table_contains(table, "macaddr")) {
            g_key_file_set_value(config, grp_service, "MAC", 
                    (char*)g_hash_table_lookup(table, "macaddr"));
        }

        if (g_hash_table_lookup(table, "dns")) {
            g_key_file_set_value(config, grp_service, "Nameservers",
                            (char*)g_hash_table_lookup(table, "dns"));
        }

        if (g_hash_table_lookup(table, "dns_search")) {
            g_key_file_set_value(config, grp_service, "SearchDomains",
                             (char*)g_hash_table_lookup(table, "dns_search"));
        }

        g_hash_table_unref(table);
        g_free(grp_service);
    }

    INFO("Generated connman configuration:\n%s", 
            g_key_file_to_data(config, NULL, NULL));

    if (n_services) {
        GError *err = NULL;
        char *file_name = g_strdup_printf("%s/uci-ethernet.config", params.connman_dir);
        
        INFO("Writing to file :%s", file_name);
        
        if (!g_key_file_save_to_file(config, file_name, &err)) {
            WARN("Failed to config to file: %s", err->message);
            g_error_free(err);
        }

        g_free(file_name);
    }

end:
    g_key_file_unref(config);

    uci_unload(params.uci, p);

    return ret;
}

static
int update_network_config()
{
    uci_config_parse_network(prepare_interface, NULL, NULL);
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
int update_wireless_config()
{
    struct uci_package *p = NULL;
    struct uci_element *e = NULL;
    struct uci_ptr ptr = { .package = "wireless" };
    GKeyFile *config = NULL;
    int n_services = 0;
    int ret = 0;

    if (uci_load(params.uci, ptr.package, &p)) {
        return params.uci->err;
    }

    if (uci_list_empty(&p->sections)) {
        WARN("No sections found in network config");
        ret = -1;
        goto end;
    }

    INFO("Wireless Configuration:");

    config = g_key_file_new();

    g_key_file_set_value(config, "global", "Name", "UCI");
    g_key_file_set_value(config, "global", "Description", "UCI generated wireless configuration");

    uci_foreach_element(&p->sections, e) {
        GHashTable *table = NULL;
        struct uci_section *s = uci_to_section(e);
        char *eap = NULL, *v = NULL;
        char *encryption = NULL;
        char *grp_service = NULL;
        gboolean enabled;

        if (g_strcmp0(s->type, "wifi-iface"))
            continue;
        table = uci_interface_to_table(params.uci, &s->options);

        enabled = !(g_hash_table_contains(table, "disabled") &&
                   g_strcmp0(g_hash_table_lookup(table, "disabled"), "1")) ;
        if (g_key_file_get_boolean(params.settings, "Wifi", "Enable", NULL) != enabled) {
            g_key_file_set_boolean(params.settings, "Wifi", "Enable", enabled);
        }
 
        n_services++;

        grp_service = g_strdup_printf("service_wifi_%s", 
            (v = (char *)g_hash_table_lookup(table, "device")) ? v: "");

        g_key_file_set_value(config, grp_service, "Type", "Wifi");

        if (g_hash_table_contains(table, "ssid")) {
            g_key_file_set_value(config, grp_service, "SSID",
                    (char*)g_hash_table_lookup(table, "ssid"));
        }
        if ((eap = (char*)g_hash_table_lookup(table, "eap_type"))) {
            g_key_file_set_value(config, grp_service, "EAP", v);

            if ((v = (char*)g_hash_table_lookup(table, "ca_cert"))) {
                g_key_file_set_value(config, grp_service, "CACertFile", v);
            }

            if ((v = (char*)g_hash_table_lookup(table, "client_cert"))) {
                g_key_file_set_value(config, grp_service, "ClientCertFile", v);
            }

            if ((v = (char*)g_hash_table_lookup(table, "auth"))) {
                g_key_file_set_value(config, grp_service, "Phase2", v);
            }
            if ((v = (char*)g_hash_table_lookup(table, "identity"))) {
                g_key_file_set_value(config, grp_service, "Identity", v);
            }

            if (!g_strcmp0(eap, "tls")) {
                if ((v = (char*)g_hash_table_lookup(table, "priv_key"))) {
                    g_key_file_set_value(config, grp_service, "PrivateKeyFile", v);
                }
                if ((v = (char*)g_hash_table_lookup(table, "priv_key_pwd"))) {
                    g_key_file_set_value(config,grp_service, "PrivateKeyPassphrase", v);
                }
            }
        }

        if ((encryption = (char *)g_hash_table_lookup(table, "encryption"))) {
            const char *sec = "none";
            if (!g_str_has_prefix(encryption, "wep"))
                sec = "wep";
            else if (!g_str_has_prefix(encryption, "psk"))
                sec = "psk";
            g_key_file_set_value(config,grp_service, "Security", sec);
        }

        if ((v = (char *)g_hash_table_lookup(table, "key"))) {
            g_key_file_set_value(config, grp_service, "Passphrase", v);
        }

        if ((v = (char*) g_hash_table_lookup (table, "hidden"))) {
            g_key_file_set_boolean(config, grp_service, "Hidden", g_strcmp0(v, "0"));
        }

#if 0
        if ((mode = (char*)g_hash_table_lookup(table, "mode"))) {
            if (!g_strcmp0(mode, "ap")) {
              // Tethering
            } else if(!g_strcmp0(mode, "sta")) {
              // EndPoint mode
            }
        }
#endif
        g_hash_table_unref(table);
        g_free(grp_service);
    }

    INFO("Generated connman wireless configuration:\n%s",
    g_key_file_to_data(config, NULL, NULL));
    if (n_services) {
        GError *err = NULL;
        char *file_name = g_strdup_printf("%s/uci-wifi.config", params.connman_dir);
        INFO("Writing to file :%s", file_name);

        if (!g_key_file_save_to_file(config, file_name, &err)) {
            WARN("Failed to save wifi configuration : %s", err->message);
            g_error_free(err);
        }

        g_free(file_name);
    }

end:

    g_key_file_unref(config);

    uci_unload(params.uci, p);

    return ret;
}

static
gboolean read_connman_settings() {
    GError *err = NULL;
    char *file = NULL;
    gboolean res = true;

    params.settings = g_key_file_new();
    file = g_strdup_printf("%s/%s", params.connman_dir, "settings");

    res = g_key_file_load_from_file(params.settings, CONNMAN_CONF_DIR"/settings",
              G_KEY_FILE_NONE, &err);
    g_free(file);
    if (!res) {
        WARN("Failed to read connman settings from %s: %s", file, err->message);
        g_error_free(err);
    }

    return res;
}

static
void read_changes() {
    if (params.change_flags & CONFIG_NETWORK)
        update_network_config();

    if (params.change_flags & CONFIG_WIRELESS)
        update_wireless_config();
}

static
gboolean init()
{

    if (uci_config_init(params.uci_dir) != 0) {
        WARN("Failed to initialized uci");
        return -1;
    }
    read_connman_settings();

    return TRUE;
}

void cleanup()
{
    if (params.uci) {
        uci_free_context(params.uci);
        params.uci = NULL;
    }

    if ((void*)params.connman_dir != (void*)CONNMAN_CONF_DIR)
        g_free(params.connman_dir);

    if (params.settings)
        g_key_file_unref(params.settings);
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
    enum LogLevel verbose_level = LOG_ERR;

    while ((ch = getopt(argc, argv, "u:c:nwvh")) != -1) {
        switch(ch) {
        case 'u':
            params.uci_dir = g_strdup(optarg);
            break;
        case 'c':
            params.connman_dir = g_strdup(optarg);
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

    if (params.change_flags == CONFIG_NONE) {
        fprintf(stderr, "No changes to read.\n");
        cleanup();
        return 0;
    }

    log_init(verbose_level);

    init();

    read_changes();

    cleanup();

    return 0;
}
