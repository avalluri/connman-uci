
#ifndef __UCI_CONNMAN_INTERFACE_H
#define __UCI_CONNMAN_INTERFACE_H

#include <libubox/list.h>
#include <libubox/blobmsg.h>
#include <uci_blob.h>
#include <uci.h>

struct interface {
    char *name;
    char *ifname;
    char *proto;
    char *macaddr;
    char *ipaddr;
    char *dns_list;
    char *netmask;
    char *gateway;
    char *ip6addr;
    char *ip6gw;
    char *ip6hint;
    char *dns_search_list;
    char *hostname;
    char *clientid;
    char *vendorid;
    char *ip6assign;

    uint32_t metric;

    bool enabled;
    bool ipv6;
    bool force_link;
    bool autostart;
    bool no_defaultroute;
    bool no_dns;
    bool classlessroute;

    int state;

    /* priv */
    int ref_count;
};


struct wifi_device {
    char *name;
    char *type;
    char *phy;
    char *macaddr;
    char *ifname;
    bool disabled;
    char *channel;
    char *hwmode;
    uint32_t txpower;
    bool diversity;
    char *require_mode;
    char *country;
};

struct wifi_interface {
   char *name; // struct wifi_device
   bool disabled;
   char *mode;
   char *ssid;
   char *bssid;
   bool hidden;
   bool isolate;
   bool wmm;
   char *network; // struct interface
   char *device;  // struct wifi_device
   char *encryption;
   char *key;
   char *wep_key[4];
   struct list_head maclist;
   char *macaddr;

   /* WPA AccessPoint/Server Options */
   char *server;
   char *port;
   char *wpa_group_rekey;

   /* WPA Client Options */
   char *eap_type;
   char *auth;
   char *identity;
   char *password;
   char *ca_cert;
   char *client_cert;
   char *priv_key;
   char *priv_key_pwd;

   /* priv */
   int ref_count;
};

#define blobmsg_get_bool_default(attr, val) ((attr) ? blobmsg_get_bool(attr) : (val))


struct interface* interface_new(const char *name, struct blob_attr *attr[]);
struct interface* interface_from_uci(struct uci_section *s);
void   interface_unref(struct interface *iface);
int    interface_dump_status(struct interface *iface, struct blob_buf *buf);

struct wifi_interface* wifi_interface_new(const char *name, struct blob_attr *attr[]);
void   wifi_interface_unref(struct wifi_interface *iface);
struct wifi_interface* wifi_interface_from_uci(struct uci_section *s);

#endif // __UCI_CONNMAN_INTERFACE_H
