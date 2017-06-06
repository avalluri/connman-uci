
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

    uint32_t metric;
    uint32_t ip6assign;

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

#define blobmsg_get_bool_default(attr, val) ((attr) ? blobmsg_get_bool(attr) : (val))


struct interface* interface_new(const char *name, struct blob_attr *attr[]);
struct interface* parse_interface(struct uci_section *s);
void interface_unref(struct interface *iface);
int interface_dump_status(struct interface *iface, struct blob_buf *buf);

#endif // __UCI_CONNMAN_INTERFACE_H
