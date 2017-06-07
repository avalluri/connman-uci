#include <stdlib.h>

#include "ubus.h"
#include "log.h"
#include "interface.h"
#include "gutils.h"
#include "uci-parser.h"

struct ubus_interface {
    struct list_head node;
    char * ubus_name;
    struct interface *iface;
    struct ubus_object ubus_obj;
};

static
void ubus_interface_unref(struct ubus_interface *i)
{
    if (!i) return;
    if (i->iface) interface_unref(i->iface);
    g_free(i->ubus_name);
    g_free(i);
}

#ifndef UCI_CONFIG_PATH
#define UCI_CONFIG_PATH NULL
#endif

const char *uci_config_path = UCI_CONFIG_PATH;
static struct ubus_context *ctx;
static struct blob_buf b;

struct list_head ifaces = LIST_HEAD_INIT(ifaces);

#define UBUS_OBJECT(_name, _type, _methods) \
    { .name = _name, .type = _type, .methods = _methods, .n_methods = ARRAY_SIZE(_methods) }

#define DECLARE_UBUS_OBJECT(var, name, methods) \
    struct ubus_object_type var##_obj_type = UBUS_OBJECT_TYPE(name, methods);\
    struct ubus_object var##_obj = UBUS_OBJECT(name, &var##_obj_type, methods);

static
int handle_iface_up(struct ubus_context *ctx, struct ubus_object *obj,
        struct ubus_request_data *req, const char *method, struct blob_attr *msg)
{
    //interface_set_up(iface);
    return 0;
}

static
int handle_iface_down(struct ubus_context *ctx, struct ubus_object *obj,
       struct ubus_request_data *req, const char *method, struct blob_attr *msg)
{
    // interface_set_down(iface);

    return 0;
}

static
int handle_iface_status(struct ubus_context *ctx, struct ubus_object *obj,
        struct ubus_request_data *req, const char *method, struct blob_attr *msg)
{
    struct ubus_interface *iface = container_of(obj, struct ubus_interface, ubus_obj);

    blob_buf_init(&b, 0);
    DBG("status: %s", iface->iface->name);
    interface_dump_status(iface->iface, &b);
    ubus_send_reply(ctx, req, b.head);

    return 0;
}

static
int handle_iface_dump(struct ubus_context *ctx, struct ubus_object *obj,
                struct ubus_request_data *req, const char *method,
                struct blob_attr *msg)
{
    struct ubus_interface *iface = NULL;
    void *a = NULL;

    blob_buf_init(&b, 0);
    
    a = blobmsg_open_array(&b, "interfaces");
    list_for_each_entry(iface, &ifaces, node) {
        void *t = blobmsg_open_table(&b, NULL);
        interface_dump_status(iface->iface, &b);
        blobmsg_close_table(&b, t);
    }

    blobmsg_close_array(&b, a);
    ubus_send_reply(ctx, req, b.head);

    return 0;
}

#if 0
static void
iface_do_remove(struct uloop_timeout *t)
{
    vlist_delete(&interfaces, container_of(t, struct interface, remove_timer));
}
#endif

static
int handle_iface_remove(struct ubus_context *ctx, struct ubus_object *obj,
        struct ubus_request_data *req, const char *method, struct blob_attr *msg)
{
#if 0
    if (iface->remove_timer.cb)
        return UBUS_STATUS_INVALID_ARGUMENT;

    iface->remove_timer.cb = iface_do_remove;
    uloop_timeout_set(&iface->remove_timer, 100);
#endif
    return 0;

}

enum {
    DEV_LINK_NAME,
    DEV_LINK_EXT,
    __DEV_LINK_MAX,
};

static const struct blobmsg_policy dev_link_policy[__DEV_LINK_MAX] = {
    [DEV_LINK_NAME] = { .name = "name", .type = BLOBMSG_TYPE_STRING },
    [DEV_LINK_EXT] = { .name = "link-ext", .type = BLOBMSG_TYPE_BOOL },
};


static
int handle_iface_remove_device(struct ubus_context *ctx, struct ubus_object *obj,
        struct ubus_request_data *req, const char *method, struct blob_attr *msg)
{
    struct blob_attr *tb[__DEV_LINK_MAX];
    //bool link_ext = true; 
    blobmsg_parse(dev_link_policy, __DEV_LINK_MAX, tb, blob_data(msg), blob_len(msg));

    if (!tb[DEV_LINK_NAME])
        return UBUS_STATUS_INVALID_ARGUMENT;

   //link_ext = tb[DEV_LINK_EXT]? blobmsg_get_bool(tb[DEV_LINK_EXT]) : true ;

   //return interface_handle_link(iface, blobmsg_data(tb[DEV_LINK_NAME]), true, link_ext);

   return 0;
}

static
int handle_iface_add_device(struct ubus_context *ctx, struct ubus_object *obj,
        struct ubus_request_data *req, const char *method, struct blob_attr *msg)
{
    struct blob_attr *tb[__DEV_LINK_MAX];
    //bool link_ext = true;

    blobmsg_parse(dev_link_policy, __DEV_LINK_MAX, tb, blob_data(msg), blob_len(msg));

    if (!tb[DEV_LINK_NAME])
        return UBUS_STATUS_INVALID_ARGUMENT;

   // link_ext = tb[DEV_LINK_EXT]? blobmsg_get_bool(tb[DEV_LINK_EXT]) : true ;

   //return interface_handle_link(iface, blobmsg_data(tb[DEV_LINK_NAME]), false, link_ext);

   return 0;
}

static struct ubus_method iface_methods[] = {
    { .name = "up", .handler = handle_iface_up },
    { .name = "down", .handler = handle_iface_down },
    { .name = "status", .handler = handle_iface_status },
    { .name = "remove", .handler = handle_iface_remove },
    { .name = "add_device", .handler = handle_iface_add_device },
    { .name = "remove_device", .handler = handle_iface_remove_device },
    //{ .name = "renew", .handler = handle_iface_renew },
    //{ .name = "prepare", .handler = handle_iface_prepare },
    //{ .name = "notify_proto", .handler = handle_iface_notify_proto },
    //{ .name = "set_data", .handler = handle_iface_set_data },
};
struct ubus_object_type iface_obj_type = UBUS_OBJECT_TYPE("netifd_iface", iface_methods);

static const struct blobmsg_policy iface_policy[] = {
    { .name = "interface", .type = BLOBMSG_TYPE_STRING }
};

static
int handle_iface_method(struct ubus_context *ctx, struct ubus_object *obj,
        struct ubus_request_data *req, const char *method, struct blob_attr *msg)
{
    struct ubus_interface *iface = NULL;
    struct list_head *p;
    struct blob_attr *tb[1];
    int i;
    const char *interface = NULL;

    blobmsg_parse(iface_policy, 1, tb, blob_data(msg), blob_len(msg));
    if (!tb[0])
        return UBUS_STATUS_INVALID_ARGUMENT;

    interface = blobmsg_get_string(tb[0]);

    DBG("handle_iface_method(method:%s, iface:%s)", method, interface);

    list_for_each(p, &ifaces) {
        iface = list_entry(p, struct ubus_interface, node);
        if (!g_strcmp(iface->iface->name, interface))
            break;
        iface = NULL;
    }

    if (!iface)
        return UBUS_STATUS_NOT_FOUND;

    for (i = 0; i < ARRAY_SIZE(iface_methods); i++) {
        if (!strcmp(method, iface_methods[i].name))
            break;
    }
    
    if ( i == ARRAY_SIZE(iface_methods))
        return UBUS_STATUS_INVALID_ARGUMENT;

    return iface_methods[i].handler(ctx, &iface->ubus_obj, req, method, msg);
}

const struct ubus_method common_iface_methods[] = {
    UBUS_METHOD("up", handle_iface_method, iface_policy),
    UBUS_METHOD("down", handle_iface_method, iface_policy),
    UBUS_METHOD("renew", handle_iface_method, iface_policy),
    UBUS_METHOD("status", handle_iface_method, iface_policy),
    UBUS_METHOD("prepare", handle_iface_method, iface_policy),
    //UBUS_METHOD("notify_proto", handle_iface_method, NULL),
    UBUS_METHOD("remove", handle_iface_method, iface_policy),
    //UBUS_METHOD("set_data", handle_iface_method, NULL),
    UBUS_METHOD("add_device", handle_iface_method, iface_policy),
    UBUS_METHOD("remove_device", handle_iface_method, iface_policy),
    { .name = "dump", .handler = handle_iface_dump },
};
DECLARE_UBUS_OBJECT(network_iface, "network.interface", common_iface_methods);

static
void handle_found_interface(struct interface *iface, void *data)
{
    struct ubus_interface *ubus_iface = NULL;
    int ret;

    ubus_iface = g_alloc(struct ubus_interface, 1);
    ubus_iface->ubus_name = g_strdup_printf("network.interface.%s", iface->name),
    ubus_iface->iface = iface;
    ubus_iface->ubus_obj.name = ubus_iface->ubus_name;
    ubus_iface->ubus_obj.type = &iface_obj_type;
    ubus_iface->ubus_obj.methods = iface_methods;
    ubus_iface->ubus_obj.n_methods = ARRAY_SIZE(iface_methods);

    DBG("Adding UBUS interface object : %s", ubus_iface->ubus_name);
    if ( (ret = ubus_add_object(ctx, &ubus_iface->ubus_obj))) {
        WARN("Failed to add ubus interface object: %s", ubus_strerror(ret));
        ubus_interface_unref(ubus_iface);
    }

    list_add(&ubus_iface->node, &ifaces);
}

static int
handle_wdev_get_validate(struct ubus_context *ctx,
    struct ubus_object *obj, struct ubus_request_data *req,
    const char *method, struct blob_attr *msg)
{
//    struct wireless_device *wdev;
//    int ret;

    blob_buf_init(&b, 0);
#if 0
    wdev = get_wdev(msg, &ret);
    if (ret == UBUS_STATUS_NOT_FOUND)
        return ret;


    if (wdev) {
        wireless_device_get_validate(wdev, &b);
    } else {
        vlist_for_each_element(&wireless_devices, wdev, node)
        wireless_device_get_validate(wdev, &b);
    }
#endif
    ubus_send_reply(ctx, req, b.head);
    return 0;
}

#if 0
static
int netifd_handle_wdev_notify(struct ubus_context *ctx, struct ubus_object *obj,
    struct ubus_request_data *req, const char *method, struct blob_attr *msg)
{
        struct wireless_device *wdev;
        int ret;

        wdev = get_wdev(msg, &ret);
        if (!wdev) return ret;

        return wireless_device_notify(wdev, msg, req);
}
#endif

static int
handle_wdev_up(struct ubus_context *ctx, struct ubus_object *obj,
    struct ubus_request_data *req, const char *method, struct blob_attr *msg)
{
#if 0
    struct wireless_device *wdev;
    int ret;
    wdev = get_wdev(msg, &ret);
    if (ret == UBUS_STATUS_NOT_FOUND)
        return ret;

    if (wdev) {
        wireless_device_set_up(wdev);
    } else {
        vlist_for_each_element(&wireless_devices, wdev, node)
            wireless_device_set_up(wdev);
    }
#endif

    return 0;
}


static int
handle_wdev_down(struct ubus_context *ctx, struct ubus_object *obj,
            struct ubus_request_data *req, const char *method,
                        struct blob_attr *msg)
{
#if 0
    struct wireless_device *wdev;
    int ret;

    wdev = get_wdev(msg, &ret);
    if (ret == UBUS_STATUS_NOT_FOUND)
        return ret;

    if (wdev) {
        wireless_device_set_down(wdev);
    } else {
        vlist_for_each_element(&wireless_devices, wdev, node)
            wireless_device_set_down(wdev);
   }
#endif

   return 0;
}

static
int handle_wdev_status(struct ubus_context *ctx, struct ubus_object *obj,
                struct ubus_request_data *req, const char *method,
                struct blob_attr *msg)
{
#if 0
    struct wireless_device *wdev;
    int ret;

    wdev = get_wdev(msg, &ret);
    if (ret == UBUS_STATUS_NOT_FOUND)
                return ret;
#endif
    blob_buf_init(&b, 0);
#if 0
    if (wdev) {
        wireless_device_status(wdev, &b);
    } else {
        vlist_for_each_element(&wireless_devices, wdev, node)
            wireless_device_status(wdev, &b);
    }
#endif
    ubus_send_reply(ctx, req, b.head);
    return 0;
}

static const struct ubus_method wdev_methods[] = {
    { .name = "up", .handler = handle_wdev_up },
    { .name = "down", .handler = handle_wdev_down },
    { .name = "status", .handler = handle_wdev_status },
    { .name = "get_validate", .handler = handle_wdev_get_validate }
//    { .name = "notify", .handler = handle_wdev_notify },
};
DECLARE_UBUS_OBJECT(network_wdev, "network.wireless", wdev_methods);

static const struct blobmsg_policy dev_policy[] = {
    { .name = "name", .type = BLOBMSG_TYPE_STRING }
};

static int
handle_dev_status(struct ubus_context *ctx, struct ubus_object *obj,
                struct ubus_request_data *req, const char *method,
                struct blob_attr *msg)
{
    //struct device *dev = NULL;
    struct blob_attr *tb[1];

    blob_buf_init(&b, 0);
    blobmsg_parse(dev_policy, 1, tb, blob_data(msg), blob_len(msg));

#if 0
    if (!tb[0] || !(dev = device_find(blobmsg_data(tb[0]))))
        return UBUS_STATUS_INVALID_ARGUMENT;

    device_dump_status(&b, dev);
#endif
    ubus_send_reply(ctx, req, b.head);

    return 0;
}

enum { 
    ALIAS_NAME,
    ALIAS_DEV_NAME,
    __ALIAS_ATTR_MAX
};

static const struct blobmsg_policy alias_attrs[] = {
    [ALIAS_NAME] = { "alias", BLOBMSG_TYPE_ARRAY },
    [ALIAS_DEV_NAME] = { "device", BLOBMSG_TYPE_STRING },
};

static int handle_dev_set_alias(struct ubus_context *ctx,
                struct ubus_object *obj, struct ubus_request_data *req,
                const char *method, struct blob_attr *msg)
{ 
    struct blob_attr *tb[__ALIAS_ATTR_MAX];
//    struct blob_attr *cur;
//    struct device *dev = NULL;
//    int rem;

    blobmsg_parse(alias_attrs, __ALIAS_ATTR_MAX, tb, blob_data(msg), blob_len(msg));

    if (!tb[ALIAS_NAME])
        return UBUS_STATUS_INVALID_ARGUMENT;
#if 0
    if ((cur = tb[ALIAS_DEV_NAME]) != NULL) {
        if ( !(dev = device_get(blobmsg_data(cur), true)))
            return UBUS_STATUS_NOT_FOUND;
    }

    blobmsg_for_each_attr(cur, tb[ALIAS_NAME], rem) {
        if (blobmsg_type(cur) != BLOBMSG_TYPE_STRING)
            goto error;

        if (!blobmsg_check_attr(cur, NULL))
            goto error;

        alias_notify_device(blobmsg_data(cur), dev);
    }
#endif
    return 0;
#if 0
error:
    device_free_unused(dev);
    return UBUS_STATUS_INVALID_ARGUMENT;
#endif
}


enum {
    DEV_STATE_NAME,
    DEV_STATE_DEFER,
    __DEV_STATE_MAX,
};

static const struct blobmsg_policy dev_state_policy[] = {
        [DEV_STATE_NAME] = { .name = "name", .type = BLOBMSG_TYPE_STRING },
        [DEV_STATE_DEFER] = { .name = "defer", .type = BLOBMSG_TYPE_BOOL },
};

static int
handle_dev_set_state(struct ubus_context *ctx, struct ubus_object *obj,
                struct ubus_request_data *req, const char *method,
                struct blob_attr *msg)
{
    struct blob_attr *tb[__DEV_STATE_MAX];
    struct blob_attr *cur;

    blobmsg_parse(dev_state_policy, __DEV_STATE_MAX, tb, blob_data(msg), blob_len(msg));

    if ( !(cur = tb[DEV_STATE_NAME]))
        return UBUS_STATUS_INVALID_ARGUMENT;
#if 0
    if (!(dev = device_find(blobmsg_data(cur))))
        return UBUS_STATUS_NOT_FOUND;

    if ((cur = tb[DEV_STATE_DEFER]))
        device_set_deferred(dev, !!blobmsg_get_u8(cur));
#endif
    return 0;
}

static const struct ubus_method network_dev_methods[] = {
    UBUS_METHOD("status", handle_dev_status, dev_policy),
    UBUS_METHOD("set_alias", handle_dev_set_alias, alias_attrs),
    UBUS_METHOD("set_state", handle_dev_set_state, dev_state_policy),
};
DECLARE_UBUS_OBJECT(network_dev, "network.device", network_dev_methods);

static
int handle_restart(struct ubus_context *ctx, struct ubus_object *obj,
                  struct ubus_request_data *req, const char *method,
                  struct blob_attr *msg)
{
    DBG("%s", __func__);
    return 0;
}

static
int handle_reload(struct ubus_context *ctx, struct ubus_object *obj,
                  struct ubus_request_data *req, const char *method,
                  struct blob_attr *msg)
{
    DBG("%s", __func__);
    return 0;
}

static
int handle_get_protos(struct ubus_context *ctx, struct ubus_object *obj,
                  struct ubus_request_data *req, const char *method,
                  struct blob_attr *msg)
{
    DBG("%s", __func__);
    void *c, *v ;
    int i = 0;
    const char *protocols[] = { "dhcp", "static", NULL };

    blob_buf_init(&b, 0);

    for (i=0; protocols[i]; i++) {
        if ( !(c = blobmsg_open_table(&b, protocols[i]))) {
            ERR("Failed to open blob table");
            return -1;
        }
    
        v = blobmsg_open_table(&b, "validate");
        blobmsg_add_string(&b, "ipaddr", "ipaddr");
        blobmsg_close_table(&b, v);
#if 0
        blobmsg_add_u8(b, "immediate", !!(p->flags & PROTO_FLAG_IMMEDIATE));
        blobmsg_add_u8(b, "no_device", !!(p->flags & PROTO_FLAG_NODEV));
        blobmsg_add_u8(b, "init_available", !!(p->flags & PROTO_FLAG_INIT_AVAILABLE));
        blobmsg_add_u8(b, "renew_available", !!(p->flags & PROTO_FLAG_RENEW_AVAILABLE));
        blobmsg_add_u8(b, "force_link_default", !!(p->flags & PROTO_FLAG_FORCE_LINK_DEFAULT));
        blobmsg_add_u8(b, "last_error", !!(p->flags & PROTO_FLAG_LASTERROR));
        blobmsg_add_u8(b, "teardown_on_l3_link_down", !!(p->flags & PROTO_FLAG_TEARDOWN_ON_L3_LINK_DOWN));
        blobmsg_add_u8(b, "no_task", !!(p->flags & PROTO_FLAG_NO_TASK));
#endif
        blobmsg_close_table(&b, c);
    }

    ubus_send_reply(ctx, req, b.head);
    return 0;
}

static const
struct ubus_method network_methods[] = {
    { .name = "restart", .handler = handle_restart },
    { .name = "reload", .handler =handle_reload },
    { .name = "get_proto_handlers", .handler = handle_get_protos },
//    UBUS_METHOD("add_host_route", handle_add_host_route, route_policy),
//    UBUS_METHOD("add_dynamic", handle_add_dynamic, dynamic_policy),
};
DECLARE_UBUS_OBJECT(network, "network", network_methods);

static
int ubus_init()
{
    int res = 0;

    log_init("networkd", LOG_DEBUG);

    if ((res = ubus_add_object(ctx, &network_obj))) {
        ERR("Ubus error: %s", ubus_strerror(res));
        return res;
    }

    if ((res = ubus_add_object(ctx, &network_dev_obj))) {
        ERR("Ubus error: %s", ubus_strerror(res));
        return res;
    }

    if ((res = ubus_add_object(ctx, &network_wdev_obj))) {
        ERR("Ubus error: %s", ubus_strerror(res));
        return res;
    }

    if ((res = ubus_add_object(ctx, &network_iface_obj))) {
        ERR("Ubus error: %s", ubus_strerror(res));
        return res;
    }

    DBG("Parsing configuration...\n");

    uci_config_init(uci_config_path);

    uci_config_parse_network(handle_found_interface, NULL, NULL);

    return 0;
}


#ifdef RPCD_PLUGIN 
static
void ubus_cleanup()
{
    struct list_head *p, *n;
    if (ctx) {
        ubus_free(ctx);
        ctx = NULL;
    }

    list_for_each_safe(p, n, &ifaces) {
        struct ubus_interface *iface = list_entry(p, struct ubus_interface, node);
        list_del(p);
        ubus_interface_unref(iface);
    }
}

static
void print_usage(const char *exe) {
    fprintf(stderr, "Usage : %s [<options>]\n"
            "Options:\n"
            "   -s               Socket path to use to connect to ubus deamon.\n"
            "   -c               UCI configuation path.\n"
            "   -v               Increase verbosity, can be used more than once.\n"
            "   -h               Print this help text\n"
            "\n", exe);
}
int main(int argc, char *argv[])
{
    char ch;
    enum LogLevel verbose_level = LOG_WARN;
    const char *ubus_socket = NULL;


    while ((ch = getopt(argc, argv, "s:c:vh")) != -1) {
        switch(ch) {
        case 's':
            ubus_socket = optarg;
            break;
        case 'c':
            uci_config_path = optarg;
            break;
        case 'v':
            verbose_level++;
            break;
        case 'h':
            print_usage(argv[0]);
            return 0;
        default:
            WARN("Ignoring invalid argument '%c'", ch);
            break;
        }
    }

    log_init(verbose_level);

    if ( !(ctx = ubus_connect(ubus_socket))) {
        ERR("Failed to get ubus connection at %s", ubus_socket);
        return -1;
    }
    ubus_add_uloop(ctx);

    ubus_init();
    uloop_run();

    uci_config_cleanup();

    ubus_cleanup();

}
#else
#include <rpcd/plugin.h>

static int
plugin_init(const struct rpc_daemon_ops *o, struct ubus_context *context)
{
    ctx = context;
    ubus_init();
    return 0;
}

struct rpc_plugin rpc_plugin = {
    .init = plugin_init
};

#endif
