#include "interface.h"

struct device;

typedef void (*found_iface_cb_t)(struct interface *iface, void *data);
typedef void (*found_device_cb_t)(struct device *dev, void *data);

int uci_config_parse_network(found_iface_cb_t iface_cb, found_device_cb_t dev_cb, void *data);


typedef void (*found_wiface_cb_t)(struct wifi_interface *wiface, void *data);
typedef void (*found_wdevice_cb_t)(struct wifi_device *wdev, void *data);
int uci_config_parse_wireless(found_wiface_cb_t wiface_cb, found_wdevice_cb_t wdve_cb, void *data);

int uci_config_init(const char *dir);
void uci_config_cleanup();
