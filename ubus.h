#ifndef __CONNMAN_UCI_UBUS_H_
#define __CONNMAN_UCI_UBUS_H_

#include <libubus.h>

int __ubus_init(const char *ubus_socket);
void __ubus_cleanup();

#endif // __CONNMAN_UCI_UBUS_H_
