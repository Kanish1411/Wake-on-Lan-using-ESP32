#ifndef PING_H
#define PING_H
#include <stdbool.h>
bool ping_device_is_online(const char *target_ip_str, int timeout_ms);
#endif
