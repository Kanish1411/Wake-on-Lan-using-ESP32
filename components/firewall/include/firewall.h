#ifndef FIREWALL_H
#define FIREWALL_H
#include "esp_http_server.h"
#include <stdbool.h>
bool is_allowed(httpd_req_t *req, const char *ip_str);
#endif
