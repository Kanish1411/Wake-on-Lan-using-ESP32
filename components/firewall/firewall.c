//LAyer 7 firewall.c

#include "firewall.h"
#include <string.h>
#include "esp_log.h"
#include <demographic.h>
#include <logger.h>

static const char *TAG = "FIREWALL -- initial";

bool is_allowed(httpd_req_t *req, const char *ip_str) {
    const char *cc = get_code(ip_str);
    
    if (strcmp(cc, "IN") == 0 || strcmp(cc, "LOCAL") == 0) {
        ESP_LOGI(TAG, "Access allowed for IP: %s Country Code: %s", ip_str, cc);
        return true;
    }
    
    ESP_LOGW(TAG, "Access denied for IP: %s Country Code: %s", ip_str, cc);
    char formatted_message[256];
    snprintf(formatted_message, sizeof(formatted_message), "Blocked IP: %s Country Code: %s", ip_str, cc);
    write_log(formatted_message, "<div style='color:red;'>Access denied due to firewall rules.</div>");
    httpd_resp_send_err(req, HTTPD_403_FORBIDDEN, "Region Blocked: Access denied from your location.");
    return false;
}