// Module, to hit the ip-api endpoint get demographic details, which can latr be used in FIrewall,
//to allow or block access to the device based on the country of origin of the request

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "esp_log.h"
#include "esp_http_client.h"
#include "cJSON.h"

#include "demographic.h"

static const char *TAG = "Demographic Module";
char log_message[64];
char city_var[32];
char country_var[32];
char country_code[8];
bool local_ip_bypass = false;


static void get_demo(const char *ip_address) {
    memset(log_message, 0, sizeof(log_message));
    char url[256];
    snprintf(url, sizeof(url), "http://ip-api.com/json/%s", ip_address);
    
    esp_http_client_config_t config = { .url = url, .timeout_ms = 4000 };
    esp_http_client_handle_t client = esp_http_client_init(&config);
    
    if (esp_http_client_open(client, 0) == ESP_OK) {
        esp_http_client_fetch_headers(client);
        
        char buffer[1024] = {0};
        esp_http_client_read_response(client, buffer, sizeof(buffer));

        cJSON *json = cJSON_Parse(buffer);
        if (json) {
            cJSON *country = cJSON_GetObjectItemCaseSensitive(json, "country");
            cJSON *cc = cJSON_GetObjectItemCaseSensitive(json, "countryCode");
            cJSON *city = cJSON_GetObjectItemCaseSensitive(json, "city");

            if (cc && cJSON_IsString(cc)) {
                const char *print_city = (city && city->valuestring) ? city->valuestring : "Unknown City";
                const char *print_country = (country && country->valuestring) ? country->valuestring : "Unknown Country";
                snprintf(city_var, sizeof(city_var), "%s", print_city);
                snprintf(country_var, sizeof(country_var), "%s", print_country);
                snprintf(country_code, sizeof(country_code), "%s", cc->valuestring);
            }
            cJSON_Delete(json);
        } else {
            ESP_LOGE(TAG, "Failed to parse JSON string response payload.");
        }
    } else {
        ESP_LOGE(TAG, "HTTP connection failed.");
    }
    esp_http_client_cleanup(client);
}


void get_log_message(const char *ip_address){
    if (strncmp(ip_address, "192.168", 7) == 0) {
        ESP_LOGW(TAG, "Local IP address detected, skipping demographic fetch.");
        snprintf(log_message, sizeof(log_message), "Local IP bypass: %s", ip_address);
        return; 
    }
    get_demo(ip_address);
    snprintf(log_message, sizeof(log_message), "%s %s", city_var, country_var);
}

//used by firewall to get the country code
const char* get_code(const char *ip_address){
    if (strncmp(ip_address, "192.168", 7) == 0) {
        return "LOCAL";
    }
    get_demo(ip_address);
    return country_code;
}