#include <string.h>
#include "nvs_flash.h"
#include "esp_netif.h"
#include "esp_event.h"
#include "protocol_examples_common.h"

// Component Modules
#include <logger.h>
#include <web_server.h>

void app_main(void)
{
    ESP_ERROR_CHECK(nvs_flash_init());
    ESP_ERROR_CHECK(esp_netif_init());
    ESP_ERROR_CHECK(esp_event_loop_create_default());
    
    ESP_ERROR_CHECK(example_connect());

    init_sntp_time();
    write_log("System initialized.", "Awaiting incoming web panel connections.");

    start_my_web_server();
}