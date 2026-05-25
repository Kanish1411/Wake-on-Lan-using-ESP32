// Log module to log WoL actions and access attempts
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <sys/time.h>

#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "esp_log.h"     
#include "esp_sntp.h"
#include "logger.h"

static char log_buffer[32][256]; 
static char status_buffer[32][256];
static int current_log_idx = 1;
static char timestamp[32];

void init_sntp_time(void)
{
    ESP_LOGI("SNTP", "Initializing SNTP Engine...");
    esp_sntp_setoperatingmode(SNTP_OPMODE_POLL);
    esp_sntp_setservername(0, "time.google.com"); 
    esp_sntp_init();
    setenv("TZ", "IST-5:30", 1);
    tzset();
        while (sntp_get_sync_status() == SNTP_SYNC_STATUS_RESET) {
            ESP_LOGI("SNTP", "Waiting for time synchronization...");
            vTaskDelay(2000 / portTICK_PERIOD_MS);
        }
    ESP_LOGI("SNTP", "SNTP Engine initialized and time synchronized.");
}

void get_timestamp_str(char *buf, size_t max_len)
{
    time_t now;
    struct tm timeinfo;
    time(&now);
    localtime_r(&now, &timeinfo);
    
    strftime(buf, max_len, "%Y-%m-%d %H:%M:%S", &timeinfo);
}

void write_log(const char *message,const char *status) {
    get_timestamp_str(timestamp, sizeof(timestamp));
    snprintf(log_buffer[current_log_idx], sizeof(log_buffer[current_log_idx]), "[%s] %s", timestamp, message);
    snprintf(status_buffer[current_log_idx], sizeof(status_buffer[current_log_idx]), "%s", status);
    current_log_idx = (current_log_idx + 1) % 32;
}
void get_logs(const char *out_log_buffer[32], const char *out_status_buffer[32]) {
    for (int i = 0; i < 32; i++) {
        out_log_buffer[i]   = log_buffer[i];
        out_status_buffer[i] = status_buffer[i];
    }
}