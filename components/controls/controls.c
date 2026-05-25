// WoL and other functionality control module for ESP32 Web Server

#include <string.h>
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "lwip/err.h"
#include "lwip/sockets.h"
#include "lwip/sys.h"
#include "lwip/netdb.h"
#include "esp_log.h"
#include "esp_random.h"

#include "controls.h"
#include <logger.h>

static const char *TAG = "WoL_CONTROLS";

void send_wakeup_magic_packet(const char *mac_str, const char *command, const char *addr_str) {
    uint8_t target_mac[6];
    char mac_unreadable[18];
    char mask_mac[18];
    char log_msg[256];
    char status[256];
    
    snprintf(mask_mac, sizeof(mask_mac), "%s", mac_str);
    snprintf(mac_unreadable, sizeof(mac_unreadable), "%.5s:xx:xx:xx", mask_mac);
    snprintf(log_msg, sizeof(log_msg), "Command: %s, Target: %s From: %s", command, mac_unreadable, addr_str);

    int parsed_fields = sscanf(mac_str, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx", 
                               &target_mac[0], &target_mac[1], &target_mac[2], 
                               &target_mac[3], &target_mac[4], &target_mac[5]);
                               
    if (parsed_fields != 6) {
        ESP_LOGE(TAG, "Invalid MAC address format layout: %s", mac_str);
        snprintf(status, sizeof(status), "%s", "<div style='color:red;'>Error: Invalid MAC address format.</div>");
        write_log(log_msg, status);
        return;
    }

    uint8_t magic_packet[102];
    memset(magic_packet, 0xFF, 6);
    for (int i = 1; i <= 16; i++) {
        memcpy(&magic_packet[i * 6], target_mac, 6);
    }

    int broadcast_sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_IP);
    if (broadcast_sock < 0) {
        ESP_LOGE(TAG, "Failed to instantiate broadcast socket");
        snprintf(status, sizeof(status), "%s", "<div style='color:red;'>Error: Failed to create broadcast socket.</div>");
        write_log(log_msg, status);
        return;
    }

    int broadcast_permission = 1;
    if (setsockopt(broadcast_sock, SOL_SOCKET, SO_BROADCAST, &broadcast_permission, sizeof(broadcast_permission)) < 0) {
        ESP_LOGE(TAG, "Failed to apply broadcast option permissions");
        snprintf(status, sizeof(status), "%s", "<div style='color:red;'>Error: Broadcast configuration failed.</div>");
        write_log(log_msg, status);
        close(broadcast_sock); 
        return;
    }

    struct sockaddr_in broadcast_addr;
    broadcast_addr.sin_addr.s_addr = inet_addr("255.255.255.255");
    broadcast_addr.sin_family = AF_INET;
    broadcast_addr.sin_port = htons(9); 

    int sent_bytes = sendto(broadcast_sock, magic_packet, sizeof(magic_packet), 0, 
                            (struct sockaddr *)&broadcast_addr, sizeof(broadcast_addr));

    if (sent_bytes < 0) {
        ESP_LOGE(TAG, "Failed to dispatch packet transmission onto network");
        snprintf(status, sizeof(status), "%s", "<div style='color:red;'>Error: Packet transmission failed.</div>");
    } else {
        ESP_LOGI(TAG, "Magic packet successfully broadcasted to hardware targets.");
        snprintf(status, sizeof(status), "%s", "<div style='color:green;'>Magic packet sent successfully.</div>");
    }
    
    write_log(log_msg, status);
    close(broadcast_sock); 
}