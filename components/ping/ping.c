#include <string.h>
#include <unistd.h>
#include "lwip/sockets.h"
#include "lwip/inet.h"
#include "esp_log.h"

#define ICMP_ECHO_REQUEST 8

struct icmp_echo_packet {
    uint8_t  type;
    uint8_t  code;
    uint16_t checksum;
    uint16_t id;
    uint16_t sequence;
    char     payload[32]; 
};

// Standard Internet Checksum computation algorithm
static uint16_t calculate_checksum(uint16_t *addr, int count) {
    uint32_t sum = 0;
    while (count > 1) {
        sum += *addr++;
        count -= 2;
    }
    if (count > 0) {
        sum += *(uint8_t *)addr;
    }
    while (sum >> 16) {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    return (uint16_t)(~sum);
}

// Synchronous check: Returns true if device answers, false otherwise
bool ping_device_is_online(const char *target_ip_str, int timeout_ms) {
    int sock = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
    if (sock < 0) {
        ESP_LOGE("PING_CHECK", "Failed to allocate raw network socket slot");
        return false;
    }

    // Bind socket blocking timeout constraints
    struct timeval tv_timeout;
    tv_timeout.tv_sec = timeout_ms / 1000;
    tv_timeout.tv_usec = (timeout_ms % 1000) * 1000;
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv_timeout, sizeof(tv_timeout));

    struct sockaddr_in target_addr;
    memset(&target_addr, 0, sizeof(target_addr));
    target_addr.sin_family = AF_INET;
    target_addr.sin_addr.s_addr = inet_addr(target_ip_str);

    // Build the structural payload elements
    struct icmp_echo_packet packet;
    memset(&packet, 0, sizeof(packet));
    packet.type = ICMP_ECHO_REQUEST;
    packet.code = 0;
    packet.id = 0x1234;
    packet.sequence = 1;
    strcpy(packet.payload, "ESP32_PING_PROBE_REQUEST_PING");
    packet.checksum = calculate_checksum((uint16_t *)&packet, sizeof(packet));

    int sent = sendto(sock, &packet, sizeof(packet), 0, 
                      (struct sockaddr *)&target_addr, sizeof(target_addr));
    if (sent <= 0) {
        close(sock);
        return false;
    }

    // Wait for incoming response frames
    char rx_buffer[128];
    struct sockaddr_in from_addr;
    socklen_t from_len = sizeof(from_addr);

    int received = recvfrom(sock, rx_buffer, sizeof(rx_buffer), 0, 
                            (struct sockaddr *)&from_addr, &from_len);

    close(sock); 

    if (received > 0) {
        ESP_LOGI("PING_CHECK", "Host %s is ONLINE", target_ip_str);
        return true;
    }

    ESP_LOGW("PING_CHECK", "Host %s is OFFLINE (Timeout)", target_ip_str);
    return false;
}