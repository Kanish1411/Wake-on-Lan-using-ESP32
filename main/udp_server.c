/* BSD Socket API Example

   This example code is in the Public Domain (or CC0 licensed, at your option.)

   Unless required by applicable law or agreed to in writing, this
   software is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR
   CONDITIONS OF ANY KIND, either express or implied.
*/
#include <string.h>
#include <sys/param.h>
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "esp_system.h"
#include "esp_wifi.h"
#include "esp_event.h"
#include "esp_log.h"
#include "nvs_flash.h"
#include "esp_netif.h"
#include "protocol_examples_common.h"
#include "esp_http_server.h"
#include "esp_log.h"

#include "lwip/err.h"
#include "lwip/sockets.h"
#include "lwip/sys.h"
#include <lwip/netdb.h>

static char log_buffer[10][256] = {
    "System initialized. Awaiting incoming network commands..."
};
static char status_buffer[10][256] = {
    "No commands received yet."
};


static int current_log_idx = 1;

#define PORT CONFIG_EXAMPLE_PORT

static const char *TAG = "ESP_UDP_SERVER";
static void send_wakeup_magic_packet(const char *mac_str, const char *command, const char *addr_str) {
    uint8_t target_mac[6];
    snprintf(log_buffer[current_log_idx], sizeof(log_buffer[current_log_idx]), "Command: %s, Target: %s From: %s", command, mac_str, addr_str);

    int parsed_fields = sscanf(mac_str, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx", 
                               &target_mac[0], &target_mac[1], &target_mac[2], 
                               &target_mac[3], &target_mac[4], &target_mac[5]);
                               
    if (parsed_fields != 6) {
        ESP_LOGE(TAG, "Invalid MAC address format layout: %s", mac_str);
        snprintf(status_buffer[current_log_idx], sizeof(status_buffer[current_log_idx]), "%s", "<div style='color:red;'>Error: Invalid MAC address format.</div>");
        current_log_idx = (current_log_idx + 1) % 10;
        return;
    }

    // --- CONSTRUCT THE MAGIC PACKET ---
    uint8_t magic_packet[102];
    
    // The first 6 bytes must be completely filled with 0xFF
    memset(magic_packet, 0xFF, 6);
    
    // The next 96 bytes contain the physical target MAC address repeated exactly 16 times
    for (int i = 1; i <= 16; i++) {
        memcpy(&magic_packet[i * 6], target_mac, 6);
    }

    // --- BLAST OUT THE UDP BROADCAST ---
    int broadcast_sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_IP);
    if (broadcast_sock < 0) {
        ESP_LOGE(TAG, "Failed to instantiate broadcast socket");
        snprintf(status_buffer[current_log_idx], sizeof(status_buffer[current_log_idx]), "%s", "<div style='color:red;'>Error: Failed to create broadcast socket.</div>");
        current_log_idx = (current_log_idx + 1) % 10;
        return;
    }

    // Essential socket option: Tell the OS kernel we are intentionally sending a broadcast frame
    int broadcast_permission = 1;
    setsockopt(broadcast_sock, SOL_SOCKET, SO_BROADCAST, &broadcast_permission, sizeof(broadcast_permission));

    // Target the absolute local network broadcast layer address
    struct sockaddr_in broadcast_addr;
    broadcast_addr.sin_addr.s_addr = inet_addr("255.255.255.255");
    broadcast_addr.sin_family = AF_INET;
    broadcast_addr.sin_port = htons(9); // Port 9 is the industry standard baseline for WoL listener agents

    // Blast the payload onto the network wire
    sendto(broadcast_sock, magic_packet, sizeof(magic_packet), 0, 
           (struct sockaddr *)&broadcast_addr, sizeof(broadcast_addr));

    ESP_LOGI(TAG, "Magic packet successfully broadcasted to hardware targets.");
    
    snprintf(status_buffer[current_log_idx], sizeof(status_buffer[current_log_idx]), "%s", "<div style='color:green;'>Magic packet sent successfully.</div>");
    current_log_idx = (current_log_idx + 1) % 10;
    close(broadcast_sock);
}


static esp_err_t homepage_action_handler(httpd_req_t *req)
{
    ESP_LOGW("ESP32_ACTION", "Web Server Triggered");
    httpd_resp_set_type(req, "text/html");

    // 1. Send the HTML header chunk
    const char *html_head = "<!DOCTYPE html><html><head><title>ESP32 Web Server</title></head>"
                            "<style>body{ background-color: #121212; color: #00ff66; text-align: center; }</style>"
                            "<body><h1>ESP32 Logs</h1><br>"
                            "<div style='background:#1a1a1e; color:#00ff66; padding:20px; border-radius:6px; "
                            "border:1px solid #29292e; font-family:monospace; text-align:left; "
                            "display:inline-block; width:80%%; max-width:600px; max-height:400px; overflow-y:auto; "
                            "white-space:pre-wrap; line-height:1.6; text-align: center;'>";
    httpd_resp_sendstr_chunk(req, html_head);

    // 2. Loop through and stream your logs directly line-by-line
    for(int i = 0; i < 10; i++) {
        // Only print if the log row actually contains written data
        if (strlen(log_buffer[i]) > 0) {
            char row_buf[261];
            char status_buf[261];
            // Format line cleanly with an HTML line break
            snprintf(row_buf, sizeof(row_buf), "%s", log_buffer[i]);
            snprintf(status_buf, sizeof(status_buf), "%s<br>", status_buffer[i]);
            // Push this line out directly to the network buffer
            httpd_resp_sendstr_chunk(req, row_buf);
            httpd_resp_sendstr_chunk(req, status_buf);
        }
    }

    // 3. Send the HTML footer closing tags
    const char *html_foot = "</div></body></html>";
    httpd_resp_sendstr_chunk(req, html_foot);

    // 4. Send an empty chunk to explicitly tell the browser we are done transmission
    httpd_resp_sendstr_chunk(req, NULL);

    return ESP_OK;
}

static const httpd_uri_t homepage_uri = {
    .uri       = "/",
    .method    = HTTP_GET,
    .handler   = homepage_action_handler,
    .user_ctx  = NULL
};

static void start_my_web_server(void)
{
    httpd_handle_t my_server = NULL;
    httpd_config_t config = HTTPD_DEFAULT_CONFIG(); // This fires up TCP Port 80

    if (httpd_start(&my_server, &config) == ESP_OK) {
        // Register your clean single-page layout
        httpd_register_uri_handler(my_server, &homepage_uri);
        ESP_LOGI("WEB_SERVER", "Web server successfully launched on port 80!");
    }
}

static void udp_server_task(void *pvParameters)
{
    char rx_buffer[128];
    char addr_str[128];
    int addr_family = (int)pvParameters;
    int ip_protocol = 0;
    struct sockaddr_in6 dest_addr;

    while (1) {

        if (addr_family == AF_INET) {
            struct sockaddr_in *dest_addr_ip4 = (struct sockaddr_in *)&dest_addr;
            dest_addr_ip4->sin_addr.s_addr = htonl(INADDR_ANY);
            dest_addr_ip4->sin_family = AF_INET;
            dest_addr_ip4->sin_port = htons(PORT);
            ip_protocol = IPPROTO_IP;
        } else if (addr_family == AF_INET6) {
            bzero(&dest_addr.sin6_addr.un, sizeof(dest_addr.sin6_addr.un));
            dest_addr.sin6_family = AF_INET6;
            dest_addr.sin6_port = htons(PORT);
            ip_protocol = IPPROTO_IPV6;
        }

        int sock = socket(addr_family, SOCK_DGRAM, ip_protocol);
        if (sock < 0) {
            ESP_LOGE(TAG, "Unable to create socket: errno %d", errno);
            break;
        }
        ESP_LOGI(TAG, "Socket created");

#if defined(CONFIG_LWIP_NETBUF_RECVINFO) && !defined(CONFIG_EXAMPLE_IPV6)
        int enable = 1;
        lwip_setsockopt(sock, IPPROTO_IP, IP_PKTINFO, &enable, sizeof(enable));
#endif

#if defined(CONFIG_EXAMPLE_IPV4) && defined(CONFIG_EXAMPLE_IPV6)
        if (addr_family == AF_INET6) {
            // Note that by default IPV6 binds to both protocols, it is must be disabled
            // if both protocols used at the same time (used in CI)
            int opt = 1;
            setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
            setsockopt(sock, IPPROTO_IPV6, IPV6_V6ONLY, &opt, sizeof(opt));
        }
#endif
        // Set timeout
        struct timeval timeout;
        timeout.tv_sec = 10;
        timeout.tv_usec = 0;
        setsockopt (sock, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof timeout);

        int err = bind(sock, (struct sockaddr *)&dest_addr, sizeof(dest_addr));
        if (err < 0) {
            ESP_LOGE(TAG, "Socket unable to bind: errno %d", errno);
        }
        ESP_LOGI(TAG, "Socket bound, port %d", PORT);

        struct sockaddr_storage source_addr; // Large enough for both IPv4 or IPv6
        socklen_t socklen = sizeof(source_addr);

#if defined(CONFIG_LWIP_NETBUF_RECVINFO) && !defined(CONFIG_EXAMPLE_IPV6)
        struct iovec iov;
        struct msghdr msg;
        struct cmsghdr *cmsgtmp;
        u8_t cmsg_buf[CMSG_SPACE(sizeof(struct in_pktinfo))];

        iov.iov_base = rx_buffer;
        iov.iov_len = sizeof(rx_buffer);
        msg.msg_control = cmsg_buf;
        msg.msg_controllen = sizeof(cmsg_buf);
        msg.msg_flags = 0;
        msg.msg_iov = &iov;
        msg.msg_iovlen = 1;
        msg.msg_name = (struct sockaddr *)&source_addr;
        msg.msg_namelen = socklen;
#endif

        while (1) {
            ESP_LOGI(TAG, "Waiting for data");
#if defined(CONFIG_LWIP_NETBUF_RECVINFO) && !defined(CONFIG_EXAMPLE_IPV6)
            int len = recvmsg(sock, &msg, 0);
#else
            int len = recvfrom(sock, rx_buffer, sizeof(rx_buffer) - 1, 0, (struct sockaddr *)&source_addr, &socklen);
#endif
            // Error occurred during receiving
            if (len < 0) {
                ESP_LOGE(TAG, "recvfrom failed: errno %d", errno);
                break;
            }
            // Data received
            else {
                // Get the sender's ip address as string
                if (source_addr.ss_family == PF_INET) {
                    inet_ntoa_r(((struct sockaddr_in *)&source_addr)->sin_addr, addr_str, sizeof(addr_str) - 1);
#if defined(CONFIG_LWIP_NETBUF_RECVINFO) && !defined(CONFIG_EXAMPLE_IPV6)
                    for ( cmsgtmp = CMSG_FIRSTHDR(&msg); cmsgtmp != NULL; cmsgtmp = CMSG_NXTHDR(&msg, cmsgtmp) ) {
                        if ( cmsgtmp->cmsg_level == IPPROTO_IP && cmsgtmp->cmsg_type == IP_PKTINFO ) {
                            struct in_pktinfo *pktinfo;
                            pktinfo = (struct in_pktinfo*)CMSG_DATA(cmsgtmp);
                            ESP_LOGI(TAG, "dest ip: %s", inet_ntoa(pktinfo->ipi_addr));
                        }
                    }
#endif
                } else if (source_addr.ss_family == PF_INET6) {
                    inet6_ntoa_r(((struct sockaddr_in6 *)&source_addr)->sin6_addr, addr_str, sizeof(addr_str) - 1);
                }

                rx_buffer[len] = 0; // Null-terminate whatever we received and treat like a string...
                char *command = strtok(rx_buffer, " ");

                // 2. Validate that the command is actually "connect"
                if (command != NULL && strncmp(command, "ping", 4) == 0) {
                    
                    // 3. Extract the second token (The Target Address)
                    // Passing NULL tells strtok to continue scanning the same buffer from where it left off
                    char *target_addr = strtok(NULL, " ");
                    
                    if (target_addr != NULL) {
                        ESP_LOGI(TAG, "Command: %s", command);
                        ESP_LOGI(TAG, "Target Address Extracted: %s", target_addr);
                        ESP_LOGI(TAG, "Address Extracted: %s", addr_str);
                        
                        send_wakeup_magic_packet(target_addr, command, addr_str);
                        
                        
                    } else {
                        ESP_LOGW(TAG, "Missing target address parameter!");
                        snprintf(log_buffer[current_log_idx], sizeof(log_buffer[current_log_idx]), "Command: %s, Missing Target Address From: %s", command, addr_str);
                        snprintf(status_buffer[current_log_idx], sizeof(status_buffer[current_log_idx]), "%s", "<div style='color:red;'>Error: Missing target address.</div>");
                        current_log_idx = (current_log_idx + 1) % 10;
                    }
                }

                int err = sendto(sock, rx_buffer, len, 0, (struct sockaddr *)&source_addr, sizeof(source_addr));
                if (err < 0) {
                    ESP_LOGE(TAG, "Error occurred during sending: errno %d", errno);
                    break;
                }
            }
        }

        if (sock != -1) {
            ESP_LOGE(TAG, "Shutting down socket and restarting...");
            shutdown(sock, 0);
            close(sock);
        }
    }
    vTaskDelete(NULL);
}

void app_main(void)
{
    ESP_ERROR_CHECK(nvs_flash_init());
    ESP_ERROR_CHECK(esp_netif_init());
    ESP_ERROR_CHECK(esp_event_loop_create_default());

    /* This helper function configures Wi-Fi or Ethernet, as selected in menuconfig.
     * Read "Establishing Wi-Fi or Ethernet Connection" section in
     * examples/protocols/README.md for more information about this function.
     */
    ESP_ERROR_CHECK(example_connect());
    start_my_web_server();

#ifdef CONFIG_EXAMPLE_IPV4
    xTaskCreate(udp_server_task, "udp_server", 4096, (void*)AF_INET, 5, NULL);
#endif
#ifdef CONFIG_EXAMPLE_IPV6
    xTaskCreate(udp_server_task, "udp_server", 4096, (void*)AF_INET6, 5, NULL);
#endif

}
