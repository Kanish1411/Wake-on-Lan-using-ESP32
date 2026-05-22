/* BSD Socket API Example

   This example code is in the Public Domain (or CC0 licensed, at your option.)

   Unless required by applicable law or agreed to in writing, this
   software is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR
   CONDITIONS OF ANY KIND, either express or implied.
*/
#include <string.h>
#include <ctype.h>
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
#include "esp_https_server.h"

#include "lwip/err.h"
#include "lwip/sockets.h"
#include "lwip/sys.h"
#include <lwip/netdb.h>
#include <time.h>
#include <sys/time.h>
#include "esp_sntp.h"


static char log_buffer[32][256] = {
    "System initialized. Awaiting incoming network commands..."
};
static char status_buffer[32][256] = {
    "No commands received yet."
};

static int current_log_idx = 1;

#define PORT CONFIG_EXAMPLE_PORT

static const char *TAG = "ESP_UDP_SERVER";
#define MAX_SESSIONS 4
#define SESSION_TOKEN_LEN 16

typedef struct {
    char ip[48];
    char token[SESSION_TOKEN_LEN + 1];
    int64_t expiry_time;
    char location[64];
} client_session_t;

static client_session_t session_table[MAX_SESSIONS];
static char timestamp[32];

extern const unsigned char servercert_start[] asm("_binary_servercert_pem_start");
extern const unsigned char servercert_end[]   asm("_binary_servercert_pem_end");
extern const unsigned char prkey_start[] asm("_binary_prkey_pem_start");
extern const unsigned char prkey_end[]   asm("_binary_prkey_pem_end");

void init_sntp_time(void)
{
    ESP_LOGI("SNTP", "Initializing SNTP Engine...");
    esp_sntp_setoperatingmode(SNTP_OPMODE_POLL);
    esp_sntp_setservername(0, "time.google.com"); // Global NTP server pool
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

static void url_decode(char *dst, const char *src) {
    char a, b;
    while (*src) {
        if ((*src == '%') &&
            ((a = src[1]) && (b = src[2])) &&
            (isxdigit((int)a) && isxdigit((int)b))) {
            if (a >= 'a') a -= 'a' - 10;
            else if (a >= 'A') a -= 'A' - 10;
            else a -= '0';
            if (b >= 'a') b -= 'a' - 10;
            else if (b >= 'A') b -= 'A' - 10;
            else b -= '0';
            
            *dst++ = 16 * a + b;
            src += 3;
        } else if (*src == '+') {
            *dst++ = ' ';
            src++;
        } else {
            *dst++ = *src++;
        }
    }
    *dst = '\0';
}

static void get_client_ip(httpd_req_t *req, char *ip_str, size_t max_len) {
    strncpy(ip_str, "Unknown", max_len);
    int sockfd = httpd_req_to_sockfd(req);        
    if (sockfd >= 0) {
        struct sockaddr_storage addr;
        socklen_t len = sizeof(addr);
        if (getpeername(sockfd, (struct sockaddr *)&addr, &len) == 0) {
            if (addr.ss_family == AF_INET) {
                struct sockaddr_in *s = (struct sockaddr_in *)&addr;
                inet_ntoa_r(s->sin_addr, ip_str, max_len);
            } else if (addr.ss_family == AF_INET6) {
                struct sockaddr_in6 *s = (struct sockaddr_in6 *)&addr;
                if (IN6_IS_ADDR_V4MAPPED(&s->sin6_addr)) {
                    uint8_t *ipv4 = (uint8_t *)&s->sin6_addr.s6_addr[12];
                    snprintf(ip_str, max_len, "%d.%d.%d.%d", ipv4[0], ipv4[1], ipv4[2], ipv4[3]);
                } else {
                    inet6_ntoa_r(s->sin6_addr, ip_str, max_len);
                }
            }
        }
    }
}

static void send_wakeup_magic_packet(const char *mac_str, const char *command, const char *addr_str) {
    uint8_t target_mac[6];
    char mac_unreadable[18];
    char mask_mac[18];
    snprintf(mask_mac, sizeof(mask_mac), "%s", mac_str);
    snprintf(mac_unreadable, sizeof(mac_unreadable), "%.5s:xx:xx:xx:xx", mask_mac);
    
    get_timestamp_str(timestamp, sizeof(timestamp));
    snprintf(log_buffer[current_log_idx], sizeof(log_buffer[current_log_idx]), "[%s] Command: %s, Target: %s From: %s", timestamp, command, mac_unreadable, addr_str);

    int parsed_fields = sscanf(mac_str, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx", 
                               &target_mac[0], &target_mac[1], &target_mac[2], 
                               &target_mac[3], &target_mac[4], &target_mac[5]);
                               
    if (parsed_fields != 6) {
        ESP_LOGE(TAG, "Invalid MAC address format layout: %s", mac_str);
        snprintf(status_buffer[current_log_idx], sizeof(status_buffer[current_log_idx]), "%s", "<div style='color:red;'>Error: Invalid MAC address format.</div>");
        current_log_idx = (current_log_idx + 1) % 10;
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
        snprintf(status_buffer[current_log_idx], sizeof(status_buffer[current_log_idx]), "%s", "<div style='color:red;'>Error: Failed to create broadcast socket.</div>");
        current_log_idx = (current_log_idx + 1) % 10;
        return;
    }

    int broadcast_permission = 1;
    setsockopt(broadcast_sock, SOL_SOCKET, SO_BROADCAST, &broadcast_permission, sizeof(broadcast_permission));

    struct sockaddr_in broadcast_addr;
    broadcast_addr.sin_addr.s_addr = inet_addr("255.255.255.255");
    broadcast_addr.sin_family = AF_INET;
    broadcast_addr.sin_port = htons(9); 

    sendto(broadcast_sock, magic_packet, sizeof(magic_packet), 0, 
           (struct sockaddr *)&broadcast_addr, sizeof(broadcast_addr));

    ESP_LOGI(TAG, "Magic packet successfully broadcasted to hardware targets.");
    
    snprintf(status_buffer[current_log_idx], sizeof(status_buffer[current_log_idx]), "%s", "<div style='color:green;'>Magic packet sent successfully.</div>");
    current_log_idx = (current_log_idx + 1) % 10;
    close(broadcast_sock);
}

static bool is_logged_in(httpd_req_t *req) {
    char ip_str[48] = {0};
    get_client_ip(req, ip_str, sizeof(ip_str));

    char cookie_buf[128] = {0};
    size_t header_len = httpd_req_get_hdr_value_len(req, "Cookie");

    if (header_len > 0 && header_len < sizeof(cookie_buf)) {
        if (httpd_req_get_hdr_value_str(req, "Cookie", cookie_buf, sizeof(cookie_buf)) == ESP_OK) {
            for (int i = 0; i < MAX_SESSIONS; i++) {
                if (strlen(session_table[i].token) > 0 && 
                    strcmp(session_table[i].ip, ip_str) == 0 && 
                    strstr(cookie_buf, session_table[i].token) != NULL) {
                    return true; 
                }
            }
        }
    }
    get_timestamp_str(timestamp, sizeof(timestamp));
    snprintf(log_buffer[current_log_idx], sizeof(log_buffer[current_log_idx]), "[%s] Unauthorized access attempt from: %s", timestamp, ip_str);
    snprintf(status_buffer[current_log_idx], sizeof(status_buffer[current_log_idx]), "%s", "<div style='color:red;'>Unauthorized access. Please log in.</div>");
    current_log_idx = (current_log_idx + 1) % 10;
    return false;
}

static esp_err_t login_page(httpd_req_t *req)
{
    char ip_str[48] = {0};
    get_client_ip(req, ip_str, sizeof(ip_str));
    
    bool already_logged = false;
    char cookie_buf[128] = {0};
    size_t header_len = httpd_req_get_hdr_value_len(req, "Cookie");

    if (header_len > 0 && header_len < sizeof(cookie_buf)) {
        if (httpd_req_get_hdr_value_str(req, "Cookie", cookie_buf, sizeof(cookie_buf)) == ESP_OK) {
            for (int i = 0; i < MAX_SESSIONS; i++) {
                if (strlen(session_table[i].token) > 0 && 
                    strcmp(session_table[i].ip, ip_str) == 0 && 
                    strstr(cookie_buf, session_table[i].token) != NULL) {
                    already_logged = true;
                    break;
                }
            }
        }
    }
    if (!already_logged) {
        httpd_resp_set_type(req, "text/html");
        httpd_resp_sendstr_chunk(req, "<!DOCTYPE html><html><head><title>Login</title></head>"
                                    "<style>body{ background-color: #121212; color: #00ff66; text-align: center; }</style>"
                                    "<body><h1>Login</h1><br>"
                                    "<form method='POST' action='/login'>"
                                    "<input type='text' name='username' placeholder='Username'><br><br>"
                                    "<input type='password' name='password' placeholder='Password'><br><br>"
                                    "<input type='submit' value='Login'>"
                                    "</form></body></html>");
        httpd_resp_sendstr_chunk(req, NULL);
    } else {
        httpd_resp_set_status(req, "303 See Other");
        httpd_resp_set_hdr(req, "Location", "/");
        httpd_resp_sendstr_chunk(req, NULL);
    }
    return ESP_OK;
}

static esp_err_t login_action_handler(httpd_req_t *req)
{
    char content[128] = {0};
    size_t recv_size = req->content_len;

    if (recv_size >= sizeof(content)) {
        httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "Payload too large");
        return ESP_FAIL;
    }

    int ret = httpd_req_recv(req, content, recv_size);
    if (ret <= 0) return ESP_FAIL;
    content[recv_size] = '\0'; 

    char username[32] = {0};
    char password[128] = {0};

    if (httpd_query_key_value(content, "username", username, sizeof(username)) == ESP_OK &&
        httpd_query_key_value(content, "password", password, sizeof(password)) == ESP_OK) {

        if (strcmp(username, "admin") == 0 && strcmp(password, "admin") == 0) {
            
            char ip_str[48] = {0};
            get_client_ip(req, ip_str, sizeof(ip_str)); 

            char generated_token[17] = {0};
            snprintf(generated_token, sizeof(generated_token), "%08lx%08lx", esp_random(), esp_random());

            int slot_to_use = 0; 
            for(int i = 0; i < MAX_SESSIONS; i++) {
                if(strlen(session_table[i].token) == 0 || strcmp(session_table[i].ip, ip_str) == 0) {
                    slot_to_use = i;
                    break;
                }
            }
            
            strcpy(session_table[slot_to_use].ip, ip_str);
            strcpy(session_table[slot_to_use].token, generated_token);
            

            char cookie_header[128];
            snprintf(cookie_header, sizeof(cookie_header), "session=%s; Path=/; HttpOnly; Secure", generated_token);

            httpd_resp_set_status(req, "303 See Other");
            httpd_resp_set_hdr(req, "Location", "/");
            httpd_resp_set_hdr(req, "Set-Cookie", cookie_header);
            httpd_resp_sendstr_chunk(req, NULL);
            return ESP_OK;
        }
    }

    httpd_resp_set_status(req, "303 See Other");
    httpd_resp_set_hdr(req, "Location", "/login");
    httpd_resp_sendstr_chunk(req, NULL);
    return ESP_OK;
}

static esp_err_t homepage_action_handler(httpd_req_t *req){
    if (!is_logged_in(req)) {
        httpd_resp_set_status(req, "303 See Other");
        httpd_resp_set_hdr(req, "Location", "/login");
        httpd_resp_sendstr_chunk(req, NULL);
        return ESP_OK;
    }
    
    httpd_resp_set_type(req, "text/html");
    httpd_resp_sendstr_chunk(req,  "<!DOCTYPE html><html><head><title>ESP32 Web Server</title></head>"
                                "<style>body{ background-color: #121212; color: #00ff66; text-align: center; }</style>"
                                "<body><h1>ESP32 Control Portal</h1><br>"
                                "<div style='background:#1a1a1e; color:#00ff66; padding:20px; border-radius:6px; "
                                "border:1px solid #29292e; font-family:monospace; text-align:left; display:inline-block;'> "
                                "<button onclick=\"location.href='/logs'\">View Logs</button><br><br>"
                                "<button onclick=\"location.href='/wol'\">Send WoL Packet</button></div></body></html>");
    httpd_resp_sendstr_chunk(req, NULL);
    return ESP_OK;
}

static esp_err_t wol_handler(httpd_req_t *req){
    if (!is_logged_in(req)) {
        httpd_resp_set_status(req, "303 See Other");
        httpd_resp_set_hdr(req, "Location", "/login");
        httpd_resp_sendstr_chunk(req, NULL);
        return ESP_OK;
    }
    httpd_resp_set_type(req, "text/html");
    httpd_resp_sendstr_chunk(req, "<!DOCTYPE html><html><head><title>ESP32 Web Server</title></head>"
                                "<style>body{ background-color: #121212; color: #00ff66; text-align: center; }</style>"
                                "<body><h1>Send Wake-on-LAN Packet</h1><br>"
                                "<form method='POST' action='/wol'>"
                                "<input type='text' name='mac' placeholder='Target MAC Address (e.g. AA:BB:CC:DD:EE:FF)'><br><br>"
                                "<input type='submit' value='Send WoL Packet'>"
                                "</form> <button onclick=\"location.href='/'\">Back to Home</button>"
                                "</body></html>");
    httpd_resp_sendstr_chunk(req, NULL);    
    return ESP_OK;
}

static esp_err_t wol_action_handler(httpd_req_t *req){
    if (!is_logged_in(req)) {
        httpd_resp_set_status(req, "303 See Other");
        httpd_resp_set_hdr(req, "Location", "/login");
        httpd_resp_sendstr_chunk(req, NULL);
        return ESP_OK;
    }
    char content[128] = {0};
    size_t recv_size = req->content_len;

    if (recv_size >= sizeof(content)) {
        httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "Payload too large");
        return ESP_FAIL;
    }

    int ret = httpd_req_recv(req, content, recv_size);
    if (ret <= 0) return ESP_FAIL;
    content[recv_size] = '\0'; 

    char mac[32] = {0};

    if (httpd_query_key_value(content, "mac", mac, sizeof(mac)) == ESP_OK) {
        char ip_str[48] = {0};
        char decoded_mac[32] = {0};
        url_decode(decoded_mac, mac);
        get_client_ip(req, ip_str, sizeof(ip_str));
        get_timestamp_str(timestamp, sizeof(timestamp));
        snprintf(log_buffer[current_log_idx], sizeof(log_buffer[current_log_idx]), "[%s] WoL command received for MAC: %.5s:xx:xx:xx:xx from IP: %s", timestamp, decoded_mac, ip_str);
        snprintf(status_buffer[current_log_idx], sizeof(status_buffer[current_log_idx]), "%s", "<div style='color:green;'>WoL command received. Attempting to send magic packet...</div>");
        current_log_idx = (current_log_idx + 1) % 10;
        send_wakeup_magic_packet(decoded_mac, "Manual WoL Trigger", ip_str);
    }
    return ESP_OK;
}

static esp_err_t log_handler(httpd_req_t *req)
{
    ESP_LOGW("ESP32_ACTION", "Log Page Triggered");
    if (!is_logged_in(req)) {
        char ip_str[48] = {0};
        get_client_ip(req, ip_str, sizeof(ip_str));
        get_timestamp_str(timestamp, sizeof(timestamp));
        snprintf(log_buffer[current_log_idx], sizeof(log_buffer[current_log_idx]), "[%s] Unauthenticated user accessed log page from IP: %s", timestamp, ip_str);
        snprintf(status_buffer[current_log_idx], sizeof(status_buffer[current_log_idx]), "%s", "<div style='color:red;'>Access denied. Please log in.</div>");
        current_log_idx = (current_log_idx + 1) % 10;
        httpd_resp_set_status(req, "303 See Other");
        httpd_resp_set_hdr(req, "Location", "/login");
        httpd_resp_sendstr_chunk(req, NULL);
        return ESP_OK;
    }
    
    char ip_str[48] = {0};
    get_client_ip(req, ip_str, sizeof(ip_str));
    
    httpd_resp_set_type(req, "text/html");
    httpd_resp_sendstr_chunk(req,  "<!DOCTYPE html><html><head><title>ESP32 Web Server</title></head>"
                                "<style>body{ background-color: #121212; color: #00ff66; text-align: center; }</style>"
                                "<body><h1>ESP32 Logs</h1><br>"
                                "<div style='background:#1a1a1e; color:#00ff66; padding:20px; border-radius:6px; "
                                "border:1px solid #29292e; font-family:monospace; text-align:left; "
                                "display:inline-block; width:80%%; max-width:600px; max-height:400px; overflow-y:auto; "
                                "white-space:pre-wrap; line-height:1.6;'>");

    for(int i = 0; i < 10; i++) {
        if (strlen(log_buffer[i]) > 0) {
            httpd_resp_sendstr_chunk(req, log_buffer[i]);
            httpd_resp_sendstr_chunk(req, status_buffer[i]);
            httpd_resp_sendstr_chunk(req, "<br>");
        }
    }

    httpd_resp_sendstr_chunk(req, "</div><br><br><button onclick=\"location.href='/'\">Back to Home</button></body></html>");
    httpd_resp_sendstr_chunk(req, NULL);

    return ESP_OK;
}



static void start_my_web_server(void)
{
    httpd_handle_t my_server = NULL;
    httpd_ssl_config_t config = HTTPD_SSL_CONFIG_DEFAULT();
    config.servercert = servercert_start;
    config.servercert_len = servercert_end - servercert_start;
    config.prvtkey_pem = prkey_start;
    config.prvtkey_len = prkey_end - prkey_start;

    ESP_LOGI(TAG, "Launching secure engine on port 443...");
    if (httpd_ssl_start(&my_server, &config) == ESP_OK) {
        
        httpd_uri_t uri_home = {
            .uri      = "/",
            .method   = HTTP_GET,
            .handler  = homepage_action_handler, 
            .user_ctx = NULL
        };
        httpd_uri_t uri_login = {
            .uri      = "/login",
            .method   = HTTP_GET,
            .handler  = login_page, 
            .user_ctx = NULL
        };

        httpd_uri_t uri_login_post = {
            .uri      = "/login",
            .method   = HTTP_POST,
            .handler  = login_action_handler,
            .user_ctx = NULL
        };
        httpd_uri_t uri_logs = {
            .uri      = "/logs",
            .method   = HTTP_GET,
            .handler  = log_handler, 
            .user_ctx = NULL
        };
        httpd_uri_t uri_wol = {
            .uri      = "/wol",
            .method   = HTTP_GET,
            .handler  = wol_handler, 
            .user_ctx = NULL
        };
        httpd_uri_t uri_wol_action = {
            .uri      = "/wol",
            .method   = HTTP_POST,
            .handler  = wol_action_handler,
            .user_ctx = NULL
        };
        httpd_register_uri_handler(my_server, &uri_home);
        httpd_register_uri_handler(my_server, &uri_login);
        httpd_register_uri_handler(my_server, &uri_login_post);
        httpd_register_uri_handler(my_server, &uri_logs);
        httpd_register_uri_handler(my_server, &uri_wol);
        httpd_register_uri_handler(my_server, &uri_wol_action);

        ESP_LOGI(TAG, "HTTPS Web Server successfully deployed!");
    } else {
        ESP_LOGE(TAG, "Critical: HTTPS engine initialization failed!");
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
            int opt = 1;
            setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
            setsockopt(sock, IPPROTO_IPV6, IPV6_V6ONLY, &opt, sizeof(opt));
        }
#endif
        struct timeval timeout;
        timeout.tv_sec = 10;
        timeout.tv_usec = 0;
        setsockopt (sock, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof timeout);

        int err = bind(sock, (struct sockaddr *)&dest_addr, sizeof(dest_addr));
        if (err < 0) {
            ESP_LOGE(TAG, "Socket unable to bind: errno %d", errno);
        }
        ESP_LOGI(TAG, "Socket bound, port %d", PORT);

        struct sockaddr_storage source_addr; 
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
            if (len < 0) {
                ESP_LOGE(TAG, "recvfrom failed: errno %d", errno);
                break;
            }
            else {
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

                rx_buffer[len] = 0; 
                char *command = strtok(rx_buffer, " ");

                if (command != NULL && strncmp(command, "ping", 4) == 0) {
                    char *target_addr = strtok(NULL, " ");
                    if (target_addr != NULL) {
                        ESP_LOGI(TAG, "Command: %s", command);
                        ESP_LOGI(TAG, "Target Address Extracted: %s", target_addr);
                        ESP_LOGI(TAG, "Address Extracted: %s", addr_str);
                        
                        send_wakeup_magic_packet(target_addr, command, addr_str);
                    } else {
                        ESP_LOGW(TAG, "Missing target address parameter!");
                        get_timestamp_str(timestamp, sizeof(timestamp));
                        snprintf(log_buffer[current_log_idx], sizeof(log_buffer[current_log_idx]), "[%s] Command: %s, Missing Target Address From: %s", timestamp, command, addr_str);
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
    ESP_ERROR_CHECK(example_connect());

    init_sntp_time();
    start_my_web_server();

#ifdef CONFIG_EXAMPLE_IPV4
    xTaskCreate(udp_server_task, "udp_server", 4096, (void*)AF_INET, 5, NULL);
#endif
#ifdef CONFIG_EXAMPLE_IPV6
    xTaskCreate(udp_server_task, "udp_server", 4096, (void*)AF_INET6, 5, NULL);
#endif
}