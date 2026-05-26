// Web_server module for ESP32 WoL project


#include <string.h>
#include <ctype.h>
#include <sys/param.h>
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "lwip/err.h"
#include "lwip/sockets.h"
#include "lwip/sys.h"
#include "lwip/netdb.h"
#include "esp_netif.h"
#include "esp_log.h"
#include "esp_random.h"       
#include "esp_https_server.h"


#include <logger.h>              
#include "web_server.h"
#include <controls.h>

#define MAX_SESSIONS 4
#define SESSION_TOKEN_LEN 16
static const char *TAG = "WEB_SERVER";

typedef struct {
    char ip[48];
    char token[SESSION_TOKEN_LEN + 1];
    int64_t expiry_time;
    char location[64];
} client_session_t;

static client_session_t session_table[MAX_SESSIONS];

extern const unsigned char servercert_start[] asm("_binary_servercert_pem_start");
extern const unsigned char servercert_end[]   asm("_binary_servercert_pem_end");
extern const unsigned char prkey_start[] asm("_binary_prkey_pem_start");
extern const unsigned char prkey_end[]   asm("_binary_prkey_pem_end");

static void url_decode(char *dst, const char *src) {
    while (*src) {
        unsigned int val;
        if (*src == '%' && sscanf(src + 1, "%2x", &val) == 1) {
            *dst++ = (char)val;
            src += 3;
        } else {
            *dst++ = (*src == '+') ? ' ' : *src;
            src++;
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

//changed to auth after implementing Crypto
static bool is_logged_in(httpd_req_t *req, const char *location) {
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
    static char timestamp[32];
    get_timestamp_str(timestamp, sizeof(timestamp));
    char formatted_message[256];
    snprintf(formatted_message, sizeof(formatted_message), 
             "Unauthenticated access attempt to %s from IP: %s", 
             location, ip_str);
    write_log(formatted_message, "<div style='color:red;'>Access denied. Please log in.</div>");
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
    if (!is_logged_in(req,"homepage")) {
        httpd_resp_set_status(req, "303 See Other");
        httpd_resp_set_hdr(req, "Location", "/login");
        httpd_resp_sendstr_chunk(req, NULL);
        return ESP_OK;
    }
    
    httpd_resp_set_type(req, "text/html");
    httpd_resp_sendstr_chunk(req,  "<!DOCTYPE html><html><head><title>ESP32 Web Server v1.1</title></head>"
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
    if (!is_logged_in(req,"wol")) {
        httpd_resp_set_status(req, "303 See Other");
        httpd_resp_set_hdr(req, "Location", "/login");
        httpd_resp_sendstr_chunk(req, NULL);
        return ESP_OK;
    }
    httpd_resp_set_type(req, "text/html");
    httpd_resp_sendstr_chunk(req, "<!DOCTYPE html><html><head><title>ESP32 Web Server v1.1</title></head>"
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
    if (!is_logged_in(req,"wol POST")) {
        httpd_resp_set_status(req, "303 See Other");
        httpd_resp_set_hdr(req, "Location", "/login");
        httpd_resp_sendstr_chunk(req, NULL);
        return ESP_OK;
    }
    char content[128] = {0};
    size_t recv_size = req->content_len;

    if (recv_size >= sizeof(content)) {
        httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "Payload too large");
        httpd_resp_set_status(req, "303 See Other");
        httpd_resp_set_hdr(req, "Location", "/logs"); 
        httpd_resp_sendstr_chunk(req, NULL);
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
        char formatted_message[256];
        snprintf(formatted_message, sizeof(formatted_message), 
                "WoL command received for MAC: %.5s:xx:xx:xx:xx from IP: %s",  decoded_mac, ip_str);
        write_log(formatted_message, "<div style='color:green;'>WoL command received. Attempting to send magic packet...</div>");
        send_wakeup_magic_packet(decoded_mac, "Manual WoL Trigger", ip_str);
        
    }
    httpd_resp_set_status(req, "303 See Other");
    httpd_resp_set_hdr(req, "Location", "/logs"); 
    httpd_resp_sendstr_chunk(req, NULL);
    return ESP_OK;
}

static esp_err_t log_handler(httpd_req_t *req)
{
    ESP_LOGW("ESP32_ACTION", "Log Page Triggered");
    if (!is_logged_in(req,"LOG Page")) {
        httpd_resp_set_status(req, "303 See Other");
        httpd_resp_set_hdr(req, "Location", "/login");
        httpd_resp_sendstr_chunk(req, NULL);
        return ESP_OK;
    }
    
    httpd_resp_set_type(req, "text/html");
    httpd_resp_sendstr_chunk(req,  "<!DOCTYPE html><html><head><title>ESP32 Web Server v1.1</title></head>"
                                "<style>body{ background-color: #121212; color: #00ff66; text-align: center; }</style>"
                                "<body><h1>ESP32 Logs</h1><br>"
                                "<div style='background:#1a1a1e; color:#00ff66; padding:20px; border-radius:6px; "
                                "border:1px solid #29292e; font-family:monospace; text-align:left; "
                                "display:inline-block; width:80%%; max-width:1000px; max-height:600px; overflow-y:auto; "
                                "white-space:pre-wrap; line-height:1.6;'>");
        const char *log_ptrs[32];
        const char *status_ptrs[32];

        get_logs(log_ptrs, status_ptrs);

        for (int i = 0; i < 32; i++) {
            if (log_ptrs[i] != NULL && strlen(log_ptrs[i]) > 0) {
            httpd_resp_sendstr_chunk(req, log_ptrs[i]);
            httpd_resp_sendstr_chunk(req, status_ptrs[i]);
            httpd_resp_sendstr_chunk(req, "<br>");
        }
    }

    httpd_resp_sendstr_chunk(req, "</div><br><br><button onclick=\"location.href='/'\">Back to Home</button></body></html>");
    
    httpd_resp_sendstr_chunk(req, NULL);
    
    return ESP_OK;
}


void start_my_web_server(void)
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