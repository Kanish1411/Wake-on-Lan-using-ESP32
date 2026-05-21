idf_component_register(SRCS "udp_server.c"
                    INCLUDE_DIRS "."
                    REQUIRES esp_http_server lwip esp_wifi nvs_flash esp_event)
