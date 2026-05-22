idf_component_register(SRCS "udp_server.c"
                       INCLUDE_DIRS "."
                       REQUIRES esp_https_server lwip esp_wifi nvs_flash esp_event
                       EMBED_TXTFILES "../certs/servercert.pem" "../certs/prkey.pem")