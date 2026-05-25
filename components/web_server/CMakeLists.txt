idf_component_register(SRCS "web_server.c"
                       INCLUDE_DIRS "include"
                       REQUIRES esp_https_server lwip esp_wifi nvs_flash esp_event logger controls
                       EMBED_TXTFILES "../certs/servercert.pem" "../certs/prkey.pem")