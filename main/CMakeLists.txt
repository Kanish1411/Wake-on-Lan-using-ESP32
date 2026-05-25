idf_component_register(SRCS "udp_server.c"
                       INCLUDE_DIRS "."
                       REQUIRES logger web_server controls)