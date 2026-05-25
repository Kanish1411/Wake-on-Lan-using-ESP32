#ifndef LOGGER_H
#define LOGGER_H
void init_sntp_time(void);
void get_timestamp_str(char *buf, size_t max_len);
void write_log(const char *message,const char *status);
void get_logs(const char *out_log_buffer[32], const char *out_status_buffer[32]);
#endif
