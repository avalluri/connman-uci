#ifndef __CONNMAN_UCI_LOG_H_
#define __CONNMAN_UCI_LOG_H_

#include <stdio.h>

enum LogLevel {
    LOG_ERR,
    LOG_WARN,
    LOG_INFO,
    LOG_DEBUG,
};

extern enum LogLevel verbose;

static inline const char *s_loglevel(enum LogLevel level) {
    switch(level) {
        case LOG_ERR:  return "ERROR";
        case LOG_WARN: return "WARN";
        case LOG_INFO: return "INFO";
        case LOG_DEBUG: return "DEBUG";
    }
    return "";
}

#define LOG(level, fmt, ...) \
    if (verbose >= level) { \
        fprintf(stderr, "%s:"fmt"\n", s_loglevel(level), ##__VA_ARGS__); \
    }

#define ERR(fmt, ...)  LOG(LOG_ERR,  fmt, ##__VA_ARGS__)
#define WARN(fmt, ...) LOG(LOG_WARN, fmt, ##__VA_ARGS__)
#define INFO(fmt, ...) LOG(LOG_INFO, fmt, ##__VA_ARGS__)
#define DBG(fmt, ...) LOG(LOG_DEBUG, fmt, ##__VA_ARGS__)

void log_init(enum LogLevel l);

#endif // __CONNMAN_UCI_LOG_H_
