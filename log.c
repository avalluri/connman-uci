#include "log.h"

enum LogLevel verbose = LOG_ERR;

void log_init(enum LogLevel l) {
    verbose = l;
}
