#include "log.h"

enum LogLevel verbose = LOG_WARN;
const char *prefix = "";

void log_init(const char *p, enum LogLevel l) {
    verbose = l;
    prefix = p;
}
