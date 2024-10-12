#include "common/common.h"
#include "common/application.h"

void application_log(FILE *restrict stream, const char *restrict format, ...) {
    time_t rawtime;
    struct tm *timeinfo;
    time(&rawtime);
    timeinfo = localtime(&rawtime);
    char buffer[100];
    strftime(buffer, sizeof(buffer), "%Y-%m-%d %H:%M:%S", timeinfo);
    char new_format[256];
    snprintf(new_format, sizeof(new_format), "[%s] %s", buffer, format);
    va_list args;
    va_start(args, format);
    vfprintf(stream, new_format, args);
    va_end(args);
}