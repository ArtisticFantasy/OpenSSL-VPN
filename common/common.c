#include "common/common.h"

int host_type = -1;

void application_log(FILE *restrict stream, const char *restrict format, ...) {
    time_t rawtime;
    struct tm *timeinfo;
    time(&rawtime);
    timeinfo = localtime(&rawtime);
    char buffer[100];
    strftime(buffer, sizeof(buffer), "%Y-%m-%d %H:%M:%S", timeinfo);
    char *app_name = "";
    if (host_type == SERVER) {
        app_name = "vpn_server";
    } else if (host_type == CLIENT) {
        app_name = "vpn_client";
    }
    char new_format[256];
    snprintf(new_format, sizeof(new_format), "[%s] %s: %s", buffer, app_name, format);
    va_list args;
    va_start(args, format);
    vfprintf(stream, new_format, args);
    va_end(args);
}