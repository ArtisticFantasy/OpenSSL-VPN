#ifndef VPN_APPLICATION_H
#define VPN_APPLICATION_H

#include <stdarg.h>

#define PORT 54433

void application_log(FILE *restrict stream, const char *restrict format, ...);

#endif
/* VPN_APPLICATION_H */