#ifndef VPN_COMMON_H
#define VPN_COMMON_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <time.h>
#include <assert.h>
#include <sys/time.h>
#include <stdarg.h>

enum {
    CLIENT,
    SERVER
};

void application_log(FILE *restrict stream, const char *restrict format, ...);

#endif
/* VPN_COMMON_H */