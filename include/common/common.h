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
#include <getopt.h>

enum {
    CLIENT,
    SERVER
};

#define MAX_PKT_SIZE 65535

#define KEEP_ALIVE_CODE 7654321

void application_log(FILE *restrict stream, const char *restrict format, ...);

#endif
/* VPN_COMMON_H */