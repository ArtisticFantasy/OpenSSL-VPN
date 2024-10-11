#ifndef VPN_SIGNAL_H
#define VPN_SIGNAL_H

#include <signal.h>

void handle_signal(int signal);

void setup_signal_handler(void);

#endif
/* VPN_SIGNAL_H */