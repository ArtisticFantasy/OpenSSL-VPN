#include "common/common.h"
#include "common/signal.h"
#include "common/application.h"

void handle_signal(int signal) {
    if (signal == SIGINT) {
        exit(EXIT_SUCCESS);
    }
}

void setup_signal_handler() {
    struct sigaction sa;
    sa.sa_handler = handle_signal;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0;

    if (sigaction(SIGINT, &sa, NULL) == -1) {
        application_log(stderr, "sigaction failed.\n");
        exit(EXIT_FAILURE);
    }
}