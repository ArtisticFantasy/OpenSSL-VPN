#include "common/common.h"
#include "common/application.h"

uint16_t PORT = 0;
uint16_t EXPECTED_HOST_ID = 0;
int host_type = -1;

char *trim(char *str) {
    while (isspace(*str)) {
        ++str;
    }
    char *end = str + strlen(str) - 1;
    while (end >= str && isspace(*end)) {
        --end;
    }
    *(end + 1) = '\0';
    return str;
}

long parse_value(char *value) {
    errno = 0;
    char *endptr;
    long tmp = strtol(value, &endptr, 10);

    if (errno || *endptr != '\0') {
        return -1;
    }
    return tmp;
}

void parse_config_file(const char *file_path, int max_hosts) {
    FILE *file = fopen(file_path, "r");
    if (!file) {
        application_log(stderr, "Unable to open config file %s\n", file_path);
        exit(EXIT_FAILURE);
    }

    application_log(stdout, "Parsing config file %s...\n", file_path);

    char line[1000];
    while (fgets(line, sizeof(line), file)) {
        if (!strlen(line)) continue;
        int len = strlen(line);
        for (int i = 0; i < len; i++) {
            if (line[i] == '#') {
                line[i] = '\0';
                break;
            }
        }
        if (!strlen(line)) continue;

        char *key = strtok(line, "=");
        char *value = strtok(NULL, "=");
        if (!key || !value) {
            continue;
        }
        key = trim(key);
        value = trim(value);

        if (!strcmp(key, "PORT")) {
            if (PORT) continue;
            if (!strlen(value)) {
                application_log(stderr, "Invalid PORT value.\n");
                fclose(file);
                exit(EXIT_FAILURE);
            }
            else {
                long tmp = parse_value(value);

                if (tmp < 50000 || tmp >= UINT16_MAX) {
                    application_log(stderr, "Invalid PORT value.\n");
                    fclose(file);
                    exit(EXIT_FAILURE);
                }
                PORT = (uint16_t)tmp;

                if (host_type == SERVER) {
                    application_log(stdout, "Setting server port: %d\n", PORT);
                }
                else if (host_type == CLIENT) {
                    application_log(stdout, "Connecting to server port: %d\n", PORT);
                }
                
            }
        }
        else if (!strcmp(key, "EXPECTED_HOST_ID")) {
            if (EXPECTED_HOST_ID) continue;
            if (!strlen(value)) {
                application_log(stderr, "Invalid EXPECTED_HOST_ID value.\n");
                fclose(file);
                exit(EXIT_FAILURE);
            }
            else {
                long tmp = parse_value(value);

                if (tmp <= 0 || tmp >= (host_type == SERVER ? max_hosts : MAX_HOSTS)) {
                    application_log(stderr, "Invalid EXPECTED_HOST_ID value.\n");
                    fclose(file);
                    exit(EXIT_FAILURE);
                }
                EXPECTED_HOST_ID = (int)tmp;

                application_log(stdout, "Setting expected host id: %d\n", EXPECTED_HOST_ID);
            }
        }
    }

    if (!PORT) {
        PORT = 54433;
        if (host_type == SERVER) {
            application_log(stdout, "Did not find PORT in config file, using default server port: %d\n", PORT);
        }
        else if (host_type == CLIENT) {
            application_log(stdout, "Did not find PORT in config file, connecting to default server PORT: %d\n", PORT);
        }
    }

    if (!EXPECTED_HOST_ID) {
        if (host_type == SERVER) {
            EXPECTED_HOST_ID = 1;
            application_log(stdout, "Did not find EXPECTED_HOST_ID in config file, using default value: %d\n", EXPECTED_HOST_ID);
        }
        else if (host_type == CLIENT) {
            application_log(stdout, "Did not find EXPECTED_HOST_ID in config file, let server determine it.\n");
        }
    }

    fclose(file);

    application_log(stdout, "Config file parsed successfully.\n");
}