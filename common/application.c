#include "common/common.h"
#include "common/application.h"

uint16_t PORT = 0;
uint16_t EXPECTED_HOST_ID = 0;
in_addr_t SERVER_IP = INADDR_NONE;
extern int host_type;

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

        char *trim_line = trim(line);

        char *key = strtok(trim_line, "=");
        char *value = strtok(NULL, "=");
        if (!key || !value) {
            if (strlen(trim_line)) {
                application_log(stderr, "Invalid grammar in config file: %s\n", line);
                fclose(file);
                exit(EXIT_FAILURE);
            }
            continue;
        }
        key = trim(key);
        value = trim(value);
        
        //Option PORT
        if (!strcmp(key, "PORT")) {
            if (PORT) {
                application_log(stderr, "Multiple PORT specified.\n");
                fclose(file);
                exit(EXIT_FAILURE);
            }
            if (!strlen(value)) {
                application_log(stderr, "Invalid PORT value.\n");
                fclose(file);
                exit(EXIT_FAILURE);
            }
            else {
                long tmp = parse_value(value);

                if (tmp < 10000 || tmp >= UINT16_MAX) {
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
        //Option EXPECTED_HOST_ID
        else if (!strcmp(key, "EXPECTED_HOST_ID")) {
            if (EXPECTED_HOST_ID) {
                application_log(stderr, "Multiple EXPECTED_HOST_ID specified.\n");
                fclose(file);
                exit(EXIT_FAILURE);
            }
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
        // Option SERVER_IP
        else if (!strcmp(key, "SERVER_IP")) {
            if (SERVER_IP != INADDR_NONE) {
                application_log(stderr, "Multiple SERVER_IP specified.\n");
                fclose(file);
                exit(EXIT_FAILURE);
            }
            SERVER_IP = inet_addr(value);
            if (SERVER_IP == INADDR_NONE) {
                application_log(stderr, "Invalid SERVER_IP value.\n");
                fclose(file);
                exit(EXIT_FAILURE);
            }
            if (host_type == SERVER) {
                application_log(stdout, "SERVER_IP is useless for server, skip.\n");
            }
            else {
                application_log(stdout, "Setting server ip: %s\n", value);
            }
        }
        else {
            application_log(stderr, "Unknown option: %s\n", key);
            fclose(file);
            exit(EXIT_FAILURE);
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

    if (host_type == CLIENT && SERVER_IP == INADDR_NONE) {
        application_log(stderr, "Did not find SERVER_IP in config file!\n");
        fclose(file);
        exit(EXIT_FAILURE);
    }

    fclose(file);

    application_log(stdout, "Config file parsed successfully.\n");
}