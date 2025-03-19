// SPDX-License-Identifier: Apache-2.0

#include <stdio.h>
#include <stdlib.h>
#include <limits.h>

#include "cpid/cpid_macos.h"

int main(int argc, char *argv[]) {
    if (argc != 2) {
        fprintf(stderr, "Exactly one program argument equal to the process PID is required.\n");
    }

    char *endptr = NULL;
    long parsed_pid = strtol(argv[1], &endptr, 10);
    if (endptr == NULL || endptr == argv[1] || *endptr != '\0') {
        fprintf(stderr, "Error parsing supplied PID.\n");
        return -1;
    }

    if (parsed_pid < INT_MIN || parsed_pid > INT_MAX) {
        fprintf(stderr, "Supplied PID must be a valid 32-bit integer.\n");
        return -1;
    }

    pid_t pid =  (pid_t) parsed_pid;
    uuid_string_t uuid_string = {0};

    cpid_handle_t cpid_handle = cpid_initialize();
    if (NULL == cpid_handle) {
        fprintf(stderr, "Failed to initialize cpid_instance_t.\n");
        return -1;
    }

    int return_code = cpid_get_uuid_string(cpid_handle, pid, uuid_string);

    cpid_finalize(cpid_handle);

    if (return_code) {
        fprintf(stderr, "Failed to calculate CPID.\n");
    } else {
        printf("%s\n", uuid_string);
    }

    return return_code;
}
