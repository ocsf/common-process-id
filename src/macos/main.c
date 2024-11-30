#include <stdio.h>
#include <stdlib.h>

#include "cpid/cpid_macos.h"
#include "../constants.h"

int main(int argc, char *argv[]) {
    if (argc != 2) {
        fprintf(stderr, "Exactly one program argument equal to the process PID is required.\n");
    }

    char *endptr = NULL;
    long parsed_pid = strtol(argv[1], &endptr, 10);
    if (endptr == NULL || endptr == argv[1] || *endptr != '\0') {
        fprintf(stderr, "Error parsing supplied PID.\n");
        return RETURN_ERROR;
    }

    if (parsed_pid < 0 || parsed_pid > 0x7FFFFFFF) {
        fprintf(stderr, "Supplied PID must be an integer in [0, 2^31-1].\n");
        return RETURN_ERROR;
    }

    uint32_t pid = (uint32_t) parsed_pid;
    uuid_string_t uuid_string = {0};

    cpid_handle_t cpid_handle = cpid_initialize();
    if (NULL == cpid_handle) {
        fprintf(stderr, "Failed to initialize cpid_instance_t.\n");
        return RETURN_ERROR;
    }

    int return_code = cpid_get_uuid_string(cpid_handle, pid, uuid_string);
    cpid_finalize(cpid_handle);

    if (RETURN_SUCCESS != return_code) {
        fprintf(stderr, "Failed to calculate CPID.\n");
    } else {
        printf("%s\n", uuid_string);
    }

    return return_code;
}
