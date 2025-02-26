// SPDX-License-Identifier: Apache-2.0

// We enforce standard C with no extensions in CMake
// This is needed for readlink method to be defined
#define _POSIX_C_SOURCE 200112L

#include <ctype.h>
#include <stdint.h>
#include <sys/types.h>
#include <string.h>
#include <unistd.h>
#include <uuid/uuid.h>
#include <openssl/evp.h>

#include "cpid/cpid_linux.h"

#define LINUX_EXPECTED_DIGEST_INPUT_CONTENT_SIZE 40
#define OPEN_SSL_SUCCESS 1
#define SHA256_BUFFER_SIZE 32

#pragma pack(push, 1)
typedef struct {
    uuid_t boot_uuid;                     //   16 bytes
    uint64_t pid_namespace;               //  + 8 bytes
    uint64_t process_creation_time_ticks; //  + 8 bytes
    int64_t pid_namespace_tgid;               //  + 8 bytes
} digest_input_content_t;                 // = 40 bytes
#pragma pack(pop)

_Static_assert(LINUX_EXPECTED_DIGEST_INPUT_CONTENT_SIZE == sizeof(digest_input_content_t), "Linux digest_input_content_t size should be 40 bytes.");

typedef struct {
    EVP_MD_CTX *digest_context;
    EVP_MD *sha256;
    uint8_t digest_destination_buffer[EVP_MAX_MD_SIZE];
    digest_input_content_t digest_input_content;
} *cpid_handle_internal_t;

_Static_assert(EVP_MAX_MD_SIZE >= SHA256_BUFFER_SIZE, "OpenSSL EVP_MAX_MD_SIZE must be larger than SHA256_BUFFER_SIZE.");
_Static_assert(SHA256_BUFFER_SIZE >= sizeof(uuid_t), "SHA256_BUFFER_SIZE must be larger than uuid_t.");

static int cpid_get_boot_uuid(uuid_t boot_uuid) {

    uuid_string_t boot_uuid_string = {0};

    #define LINUX_BOOT_ID_FILE_PATH "/proc/sys/kernel/random/boot_id"
    FILE *file = fopen(LINUX_BOOT_ID_FILE_PATH, "r");
    if (!file) {
        return -1;
    }

    size_t bytesRead = fread(boot_uuid_string, sizeof(char), sizeof(uuid_string_t) - 1, file);

    int file_close_return = fclose(file);

    if (sizeof(uuid_string_t) - 1 != bytesRead) {
        return -1;
    }

    if(file_close_return) {
        fprintf(stderr, "Error closing `%s`.\n", LINUX_BOOT_ID_FILE_PATH);
        return -1;
    }

    if (uuid_parse(boot_uuid_string, boot_uuid)) {
        return -1;
    }

    return 0;
}

cpid_handle_t cpid_initialize(void) {

    cpid_handle_internal_t library_handle_internal = calloc(1, sizeof(*library_handle_internal));
    if (!library_handle_internal) {
        return NULL;
    }

    int return_code = 0;
    do {
        library_handle_internal->sha256 = EVP_MD_fetch(NULL, "SHA256", NULL);
        if (!library_handle_internal->sha256) {
            return_code = -1;
            break;
        }

        library_handle_internal->digest_context = EVP_MD_CTX_new();
        if (!library_handle_internal->digest_context) {
            return_code = -1;
            break;
        }


        if(cpid_get_boot_uuid(library_handle_internal->digest_input_content.boot_uuid)) {
            return_code = -1;
        }
    } while(0);

    if (return_code) {
        cpid_finalize(library_handle_internal);
        library_handle_internal = NULL;
    }

    return library_handle_internal;
}

void cpid_finalize(cpid_handle_t const library_handle) {

    cpid_handle_internal_t library_handle_internal = (cpid_handle_internal_t) library_handle;

    if (library_handle_internal) {
        if (library_handle_internal->digest_context) {
            EVP_MD_CTX_free(library_handle_internal->digest_context);
        }

        if (library_handle_internal->sha256) {
            EVP_MD_free(library_handle_internal->sha256);
        }

        free(library_handle_internal);
    }
}

int cpid_make_uuid(cpid_handle_t const library_handle, const pid_t pid_namespace_tgid, const uint64_t creation_time_ticks, const ino_t pid_namespace, uuid_t uuid) {
    if (!library_handle || !uuid) {
        return -1;
    }

    cpid_handle_internal_t library_handle_internal = (cpid_handle_internal_t) library_handle;

    library_handle_internal->digest_input_content.pid_namespace = pid_namespace;
    library_handle_internal->digest_input_content.process_creation_time_ticks = creation_time_ticks;
    library_handle_internal->digest_input_content.pid_namespace_tgid = pid_namespace_tgid;

    // initialize digest context for new digest calculation
    if (OPEN_SSL_SUCCESS != EVP_DigestInit_ex2(library_handle_internal->digest_context, library_handle_internal->sha256, NULL)) {
        return -1;
    }

    // update digest with the input content
    if (OPEN_SSL_SUCCESS != EVP_DigestUpdate(library_handle_internal->digest_context, &library_handle_internal->digest_input_content, sizeof(library_handle_internal->digest_input_content))) {
        return -1;
    }

    // finalize the digest, coping the result to the destination buffer
    // this intermediate buffer is needed since there is no OpenSSL option
    // for only retrieving the first 128 bits of the digest
    unsigned int digest_size = 0;
    if (OPEN_SSL_SUCCESS != EVP_DigestFinal_ex(library_handle_internal->digest_context, library_handle_internal->digest_destination_buffer, &digest_size)) {
        return -1;
    } else if (SHA256_BUFFER_SIZE != digest_size) {
        return -1;
    }

    #define UUID_VERSION_BYTE_INDEX 6
    #define UUID_VERSION_BIT_MASK 0x0F
    #define UUID_VERSION_CONTENT 0x80
    library_handle_internal->digest_destination_buffer[UUID_VERSION_BYTE_INDEX] = (library_handle_internal->digest_destination_buffer[UUID_VERSION_BYTE_INDEX] & UUID_VERSION_BIT_MASK) | UUID_VERSION_CONTENT;


    #define UUID_VARIANT_BYTE_INDEX 8
    #define UUID_VARIANT_BIT_MASK 0x3F
    #define UUID_VARIANT_CONTENT 0x80
    library_handle_internal->digest_destination_buffer[UUID_VARIANT_BYTE_INDEX] = (library_handle_internal->digest_destination_buffer[UUID_VARIANT_BYTE_INDEX] & UUID_VARIANT_BIT_MASK) | UUID_VARIANT_CONTENT;

    // copy the first 128 bits of the digest to the output buffer
    memcpy(uuid, library_handle_internal->digest_destination_buffer, sizeof(uuid_t));

    return 0;
}

static int advance_file_to_last_number_in_line(FILE *const file) {
    long last_number_start_position = 0;
    uint8_t on_number = 0;
    int c = 0;
    while(EOF != (c = fgetc(file))) {
        if('\n' == c) {
            break;
        }
        
        long position = ftell(file);

        if('0' <= c && '9' >= c) {
            // newly on a number
            if(!on_number) {
                on_number = 1;
                last_number_start_position = position - 1;
            }
        } else {
            // not on a number
            on_number = 0;
        }
    }

    // If we didn't find a number, return an error
    if(!last_number_start_position) {
        return -1;
    }

    // Now, set file position to the start of the last number
    if(fseek(file, last_number_start_position, 0)) {
        return -1;
    }

    return 0;
}

static int advance_file_to_next_line(FILE *const file) {
    int c = 0;
    while(EOF != (c = fgetc(file))) {
        if('\n' == c) {
            return 0;
        }
    }

    // returns error if new line not found
    return -1;
}

static int is_file_line_nstgid(FILE *file, uint8_t *is_nstgid) {
    #define NSTGID_LINE_START_BUFFER_SIZE 8 // 7 known characters + null terminator
    char nstgid_line_start_read_string[NSTGID_LINE_START_BUFFER_SIZE] = {0};

    int c  = 0;
    for(int i = 0; i < NSTGID_LINE_START_BUFFER_SIZE - 1; i++) {
        if(EOF == (c = fgetc(file))) {
            return -1;
        }
        nstgid_line_start_read_string[i] = (char) c;
    }

    #define NSTGID_LINE_START "NStgid:"

    // compare the read string to the known string to see if we are on the NStgid line
    if(!strncmp(NSTGID_LINE_START, nstgid_line_start_read_string, NSTGID_LINE_START_BUFFER_SIZE)) {
        *is_nstgid = 1;
    }

    return 0;
}

static int advance_file_to_nstgid_line(FILE *const file) {
    int return_code = 0;
    do {
        long line_start_position = ftell(file);

        // check if the line starts with "NStgid:"
        uint8_t is_nstgid = 0;
        if(is_file_line_nstgid(file, &is_nstgid)) {
            return_code = -1;
            break;
        }

        // reset file position to the start of the line
        if(fseek(file, line_start_position, 0)) {
            return_code = -1;
            break;
        }

        if(is_nstgid) {
            break;
        }
    } while(!advance_file_to_next_line(file));

    return return_code;
}

static int get_pid_namespace_tgid(const pid_t pid, pid_t *const pid_namespace_tgid) {
    // 13 known characters + max 10 characters for pid (2^32 = 4294967296) + null terminator 
    // so max 24 characters in theory
    #define PROC_STATUS_FILE_PATH_BUFFER_SIZE 128 
    char proc_status_path[PROC_STATUS_FILE_PATH_BUFFER_SIZE] = {0};
    int chars_written = snprintf(proc_status_path, PROC_STATUS_FILE_PATH_BUFFER_SIZE, "/proc/%u/status", pid);

    if (chars_written < 0 || chars_written >= PROC_STATUS_FILE_PATH_BUFFER_SIZE) {
        // error condition or truncation
        return -1;
    }

    FILE *file = fopen(proc_status_path, "r");
    if (!file) {
        return -1;
    }

    int return_code = 0;
    do {
        // Retrieve the rightmost numeric value from the "NStgid" line. This is the tgid of the process in the namespace it was created in.
        // Example line: "NStgid:  8165    25"

        if(advance_file_to_nstgid_line(file)) {
            return_code = -1;
            break;
        }

        if(advance_file_to_last_number_in_line(file)) {
            return_code = -1;
            break;
        }

        int parsed_fields = fscanf(file, "%d", pid_namespace_tgid);
        if (1 != parsed_fields) {
            return_code = -1;
        }
    } while(0);

    if(fclose(file)) {
        return_code = -1;
    }

    return return_code;
}

static int advance_file_to_after_last_right_bracket(FILE *const file) {
    long last_right_bracket_position = 0;

    // find the position of the last right bracket
    int c = 0;
    while(EOF != (c = fgetc(file))) {
        if(')' == c) { 
            last_right_bracket_position = ftell(file);
        }
    }

    if (0 == last_right_bracket_position) {
        // no right bracket found
        return -1;
    }
    

    // move the file pointer to after the last right bracket
    if(fseek(file, last_right_bracket_position, 0)) {
        return -1;
    }

    return 0;
}

static int get_creation_time_ticks(const pid_t pid, uint64_t *const creation_time_ticks) {    
    // 11 known characters + max 10 characters for pid (2^32 = 4294967296) + null terminator 
    // so max 22 characters in theory
    #define PROC_STAT_FILE_PATH_BUFFER_SIZE 128
    char proc_stat_file_path[PROC_STAT_FILE_PATH_BUFFER_SIZE] = {0};

    int chars_written = snprintf(proc_stat_file_path, PROC_STAT_FILE_PATH_BUFFER_SIZE, "/proc/%d/stat", pid);
    
    if (chars_written < 0 || chars_written >= PROC_STAT_FILE_PATH_BUFFER_SIZE) {
        // error condition or truncation
        return -1;
    }

    FILE *file = fopen(proc_stat_file_path, "r");
    if (!file) {
        return -1;
    }

    int return_code = 0;
    do {
        // An-all-in one fscanf generates warnings and I dont trust the handling of the bracketed filename
        // This skips the file to after the last last occurence of a right bracket ')'
        if(advance_file_to_after_last_right_bracket(file)) {
            return_code = -1;
            break;
        }

        unsigned long long local_creation_time_ticks = 0;
        int parsed_fields = fscanf(file, " %*s %*s %*s %*s %*s %*s %*s %*s %*s %*s %*s %*s %*s %*s %*s %*s %*s %*s %*s %llu", &local_creation_time_ticks);
        if(1 != parsed_fields) {
            return_code = -1;
            break;
        }
        
        *creation_time_ticks = (uint64_t) local_creation_time_ticks;
    } while(0);

    if(fclose(file)) {
        return_code = -1;
    }

    return return_code;
}

static int get_pid_namespace(const pid_t pid, ino_t *const pid_namespace) {
    // 13 known characters + max 10 characters for pid (2^32 = 4294967296) + null terminator
    // so max 34 characters in theory
    #define PROC_NS_PATH_BUFFER_SIZE 128  
    char proc_ns_path[PROC_NS_PATH_BUFFER_SIZE] = {0};

    int chars_written = snprintf(proc_ns_path, PROC_NS_PATH_BUFFER_SIZE, "/proc/%d/ns/pid", pid);
    
    if (chars_written < 0 || chars_written >= PROC_NS_PATH_BUFFER_SIZE) {
        // error condition or truncation
        return -1;
    }

    // example: "pid:[4026531836]"
    // 6 known characters + max 10 characters for ns (2^32 = 4294967296) + null terminator
    // so max 17 characters in theory
    #define NS_BUFFER_SIZE 64
    char ns_content[NS_BUFFER_SIZE] = {0};
    ssize_t chars_read = readlink(proc_ns_path, ns_content, NS_BUFFER_SIZE);

    // less than 0 means error
    // in [0,6] means that there wasn't enough content for an acutal namespace number to have been read
    // greater than or equal to NS_BUFFER_SIZE means truncation since only NS_BUFFER_SIZE - 1 characters should be read at most
    if(chars_read <= 6 || chars_read >= NS_BUFFER_SIZE) {
        return -1;
    }

    int parsed_fields = sscanf(ns_content, "pid:[%lu]", pid_namespace);
    if (1 != parsed_fields) {
        return -1;
    }

    return 0;
}

int cpid_get_uuid(cpid_handle_t const library_handle, const pid_t pid, uuid_t uuid) {
    if (!library_handle || !uuid) {
        return -1;
    }

    pid_t pid_namespace_tgid = 0;
    uint64_t creation_time_ticks = 0;
    ino_t pid_namespace = 0;

    if(get_pid_namespace_tgid(pid, &pid_namespace_tgid)) {
        return -1;
    }

    if(get_creation_time_ticks(pid, &creation_time_ticks)) {
        return -1;
    }

    if(get_pid_namespace(pid, &pid_namespace)) {
        return -1;
    }

    if (cpid_make_uuid(library_handle, pid_namespace_tgid, creation_time_ticks, pid_namespace, uuid)) {
        return -1;
    }

    return 0;
}

int cpid_get_uuid_string(cpid_handle_t const library_handle, const pid_t pid, uuid_string_t uuid_string) {
    if (!library_handle || !uuid_string) {
        return -1;
    }

    uuid_t uuid;

    if (cpid_get_uuid(library_handle, pid, uuid)) {
        return -1;
    }
    
    uuid_unparse(uuid, uuid_string);

    return 0;
}
