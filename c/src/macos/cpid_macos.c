// SPDX-License-Identifier: Apache-2.0

#include <IOKit/IOKitLib.h>
#include <sys/sysctl.h>
#include <openssl/evp.h>

#include <ctype.h>
#include <stdint.h>
#include <sys/types.h>
#include <uuid/uuid.h>

#include "cpid/cpid_macos.h"

#define KERNEL_TASK_PID 0
#define LAUNCHD_PID 1
#define MACOS_SERIAL_NUMBER_BUFFER_SIZE 16
#define MACOS_EXPECTED_DIGEST_INPUT_CONTENT_SIZE 88
#define MAX_MICROS_OFFSET 999999
#define MIN_MICROS_OFFSET 0
#define OPEN_SSL_SUCCESS 1
#define SHA256_BUFFER_SIZE 32

#pragma pack(push, 1)
typedef struct {
    int64_t unix_epoch_seconds; //    8 bytes
    int64_t micros_offset;      // +  8 bytes
} process_creation_time_t;      // = 16 bytes

typedef struct {
    char serial_number[MACOS_SERIAL_NUMBER_BUFFER_SIZE]; //   16 bytes
    uuid_t hardware_uuid;                                // + 16 bytes
    process_creation_time_t kernel_task_creation_time;   // + 16 bytes
    process_creation_time_t launchd_creation_time;       // + 16 bytes
    process_creation_time_t process_creation_time;       // + 16 bytes
    int64_t pid;                                         // +  8 bytes
} digest_input_content_t;                                // = 88 bytes
#pragma pack(pop)

_Static_assert(MACOS_EXPECTED_DIGEST_INPUT_CONTENT_SIZE == sizeof(digest_input_content_t), "digest_input_content_t is not the expected size.");

typedef struct cpid_struct {
    EVP_MD_CTX *digest_context;
    EVP_MD *sha256;
    uint8_t digest_destination_buffer[EVP_MAX_MD_SIZE];
    digest_input_content_t digest_input_content;
} *cpid_handle_internal_t;

_Static_assert(EVP_MAX_MD_SIZE >= SHA256_BUFFER_SIZE, "OpenSSL EVP_MAX_MD_SIZE must be larger that SHA256_BUFFER_SIZE.");
_Static_assert(SHA256_BUFFER_SIZE >= sizeof(uuid_t), "SHA256_BUFFER_SIZE must be larger that uuid_t.");

static int cpid_get_serial_number(char *const serial_number, const size_t serial_number_size) {
    if(!serial_number) {
        return -1;
    }

    if(0 == serial_number_size) {
        return -1;
    }


    io_service_t platformExpert = IOServiceGetMatchingService(kIOMainPortDefault, IOServiceMatching("IOPlatformExpertDevice"));
    if (MACH_PORT_NULL == platformExpert) {
        return -1;
    }

    CFStringRef serialNumberAsCFString = (CFStringRef) IORegistryEntryCreateCFProperty(platformExpert, CFSTR(kIOPlatformSerialNumberKey), kCFAllocatorDefault, 0);
    IOObjectRelease(platformExpert);
    if (!serialNumberAsCFString) {
        return -1;
    }

    Boolean get_cstring_succeeded = CFStringGetCString(serialNumberAsCFString, serial_number, serial_number_size, kCFStringEncodingUTF8);
    CFRelease(serialNumberAsCFString);
    if(!get_cstring_succeeded) {
        return -1;
    }

    return 0;
}

static int cpid_get_hardware_uuid(uuid_t hardware_uuid) {
    if(!hardware_uuid) {
        return -1;
    }

    uuid_string_t uuid_receive_text_buffer = {0};

    io_registry_entry_t ioRegistryRoot = IORegistryEntryFromPath(kIOMainPortDefault, "IOService:/");
    if(MACH_PORT_NULL == ioRegistryRoot) {
        return -1;
    }

    CFStringRef uuidCf = (CFStringRef) IORegistryEntryCreateCFProperty(ioRegistryRoot, CFSTR(kIOPlatformUUIDKey), kCFAllocatorDefault, 0);
    IOObjectRelease(ioRegistryRoot);
    if (!uuidCf) {
        return -1;
    }
    
    Boolean get_cstring_succeeded = CFStringGetCString(uuidCf, uuid_receive_text_buffer, sizeof(uuid_string_t), kCFStringEncodingMacRoman);
    CFRelease(uuidCf);
    if(!get_cstring_succeeded) {
        return -1;
    }
    
    if(uuid_parse(uuid_receive_text_buffer, hardware_uuid)) {
        return -1;
    }

    return 0;
}

static int cpid_get_process_creation_time(const pid_t pid, process_creation_time_t *const process_creation_time) {
    if(!process_creation_time) {
        return -1;
    }

    int mib[4] = {CTL_KERN, KERN_PROC, KERN_PROC_PID, pid};

    struct kinfo_proc process_info = {0};
    size_t info_size = sizeof(process_info);

    if (sysctl(mib, 4, &process_info, &info_size, NULL, 0)) {
        return -1;
    }

    pid_t returned_pid = process_info.kp_proc.p_pid;
    if(returned_pid != pid || 0 == process_info.kp_proc.p_starttime.tv_sec) {
        return -1;
    }

    process_creation_time->unix_epoch_seconds = process_info.kp_proc.p_starttime.tv_sec;
    process_creation_time->micros_offset = process_info.kp_proc.p_starttime.tv_usec;
    
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

        return_code = cpid_get_serial_number(library_handle_internal->digest_input_content.serial_number, sizeof(library_handle_internal->digest_input_content.serial_number));
        if (return_code) {
            break;
        }

        return_code = cpid_get_hardware_uuid(library_handle_internal->digest_input_content.hardware_uuid);
        if (return_code) {
            break;
        }

        return_code = cpid_get_process_creation_time(KERNEL_TASK_PID, &library_handle_internal->digest_input_content.kernel_task_creation_time);
        if (return_code) {
            break;
        }

        return_code = cpid_get_process_creation_time(LAUNCHD_PID, &library_handle_internal->digest_input_content.launchd_creation_time);
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

int cpid_make_uuid(cpid_handle_t const library_handle, const pid_t pid, const int64_t creation_time_unix_epoch_seconds, const int32_t creation_time_micros_offset, uuid_t uuid) {
    if (!library_handle || !uuid) {
        return -1;
    }

    if (creation_time_micros_offset < MIN_MICROS_OFFSET || creation_time_micros_offset > MAX_MICROS_OFFSET) {
        return -1;
    }

    cpid_handle_internal_t library_handle_internal = (cpid_handle_internal_t) library_handle;

    // set the process-specific information
    library_handle_internal->digest_input_content.pid = pid;
    library_handle_internal->digest_input_content.process_creation_time.unix_epoch_seconds = creation_time_unix_epoch_seconds;
    library_handle_internal->digest_input_content.process_creation_time.micros_offset = creation_time_micros_offset;

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

int cpid_get_uuid(cpid_handle_t const library_handle, const pid_t pid, uuid_t uuid) {
    if (!library_handle || !uuid) {
        return -1;
    }

    process_creation_time_t process_creation_time;

    if (cpid_get_process_creation_time(pid, &process_creation_time)) {
        return -1;
    }

    if (cpid_make_uuid(library_handle, pid, process_creation_time.unix_epoch_seconds, process_creation_time.micros_offset, uuid)) {
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

    // MacOS libuuid returns uppercase uuid string
    // normalize to lowercase
    for (size_t i = 0; i < sizeof(uuid_string_t); i++) {
        uuid_string[i] = (char) tolower(uuid_string[i]);
    }

    return 0;
}
