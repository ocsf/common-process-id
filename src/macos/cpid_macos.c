#include <stdlib.h>
#include <stdio.h>
#include <ctype.h>

#include <IOKit/IOKitLib.h>
#include <sys/sysctl.h>
#include <openssl/evp.h>

#include "cpid/cpid_macos.h"
#include "../constants.h"

#define KERNEL_TASK_PID 0
#define LAUNCHD_PID 1
#define MACOS_SERIAL_NUMBER_BUFFER_SIZE 16
#define MACOS_EXPECTED_DIGEST_INPUT_CONTENT_SIZE 88
#define MAX_MICROS_OFFSET 999999
#define OPEN_SSL_SUCCESS 1

#pragma pack(push, 1)
typedef struct {
    uint64_t unix_epoch_seconds;
    uint64_t micros_offset;
} process_creation_time_t;

typedef struct {
    char serial_number[MACOS_SERIAL_NUMBER_BUFFER_SIZE]; // 16 bytes
    uuid_t hardware_uuid; // 16 bytes
    process_creation_time_t kernel_task_creation_time;
    process_creation_time_t launchd_creation_time;
    process_creation_time_t process_creation_time;
    uint64_t pid;
} digest_input_content_t;

#pragma pack(pop)

_Static_assert(MACOS_EXPECTED_DIGEST_INPUT_CONTENT_SIZE == sizeof(digest_input_content_t), "digest_input_content_t is not the expected size.");

typedef struct cpid_struct {
    EVP_MD_CTX *digest_context;
    EVP_MD *sha256;
    uint8_t digest_destination_buffer[EVP_MAX_MD_SIZE];
    digest_input_content_t digest_input_content;
} *cpid_handle_t;

_Static_assert(EVP_MAX_MD_SIZE >= SHA256_BUFFER_SIZE, "OpenSSL EVP_MAX_MD_SIZE must be larger that SHA256_BUFFER_SIZE.");
_Static_assert(SHA256_BUFFER_SIZE >= sizeof(uuid_t), "SHA256_BUFFER_SIZE must be larger that uuid_t.");

static int cpid_get_serial_number(char * serial_number, size_t serial_number_size) {
    if(NULL == serial_number || 0 == serial_number_size) {
        return RETURN_ERROR;
    }

    io_service_t platformExpert = IOServiceGetMatchingService(kIOMainPortDefault, IOServiceMatching("IOPlatformExpertDevice"));
    if (MACH_PORT_NULL == platformExpert) {
        return RETURN_ERROR;
    }

    CFStringRef serialNumberAsCFString = (CFStringRef) IORegistryEntryCreateCFProperty(platformExpert, CFSTR(kIOPlatformSerialNumberKey), kCFAllocatorDefault, 0);
    IOObjectRelease(platformExpert);
    if (NULL == serialNumberAsCFString) {
        return RETURN_ERROR;
    }

    Boolean get_cstring_succeeded = CFStringGetCString(serialNumberAsCFString, serial_number, serial_number_size, kCFStringEncodingUTF8);
    CFRelease(serialNumberAsCFString);
    if(!get_cstring_succeeded) {
        return RETURN_ERROR;
    }

    return RETURN_SUCCESS;
}

static int cpid_get_hardware_uuid(uuid_t hardware_uuid) {
    if(NULL == hardware_uuid) {
        return RETURN_ERROR;
    }

    uuid_string_t uuid_receive_text_buffer = {0};

    io_registry_entry_t ioRegistryRoot = IORegistryEntryFromPath(kIOMainPortDefault, "IOService:/");
    if(MACH_PORT_NULL == ioRegistryRoot) {
        return RETURN_ERROR;
    }

    CFStringRef uuidCf = (CFStringRef) IORegistryEntryCreateCFProperty(ioRegistryRoot, CFSTR(kIOPlatformUUIDKey), kCFAllocatorDefault, 0);
    IOObjectRelease(ioRegistryRoot);
    if (NULL == uuidCf) {
        return RETURN_ERROR;
    }
    
    Boolean get_cstring_succeeded = CFStringGetCString(uuidCf, uuid_receive_text_buffer, sizeof(uuid_string_t), kCFStringEncodingMacRoman);
    CFRelease(uuidCf);
    if(!get_cstring_succeeded) {
        return RETURN_ERROR;
    }
    
    int return_code = uuid_parse(uuid_receive_text_buffer, hardware_uuid);
    if(0 != return_code) {
        return RETURN_ERROR;
    }

    return RETURN_SUCCESS;
}

static int cpid_get_process_creation_time(uint32_t pid, process_creation_time_t *process_creation_time) {
    // pid check needed for conversion to signed below
    if(pid > MAX_PID || NULL == process_creation_time) {
        return RETURN_ERROR;
    }

    int mib[4] = {CTL_KERN, KERN_PROC, KERN_PROC_PID, (int) pid};

    struct kinfo_proc process_info = {0};
    size_t info_size = sizeof(process_info);

    int return_code = sysctl(mib, 4, &process_info, &info_size, NULL, 0);
    if (0 != return_code) {
        return RETURN_ERROR;
    }

    // guard for conversion to unsigned
    if(process_info.kp_proc.p_pid < 0) {
        return RETURN_ERROR;
    }

    uint32_t returned_pid = process_info.kp_proc.p_pid;
    if(returned_pid != pid || 0 == process_info.kp_proc.p_starttime.tv_sec) {
        return RETURN_ERROR;
    }

    // guard for conversion to unsigned
    if (process_info.kp_proc.p_starttime.tv_sec < 0 || process_info.kp_proc.p_starttime.tv_usec < 0) {
        return RETURN_ERROR;
    }

    process_creation_time->unix_epoch_seconds = process_info.kp_proc.p_starttime.tv_sec;
    process_creation_time->micros_offset = process_info.kp_proc.p_starttime.tv_usec;
    
    return RETURN_SUCCESS;
}

cpid_handle_t cpid_initialize(void) {

    cpid_handle_t library_handle = calloc(1, sizeof(*library_handle));
    if (NULL == library_handle) {
        return NULL;
    }

    int return_code = RETURN_SUCCESS;
    do {
        library_handle->sha256 = EVP_MD_fetch(NULL, "SHA256", NULL);
        if (NULL == library_handle->sha256) {
            return_code = RETURN_ERROR;
            break;
        }

        library_handle->digest_context = EVP_MD_CTX_new();
        if (NULL == library_handle->digest_context) {
            return_code = RETURN_ERROR;
            break;
        }

        return_code = cpid_get_serial_number(library_handle->digest_input_content.serial_number, sizeof(library_handle->digest_input_content.serial_number));
        if (RETURN_SUCCESS != return_code) {
            break;
        }

        return_code = cpid_get_hardware_uuid(library_handle->digest_input_content.hardware_uuid);
        if (RETURN_SUCCESS != return_code) {
            break;
        }

        return_code = cpid_get_process_creation_time(KERNEL_TASK_PID, &library_handle->digest_input_content.kernel_task_creation_time);
        if (RETURN_SUCCESS != return_code) {
            break;
        }

        return_code = cpid_get_process_creation_time(LAUNCHD_PID, &library_handle->digest_input_content.launchd_creation_time);
        if (RETURN_SUCCESS != return_code) {
            break;
        }

    } while(0);

    if (RETURN_SUCCESS != return_code) {
        cpid_finalize(library_handle);
        library_handle = NULL;
     }

    return library_handle;
}

void cpid_finalize(_Inout_ cpid_handle_t library_handle) {
    if (NULL != library_handle) {
        if (NULL != library_handle->digest_context) {
            EVP_MD_CTX_free(library_handle->digest_context);
        }

        if (NULL != library_handle->sha256) {
            EVP_MD_free(library_handle->sha256);
        }

        free(library_handle);
    }
}

int cpid_make_uuid(_In_ cpid_handle_t library_handle, _In_ uint32_t pid, _In_ uint64_t creation_time_unix_epoch_seconds, _In_ uint32_t creation_time_micros_offset, _Out_ uuid_t uuid) {
    if (NULL == library_handle || pid > MAX_PID || creation_time_micros_offset > MAX_MICROS_OFFSET || NULL == uuid) {
        return RETURN_ERROR;
    }

    // set the process-specific information
    library_handle->digest_input_content.pid = pid;
    library_handle->digest_input_content.process_creation_time.unix_epoch_seconds = creation_time_unix_epoch_seconds;
    library_handle->digest_input_content.process_creation_time.micros_offset = creation_time_micros_offset;

    // initialize digest context for new digest calculation
    if (OPEN_SSL_SUCCESS != EVP_DigestInit_ex2(library_handle->digest_context, library_handle->sha256, NULL)) {
        return RETURN_ERROR;
    }

    // update digest with the input content
    if (OPEN_SSL_SUCCESS != EVP_DigestUpdate(library_handle->digest_context, &library_handle->digest_input_content, sizeof(library_handle->digest_input_content))) {
        return RETURN_ERROR;
    }

    // finalize the digest, coping the result to the destination buffer
    // this intermediate buffer is needed since there is no OpenSSL option
    // for only retrieving the first 128 bits of the digest
    unsigned int digest_size = 0;
    if (OPEN_SSL_SUCCESS != EVP_DigestFinal_ex(library_handle->digest_context, library_handle->digest_destination_buffer, &digest_size)) {
        return RETURN_ERROR;
    } else if (SHA256_BUFFER_SIZE != digest_size) {
        return RETURN_ERROR;
    }

    // set the uuid version (UUIDv8)
    library_handle->digest_destination_buffer[6] = (library_handle->digest_destination_buffer[6] & 0x0F) | 0x80;

    // set the uuid variant
    library_handle->digest_destination_buffer[8] = (library_handle->digest_destination_buffer[8] & 0x3F) | 0x80;

    // copy the first 128 bits of the digest to the output buffer
    memcpy(uuid, library_handle->digest_destination_buffer, sizeof(uuid_t));

    return RETURN_SUCCESS;
}

int cpid_get_uuid(_In_ cpid_handle_t library_handle, _In_ uint32_t pid, _Out_ uuid_t uuid) {
    if (NULL == library_handle || NULL == uuid) {
        return RETURN_ERROR;
    }

    process_creation_time_t process_creation_time;

    if (RETURN_SUCCESS != cpid_get_process_creation_time(pid, &process_creation_time)) {
        return RETURN_ERROR;
    }

    if (RETURN_SUCCESS != cpid_make_uuid(library_handle, pid, process_creation_time.unix_epoch_seconds, process_creation_time.micros_offset, uuid)) {
        return RETURN_ERROR;
    }

    return RETURN_SUCCESS;
}

int cpid_get_uuid_string(_In_ cpid_handle_t library_handle, _In_ uint32_t pid, _Out_ uuid_string_t uuid_string) {

    if (NULL == library_handle || NULL == uuid_string) {
        return RETURN_ERROR;
    }

    uuid_t uuid;

    if (RETURN_SUCCESS != cpid_get_uuid(library_handle, pid, uuid)) {
        return RETURN_ERROR;
    }
    
    uuid_unparse(uuid, uuid_string);

    // MacOS libuuid returns uppercase uuid string
    // normalize to lowercase
    for (size_t i = 0; i < sizeof(uuid_string_t); i++) {
        uuid_string[i] = (char) tolower(uuid_string[i]);
    }

    return RETURN_SUCCESS;
}
