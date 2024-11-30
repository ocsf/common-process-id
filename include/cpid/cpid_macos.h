#pragma once

#ifdef __cplusplus
extern "C" {
#endif

#include <stdlib.h>
#include <uuid/uuid.h>

// Microsoft SAL annotations are not available on macOS
// Define them to enable use for documentation purposes
#ifndef _In_
#define _In_
#endif
#ifndef _Out_
#define _Out_
#endif
#ifndef _Inout_
#define _Inout_
#endif

typedef struct cpid_struct *cpid_handle_t;

/**
 * Initializes a CPID handle
 * 
 * @details The returned handle must be passed to other CPID methods.
 *          It contains state that can be reused across CPID method calls.
 *          CPID handles are not thread-safe.
 *          cpid_finalize must be called when the handle is no longer needed.
 *
 * @return NULL on error, a CPID library handle on success.
 */
cpid_handle_t cpid_initialize(void);

/**
 * Finalizes a CPID handle.
 * 
 * @details This method must be called to free resources associated with a handle.
 *          The handle is no longer valid after this method is called.
 */
void cpid_finalize(_Inout_ cpid_handle_t library_handle);

/**
 * Calculates a CPID UUID using a given PID and process creation time.
 * 
 * @details uuid is populated with the CPID UUID.
 *
 * @return 0 on success, -1 on error.
 */
int cpid_make_uuid(_In_ cpid_handle_t library_handle, _In_ uint32_t pid, _In_ uint64_t creation_time_unix_epoch_seconds, _In_ uint32_t creation_time_micros_offset, _Out_ uuid_t uuid);

/**
 * Sources information for a CPID UUID and performs the calculation.
 * 
 * @details uuid is populated with the CPID UUID for the living process with the given PID.
 *
 * @return 0 on success, -1 on error.
 */
int cpid_get_uuid(_In_ cpid_handle_t library_handle, _In_ uint32_t pid, _Out_ uuid_t uuid);

/**
 * Sources information for a CPID UUID, performs the calculation
 * and converts the result to a string.
 * 
 * @details uuid_string is populated with the lowercase string representation
 *          of the CPID UUID according to RFC 9562.
 *
 * @return 0 on success, -1 on error.
 */
int cpid_get_uuid_string(_In_ cpid_handle_t library_handle, _In_ uint32_t pid, _Out_ uuid_string_t uuid_string);

#ifdef __cplusplus
}
#endif
