// SPDX-License-Identifier: Apache-2.0

#pragma once

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>
#include <sys/types.h>
#include <uuid/uuid.h>

typedef void *cpid_handle_t;

// uuid_string_t isn't defined by libuuid on Linux
typedef char uuid_string_t[37];

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
void cpid_finalize(cpid_handle_t const library_handle);

/**
 * Calculates a CPID UUID using a given a process creation time, namespace PID and PID-namespace scoped TGID.
 * 
 * @details uuid is populated with the CPID UUID.
 *
 * @return 0 on success, -1 on error.
 */
int cpid_make_uuid(cpid_handle_t const library_handle, const pid_t pid_namespace_tgid, const uint64_t creation_time_ticks, const ino_t pid_namespace, uuid_t uuid);

/**
 * Sources information for a CPID UUID and performs the calculation.
 * 
 * @details uuid is populated with the CPID UUID for the living process with the given userspace PID.
 *
 * @return 0 on success, -1 on error.
 */
int cpid_get_uuid(cpid_handle_t const library_handle, const pid_t pid, uuid_t uuid);

/**
 * Sources information for a CPID UUID, performs the calculation
 * and converts the result to a string.
 * 
 * @details uuid_string is populated with the lowercase string representation
 *          of the CPID UUID according to RFC 9562.
 *
 * @return 0 on success, -1 on error.
 */
int cpid_get_uuid_string(cpid_handle_t const library_handle, const pid_t pid, uuid_string_t uuid_string);

#ifdef __cplusplus
}
#endif
