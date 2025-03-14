// SPDX-License-Identifier: Apache-2.0

#pragma once
#define WIN32_LEAN_AND_MEAN
#include <Windows.h>
#include <rpc.h>

EXTERN_C_START

/**
* Initializes the CPID library.
*
* @details This function prepares the library for use and returns a handle that
*          is required to be passed to other functions. Failure can occur if the
*          calling thread is not running at high integrity or in the case of low
*          system resources. Note that this function is relatively expensive so
*          it is recommended to call it once and reuse the handle for multiple
*          calls to the other functions in this library.
*
* @return ERROR_SUCCESS on success, appropriate Win32 error code otherwise.
*/
DWORD cpid_initialize(_Out_ HANDLE* const libraryHandle);

/**
* Makes a CPID using the supplied PID and process creation time (PCT).
*
* @details All attributes required to construct the CPID are supplied by the
*          caller. The process does not need to be running at the time this
*          function is called and, as such, this function cannot fail in normal
*          circumstances. Failure can occur however if low system resources
*          cause one of the crypto primitives called by this function to fail.
*          Note that the generated CPID is unique to the computer on which this
*          function is called and to the boot time. In other words, calling this
*          function with the same PID and PCT but on a different computer or on
*          the same computer but following a reboot will yield a different CPID.
*
* @return ERROR_SUCCESS on success, appropriate Win32 error code otherwise.
*/
DWORD cpid_make_cpid(_In_ const HANDLE libraryHandle,
                     _In_ const DWORD pid,
                     _In_ const UINT64 pct,
                     _Out_ UUID* const cpid);

/**
* Gets the CPID for the process identified by the supplied PID.
*
* @details This convenience function simplifies the obtaining of a CPID for a
*          running process. The caller must have permission to open the target
*          process with PROCESS_QUERY_LIMITED_INFORMATION access rights.
*          Failure can also occur if low system resources cause one of the
*          crypto primitives called by this function to fail. Note that this
*          function internally calls cpid_make_cpid() to construct the CPID.
*
* @return ERROR_SUCCESS on success, appropriate Win32 error code otherwise.
*/
DWORD cpid_get_cpid(_In_ const HANDLE libraryHandle,
                    _In_ const DWORD pid,
                    _Out_ UUID* const cpid);

/**
* Finalizes the CPID library.
*
* @details This function must be called to release resources allocated by the
*          cpid_initialize() function. The library handle is not valid for use
*          after this function is called.
*
* @return ERROR_SUCCESS on success, appropriate Win32 error code otherwise.
*/
DWORD cpid_finalize(_In_ const HANDLE libraryHandle);

EXTERN_C_END
