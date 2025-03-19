// SPDX-License-Identifier: Apache-2.0

#include <cpid/cpid_windows.h>
#include <winternl.h>
#include <bcrypt.h>
#include <stdlib.h>
#include <assert.h>

extern NTSTATUS WINAPI RtlGetVersion(_Out_ OSVERSIONINFOW* versionInfo);

#define SYSTEM_PID 4

static DWORD get_process_creation_time(_In_ const DWORD pid,
                                       _Out_ UINT64* const pct)
{
    DWORD w32err = ERROR_SUCCESS;
    HANDLE processHandle = NULL;

    // Check that the out parameter is non-null.
    if (!pct)
    {
        w32err = ERROR_INVALID_PARAMETER;
        goto Exit;
    }

    // Open the process with sufficient access to query the creation time.
    processHandle = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (!processHandle)
    {
        w32err = GetLastError();
        assert(ERROR_SUCCESS != w32err);
        goto Exit;
    }

    // Get the various timestamps associated with process.
    FILETIME _;
    if (!GetProcessTimes(processHandle, (FILETIME*)pct, &_, &_, &_))
    {
        w32err = GetLastError();
        assert(ERROR_SUCCESS != w32err);
        goto Exit;
    }

Exit:
    if (processHandle)
    {
        CloseHandle(processHandle);
    }
    return w32err;
}

typedef struct _CPID_LIBRARY_DATA
{
    UUID MachineGuid;
    UINT64 BootTime;
    BCRYPT_ALG_HANDLE Sha256AlgHandle;
} CPID_LIBRARY_DATA;

DWORD cpid_initialize(_Out_ HANDLE* const libraryHandle)
{
    DWORD w32err = ERROR_SUCCESS;
    CPID_LIBRARY_DATA* libraryData = NULL;

    // Check that parameter is non-null.
    if (!libraryHandle)
    {
        w32err = ERROR_INVALID_PARAMETER;
        goto Exit;
    }
    *libraryHandle = NULL;

    // Allocate a zero-initialised instance of the library data structure.
    libraryData = calloc(1, sizeof(CPID_LIBRARY_DATA));
    if (!libraryData)
    {
        w32err = ERROR_OUTOFMEMORY;
        goto Exit;
    }

    // Determine if the current process is WOW64.
    BOOL isWow64;
    if (!IsWow64Process(GetCurrentProcess(), &isWow64))
    {
        w32err = GetLastError();
        assert(ERROR_SUCCESS != w32err);
        goto Exit;
    }

    // Read the machine GUID in from the registry (the native registry for WOW64).
    char value[37];
    DWORD valueSize = sizeof(value);
    w32err = RegGetValueA(HKEY_LOCAL_MACHINE,
                          "SOFTWARE\\Microsoft\\Cryptography",
                          "MachineGuid",
                          RRF_RT_REG_SZ | (isWow64 ? RRF_SUBKEY_WOW6464KEY : 0),
                          NULL,
                          value,
                          &valueSize);
    if (ERROR_SUCCESS != w32err)
    {
        goto Exit;
    }

    // Parse the machine GUID which is stored in RFC UUID format.
    w32err = UuidFromStringA((RPC_CSTR)value, &libraryData->MachineGuid);
    if (ERROR_SUCCESS != w32err)
    {
        goto Exit;
    }

    // Use creation time of the System process as a proxy for boot time.
    w32err = get_process_creation_time(SYSTEM_PID, &libraryData->BootTime);
    if (ERROR_SUCCESS != w32err)
    {
        goto Exit;
    }

    // Get the Windows version information.
    RTL_OSVERSIONINFOW versionInfo;
    versionInfo.dwOSVersionInfoSize = sizeof(versionInfo);
    NTSTATUS status = RtlGetVersion(&versionInfo);
    if (!NT_SUCCESS(status))
    {
        w32err = RtlNtStatusToDosError(status);
        assert(ERROR_SUCCESS != w32err);
        goto Exit;
    }

    // Determine if we're on a pre-Win10 version.
    if (versionInfo.dwMajorVersion < 10)
    {
        // No pseudo-handles to crypto algorithms before Win10 so we must get a
        // real handle to the SHA256 algorithm.
        status = BCryptOpenAlgorithmProvider(&libraryData->Sha256AlgHandle,
                                             BCRYPT_SHA256_ALGORITHM,
                                             NULL,
                                             0);
        if (!NT_SUCCESS(status))
        {
            w32err = RtlNtStatusToDosError(status);
            assert(ERROR_SUCCESS != w32err);
            goto Exit;
        }
    }

    // Use address of library data as an opaque handle to the library.
    *libraryHandle = libraryData;

Exit:
    if (ERROR_SUCCESS != w32err)
    {
        free(libraryData);
    }
    return w32err;
}

DWORD cpid_finalize(_In_ const HANDLE libraryHandle)
{
    DWORD w32err = ERROR_SUCCESS;
    CPID_LIBRARY_DATA* libraryData = NULL;

    // Check that parameter is non-null.
    if (!libraryHandle)
    {
        w32err = ERROR_INVALID_HANDLE;
        goto Exit;
    }
    libraryData = libraryHandle;

    // Determine if we obtained a handle to the SHA256 algorithm.
    if (libraryData->Sha256AlgHandle)
    {
        // Close the SHA256 algorithm handle.
        const NTSTATUS status = BCryptCloseAlgorithmProvider(libraryData->Sha256AlgHandle, 0);
        if (!NT_SUCCESS(status))
        {
            w32err = RtlNtStatusToDosError(status);
            assert(ERROR_SUCCESS != w32err);
            goto Exit;
        }
    }
Exit:
    if (libraryData)
    {
        free(libraryData);
    }
    return w32err;
}

// Set packing level explicitly to ensure no padding in the struct. It is vital
// that the constituent parts of the message data are laid out back-to-back in
// memory.
#pragma pack(push, 1)

typedef struct _CPID_MESSAGE_DATA
{
    UUID    MachineGuid;
    UINT64  BootTime;
    UINT64  CreationTime;
    UINT64  ProcessId;
} CPID_MESSAGE_DATA;

#pragma pack(pop)

#if defined(__STDC_VERSION__) && (__STDC_VERSION__ >= 201112L)

// We have C11 or higher so do a compile time check to ensure no padding.
static_assert(sizeof(CPID_MESSAGE_DATA) == (sizeof(((CPID_MESSAGE_DATA*)NULL)->MachineGuid) +
                                            sizeof(((CPID_MESSAGE_DATA*)NULL)->BootTime) +
                                            sizeof(((CPID_MESSAGE_DATA*)NULL)->CreationTime) +
                                            sizeof(((CPID_MESSAGE_DATA*)NULL)->ProcessId)),
              "The CPID_MESSAGE_DATA structure has an unexpected size.");

#endif

DWORD cpid_make_cpid(_In_ const HANDLE libraryHandle,
                     _In_ const DWORD pid,
                     _In_ const UINT64 pct,
                     _Out_ UUID* const cpid)
{
    DWORD w32err = ERROR_SUCCESS;
    CPID_LIBRARY_DATA* libraryData = NULL;

    // Check that parameters are non-null.
    if (!libraryHandle)
    {
        w32err = ERROR_INVALID_HANDLE;
        goto Exit;
    }
    if (!cpid)
    {
        w32err = ERROR_INVALID_PARAMETER;
        goto Exit;
    }

    // Cast the caller-supplied handle to the library data structure.
    libraryData = libraryHandle;

    // Fill out the message data that is hashed to get the CPID.
    const CPID_MESSAGE_DATA messageData =
    {
        libraryData->MachineGuid,
        libraryData->BootTime,
        pct,
        pid,
    };

    // Hash the stucture using SHA256.
    UCHAR sha256Digest[32];
    const NTSTATUS status = BCryptHash(libraryData->Sha256AlgHandle
                                       ? libraryData->Sha256AlgHandle
                                       : BCRYPT_SHA256_ALG_HANDLE,
                                       NULL,
                                       0,
                                       (UCHAR*)&messageData,
                                       sizeof(messageData),
                                       sha256Digest,
                                       sizeof(sha256Digest));
    if (!NT_SUCCESS(status))
    {
        w32err = RtlNtStatusToDosError(status);
        assert(ERROR_SUCCESS != w32err);
        goto Exit;
    }

    // Use the first 16 bytes of the SHA256 as the CPID.
    memcpy(cpid, sha256Digest, sizeof(*cpid));

    // The CPID is an example of what RFC9562 terms a UUIDv8 ("a format for
    // experimental or vendor-specific use cases"). The only requirement to
    // be UUIDv8 compliant is that the 4-bit version field and 2-bit variant
    // field are set to 8.
    cpid->Data3 = (cpid->Data3 & 0x0fff) | 0x8000;
    cpid->Data4[0] = (cpid->Data4[0] & 0x3f) | 0x80;

Exit:
    return w32err;
}

DWORD cpid_get_cpid(_In_ const HANDLE libraryHandle,
                    _In_ const DWORD pid,
                    _Out_ UUID* const cpid)
{
    DWORD w32err = ERROR_SUCCESS;

    // Get the process creation time (PCT).
    UINT64 pct;
    w32err = get_process_creation_time(pid, &pct);
    if (ERROR_SUCCESS != w32err)
    {
        goto Exit;
    }

    // Call the main implementation to get the CPID from the PID and PCT.
    w32err = cpid_make_cpid(libraryHandle, pid, pct, cpid);

Exit:
    return w32err;
}
