// SPDX-License-Identifier: Apache-2.0

#include <cpid/cpid_windows.h>
#include <stdio.h>
#include <stdlib.h>

int main(int argc, char** argv)
{
    if (argc != 2)
    {
        fprintf(stderr, "usage: %s <pid>\n", argv[0]);
        return ERROR_INVALID_PARAMETER;
    }

    HANDLE libraryHandle;
    DWORD w32err = cpid_initialize(&libraryHandle);
    if (ERROR_SUCCESS != w32err)
    {
        fprintf(stderr, "Error code %lu when initializing CPID library.\n", w32err);
        return w32err;
    }

    UUID cpid;
    w32err = cpid_get_cpid(libraryHandle, atol(argv[1]), &cpid);
    (void)cpid_finalize(libraryHandle);
    if (ERROR_SUCCESS != w32err)
    {
        fprintf(stderr, "Error code %lu when getting the CPID.\n", w32err);
        return w32err;
    }

    RPC_CSTR cpidString;
    w32err = UuidToStringA(&cpid, &cpidString);
    if (ERROR_SUCCESS != w32err)
    {
        fprintf(stderr, "Error code %lu when stringifying the CPID.\n", w32err);
        return w32err;
    }
    puts((const char*)cpidString);
    RpcStringFreeA(&cpidString);

    return ERROR_SUCCESS;
}
