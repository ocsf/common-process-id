//
//	main.cpp
// 
//	A C++17 example demonstrating how to collect process information for all running processes and derive their CPIDs.
// 
// 
//	Author(s)
//	ing. E.J. Loman
//---------------------------------------------------------------------------------------------------------------------
//	ByteJams B.V.
//---------------------------------------------------------------------------------------------------------------------
#include <Windows.h>
#include <tlhelp32.h>
#include <stdio.h>

#include <CPID/Cpid.h>
#include <map>
#include <string>

//
//  Example struct holding process information
//
struct ProcessInfo
{
    DWORD           ProcessId;
    DWORD           ParentProcessId;
    std::wstring    ImageFileName;

    ProcessInfo(DWORD processId, DWORD parentProcessId, const std::wstring& imageFileName) :
        ProcessId(processId),
        ParentProcessId(parentProcessId),
        ImageFileName(imageFileName)
    {
    }
};

//
//  Define type of an STL map with cpid_t as key
//
using ProcessMap = std::map<cpid_t, ProcessInfo>;


//---------------------------------------------------------------------------------------------------------------------
// 
//  EnumProcesses
// 
//  This function enumerates all running processes and adds the to specified map.
// 
//  Params  : results [ref] pointer to a map that will receive the process information
//
//---------------------------------------------------------------------------------------------------------------------
bool EnumProcesses(ProcessMap* results)
{
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

    if (hSnapshot == INVALID_HANDLE_VALUE)
    {
        printf("CreateToolhelp32Snapshot() error %u\n", GetLastError());
        return false;
    }

    PROCESSENTRY32W pe32;
    pe32.dwSize = sizeof(pe32);

    if (Process32FirstW(hSnapshot, &pe32))
    {
        do
        {
            HANDLE hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pe32.th32ProcessID);

            if (hProcess)
            {
                FILETIME ct, et, kt, ut;
                if (GetProcessTimes(hProcess, &ct, &et, &kt, &ut))
                {
                    ULARGE_INTEGER creationTime;
                    creationTime.LowPart = ct.dwLowDateTime;
                    creationTime.HighPart = ct.dwHighDateTime;

                    cpid_t cpid;
                    if (Cpid::Derive(creationTime.QuadPart, pe32.th32ProcessID, &cpid))
                    {
                        results->emplace(
                            cpid,
                            ProcessInfo(pe32.th32ProcessID, pe32.th32ParentProcessID, pe32.szExeFile));
                    }
                }
                CloseHandle(hProcess);
            }

        } while (Process32NextW(hSnapshot, &pe32));
    }

    CloseHandle(hSnapshot);

    return true;
}


//---------------------------------------------------------------------------------------------------------------------
// 
//  main
// 
//---------------------------------------------------------------------------------------------------------------------
int main()
{
    static const char* line = "------------------------------------";

    printf("CPID C++ Example 1.0 for Microsoft Windows\n\n");
    printf("The Common Process Identifier (CPID, pronounced \"see-pid\") is a standardized specification "
           "by the Open Cybersecurity Schema Framework (OCSF) for generating unique, cross-platform "
           "process IDs that unify process tracking across systems.\n\n");

    if (!Cpid::Startup())
    {
        printf(">>> CPID startup failed!\n");
    }
    else
    {
        bool pass = Cpid::SelfTest();

        printf(">>> CPID self-test: %s\n\n", pass ? "PASS" : "FAIL!");

        if (pass)
        {
            ProcessMap processes;
            if (EnumProcesses(&processes))
            {
                printf("Found %zu running processes\r\n\r\n", processes.size());

                printf("%-36s %6s %s\n", "common-process-id (cpid)", "pid", "process name");
                printf("%.36s %.6s %.36s\n", line, line, line);

                for (const auto& [cpid, info] : processes)
                {
                    auto str = Cpid::ToString(cpid);

                    printf("%-36s %6d %ls\n", str.c_str(), info.ProcessId, info.ImageFileName.c_str());
                }
            }
        }
    }

    Cpid::Shutdown();

	return 0;
}
