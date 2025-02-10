using System.Buffers.Binary;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Text;
using OCSF;

namespace CpidExample
{
    internal class Program
    {
        internal struct ProcessInfo
        {
            public int ProcessId;
            public string ProcessName;
        }

        static void Main(string[] args)
        {
            Console.WriteLine("CPID C# Example 1.0 for Microsoft Windows\n");
            Console.WriteLine("The Common Process Identifier (CPID, pronounced \"see-pid\") is a standardized " +
                              "specification by the Open Cybersecurity Schema Framework (OCSF) for generating " +
                              "unique, cross-platform process IDs that unify process tracking across systems.\n");

            bool pass = Cpid.SelfTest();

            Console.WriteLine(">>> CPID self-test: {0}", pass ? "PASS" : "FAIL!");
            Console.WriteLine();

            if (pass)
            {
                SortedDictionary<Cpid, ProcessInfo> processes = new SortedDictionary<Cpid, ProcessInfo>();

                foreach (Process process in Process.GetProcesses())
                {
                    int processId = process.Id;

                    DateTime startTime;
                    string processImageFileName;

                    if (ProcessHelper.GetProcessInformation(processId, out processImageFileName, out startTime))
                    {
                        Cpid cpid = Cpid.Derive(startTime, processId);
                        
                        ProcessInfo info = new ProcessInfo { 
                            ProcessId = processId, 
                            ProcessName = Path.GetFileName(processImageFileName) };

                        processes.Add(cpid, info);
                    }
                }

                string line = new string('-', 36);
                Console.WriteLine("Found {0} running processes", processes.Count);
                Console.WriteLine();
                Console.WriteLine("{0,-36} {1,6} {2}", "common-process-id (cpid)", "pid", "process name");
                Console.WriteLine("{0} {1} {2}", line, line.Substring(0, 6), line);

                foreach (KeyValuePair<Cpid, ProcessInfo> entry in processes)
                {
                    Console.WriteLine("{0} {1,6} {2}", entry.Key, entry.Value.ProcessId, entry.Value.ProcessName);
                }
            }

            return;
        }
    }


    internal static class ProcessHelper
    {
        // Desired access flag to query limited information about the process.
        private const int PROCESS_QUERY_LIMITED_INFORMATION = 0x1000;

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern IntPtr OpenProcess(int processAccess, bool bInheritHandle, int processId);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool CloseHandle(IntPtr hObject);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool QueryFullProcessImageName(IntPtr hProcess, int dwFlags, StringBuilder lpExeName, ref int lpdwSize);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool GetProcessTimes(IntPtr hProcess, out FILETIME lpCreationTime, out FILETIME lpExitTime, out FILETIME lpKernelTime, out FILETIME lpUserTime);

        [StructLayout(LayoutKind.Sequential)]
        private struct FILETIME
        {
            public uint dwLowDateTime;
            public uint dwHighDateTime;
        }

        /// <summary>
        /// Retrieves process information for the specified process.
        /// </summary>
        /// <param name="processId">The process ID of the process.</param>
        /// <param name="processImageFileName">Receives the filename of the specified process.</param>
        /// <param name="startTime">Receives the process creation time as DateTime.</param>
        /// <returns>true when the process information was successfully returned; false otherwise.</returns>
        public static bool GetProcessInformation(
            int processId, out string processImageFileName, out DateTime startTime)
        {
            bool returnValue = false;

            processImageFileName = string.Empty;
            startTime = DateTime.MinValue;

            IntPtr hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, processId);

            if (hProcess != IntPtr.Zero)
            {
                try
                {
                    FILETIME ftCreation;
                    FILETIME ftExit;
                    FILETIME ftKernel;
                    FILETIME ftUser;

                    var sb = new StringBuilder(1024);
                    int capacity = sb.Capacity;

                    if (QueryFullProcessImageName(hProcess, 0, sb, ref capacity))
                    {
                        processImageFileName = sb.ToString();

                        if (GetProcessTimes(hProcess, out ftCreation, out ftExit, out ftKernel, out ftUser))
                        {
                            long ticks = ((long)ftCreation.dwHighDateTime << 32) | ftCreation.dwLowDateTime;

                            startTime = DateTime.FromFileTime(ticks);

                            returnValue = true;
                        }
                    }
                }
                finally
                {
                    CloseHandle(hProcess);
                }
            }

            return returnValue;
        }

    }
}
