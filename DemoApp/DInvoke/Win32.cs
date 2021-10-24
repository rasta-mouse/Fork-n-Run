using System;
using System.IO;
using System.Runtime.InteropServices;

namespace DemoApp.DInvoke
{
    public static class Win32
    {
        public static bool CreateProcess(string applicationName, string lpCommandLine, uint creationFlags,
            Data.Win32.STARTUPINFOEX startupInfoEx, out Data.Win32.PROCESS_INFORMATION processInformation)
        {
            var pa = new Data.Win32.SECURITY_ATTRIBUTES();
            var ta = new Data.Win32.SECURITY_ATTRIBUTES();
            pa.nLength = (uint)Marshal.SizeOf(pa);
            ta.nLength = (uint)Marshal.SizeOf(ta);
            
            var pi = new Data.Win32.PROCESS_INFORMATION();

            object[] parameters =
            {
                applicationName, lpCommandLine, pa, ta, true, creationFlags, IntPtr.Zero,
                Directory.GetCurrentDirectory(), startupInfoEx, pi
            };
            
            var result = (bool)Generic.DynamicAPIInvoke("kernel32.dll", "CreateProcessA",
                typeof(Delegates.CreateProcessA), ref parameters);

            if (!result) processInformation = pi;

            processInformation = (Data.Win32.PROCESS_INFORMATION)parameters[9];
            return result;
        }

        public static bool InitializeProcThreadAttributeList(IntPtr lpAttributeList, int dwAttributeCount,
            ref IntPtr lpSize)
        {
            object[] parameters = { lpAttributeList, dwAttributeCount, 0, lpSize };
            
            var result = (bool)Generic.DynamicAPIInvoke("kernel32.dll", "InitializeProcThreadAttributeList",
                typeof(Delegates.InitializeProcThreadAttributeList), ref parameters);

            lpSize = (IntPtr)parameters[3];
            return result;
        }

        public static bool UpdateProcThreadAttributeList(IntPtr lpAttributeList, IntPtr attribute, IntPtr lpValue)
        {
            object[] parameters =
            {
                lpAttributeList, (uint)0, attribute, lpValue, (IntPtr)IntPtr.Size, IntPtr.Zero, IntPtr.Zero
            };
            
            var result = (bool)Generic.DynamicAPIInvoke("kernel32.dll", "UpdateProcThreadAttribute",
                typeof(Delegates.UpdateProcThreadAttribute), ref parameters);
            
            return result;
        }

        public static bool DeleteProcThreadAttributeList(IntPtr lpAttributeList)
        {
            object[] parameters = { lpAttributeList };
            
            var result = (bool)Generic.DynamicAPIInvoke("kernel32.dll", "DeleteProcThreadAttributeList",
                typeof(Delegates.DeleteProcThreadAttributeList), ref parameters);
            
            return result;
        }

        public static uint WaitForSingleObject(IntPtr hHandle, uint dwMilliseconds)
        {
            object[] parameters = { hHandle, dwMilliseconds };
            
            return (uint)Generic.DynamicAPIInvoke("kernel32.dll", "WaitForSingleObject",
                typeof(Delegates.WaitForSingleObject), ref parameters);
        }

        public static bool CloseHandle(IntPtr handle)
        {
            object[] parameters = { handle };
            
            return (bool)Generic.DynamicAPIInvoke("kernel32.dll", "CloseHandle", typeof(Delegates.CloseHandle),
                ref parameters);
        }

        public static bool DuplicateHandle(IntPtr hSourceProcessHandle, IntPtr hSourceHandle,
            IntPtr hTargetProcessHandle, ref IntPtr lpTargetHandle, uint dwDesiredAccess, bool bInheritHandle,
            Data.Win32.DuplicateOptions dwOptions)
        {
            object[] parameters =
            {
                hSourceProcessHandle, hSourceHandle, hTargetProcessHandle, lpTargetHandle, dwDesiredAccess,
                bInheritHandle, dwOptions
            };

            var result = (bool)Generic.DynamicAPIInvoke("kernel32.dll", "DuplicateHandle",
                typeof(Delegates.DuplicateHandle),
                ref parameters);

            lpTargetHandle = (IntPtr)parameters[3];
            return result;
        }

        public static bool CreatePipe(ref IntPtr hReadPipe, ref IntPtr hWritePipe,
            ref Data.Win32.SECURITY_ATTRIBUTES lpPipeAttributes, uint nSize)
        {
            object[] parameters = { hReadPipe, hWritePipe, lpPipeAttributes, nSize };

            var result = (bool)Generic.DynamicAPIInvoke("kernel32.dll", "CreatePipe", typeof(Delegates.CreatePipe),
                ref parameters);

            hReadPipe = (IntPtr)parameters[0];
            hWritePipe = (IntPtr)parameters[1];

            return result;
        }

        public static bool PeekNamedPipe(IntPtr handle, IntPtr buffer, IntPtr nBufferSize, IntPtr bytesRead, ref uint bytesAvail, IntPtr BytesLeftThisMessage)
        {
            object[] parameters = { handle, buffer, nBufferSize, bytesRead, bytesAvail, BytesLeftThisMessage };

            var result = (bool)Generic.DynamicAPIInvoke("kernel32.dll", "PeekNamedPipe", typeof(Delegates.PeekNamedPipe),
                ref parameters);

            bytesAvail = (uint)parameters[4];
            return result;
        }

        public static bool SetHandleInformation(IntPtr hObject, Data.Win32.HandleFlags dwMask,
            Data.Win32.HandleFlags dwFlags)
        {
            object[] parameters = { hObject, dwMask, dwFlags };

            return (bool)Generic.DynamicAPIInvoke("kernel32.dll", "SetHandleInformation",
                typeof(Delegates.SetHandleInformation),
                ref parameters);
        }
    }
}