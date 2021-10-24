using System;
using System.Runtime.InteropServices;

namespace DemoApp.DInvoke
{
    public static class Native
    {
        public static void RtlInitUnicodeString(ref Data.Native.UNICODE_STRING destinationString,
            [MarshalAs(UnmanagedType.LPWStr)] string sourceString)
        {
            object[] parameters = { destinationString, sourceString };
            
            Generic.DynamicAPIInvoke("ntdll.dll", "RtlInitUnicodeString", typeof(Delegates.RtlInitUnicodeString),
                ref parameters);
            
            destinationString = (Data.Native.UNICODE_STRING)parameters[0];
        }

        public static Data.Native.NTSTATUS LdrLoadDll(IntPtr pathToFile, uint dwFlags,
            ref Data.Native.UNICODE_STRING moduleFileName, ref IntPtr moduleHandle)
        {
            object[] parameters = { pathToFile, dwFlags, moduleFileName, moduleHandle };

            var result = (Data.Native.NTSTATUS)Generic.DynamicAPIInvoke("ntdll.dll", "LdrLoadDll",
                typeof(Delegates.LdrLoadDll), ref parameters);

            moduleHandle = (IntPtr)parameters[3];
            return result;
        }

        public static Data.Native.PROCESS_BASIC_INFORMATION NtQueryInformationProcessBasicInformation(IntPtr hProcess)
        {
            var result = NtQueryInformationProcess(hProcess, Data.Native.PROCESSINFOCLASS.ProcessBasicInformation,
                out var pProcInfo);

            if (result != Data.Native.NTSTATUS.Success)
                throw new UnauthorizedAccessException("Access is denied.");

            return (Data.Native.PROCESS_BASIC_INFORMATION)Marshal.PtrToStructure(pProcInfo,
                typeof(Data.Native.PROCESS_BASIC_INFORMATION));
        }

        private static Data.Native.NTSTATUS NtQueryInformationProcess(IntPtr hProcess,
            Data.Native.PROCESSINFOCLASS processInfoClass, out IntPtr pProcInfo)
        {
            int processInformationLength;
            uint retLen = 0;

            switch (processInfoClass)
            {
                case Data.Native.PROCESSINFOCLASS.ProcessWow64Information:
                    pProcInfo = Marshal.AllocHGlobal(IntPtr.Size);
                    RtlZeroMemory(pProcInfo, IntPtr.Size);
                    processInformationLength = IntPtr.Size;
                    break;

                case Data.Native.PROCESSINFOCLASS.ProcessBasicInformation:
                    var pbi = new Data.Native.PROCESS_BASIC_INFORMATION();
                    pProcInfo = Marshal.AllocHGlobal(Marshal.SizeOf(pbi));
                    RtlZeroMemory(pProcInfo, Marshal.SizeOf(pbi));
                    Marshal.StructureToPtr(pbi, pProcInfo, true);
                    processInformationLength = Marshal.SizeOf(pbi);
                    break;

                default:
                    throw new InvalidOperationException($"Invalid ProcessInfoClass: {processInfoClass}");
            }

            object[] parameters = { hProcess, processInfoClass, pProcInfo, processInformationLength, retLen };

            var retValue = (Data.Native.NTSTATUS)Generic.DynamicAPIInvoke("ntdll.dll", "NtQueryInformationProcess",
                typeof(Delegates.NtQueryInformationProcess), ref parameters);

            if (retValue != Data.Native.NTSTATUS.Success)
                throw new UnauthorizedAccessException("Access is denied.");

            pProcInfo = (IntPtr)parameters[2];
            return retValue;
        }

        public static void RtlZeroMemory(IntPtr destination, int length)
        {
            object[] parameters = { destination, length };
            Generic.DynamicAPIInvoke("ntdll.dll", "RtlZeroMemory", typeof(Delegates.RtlZeroMemory), ref parameters);
        }

        public static uint NtProtectVirtualMemory(IntPtr processHandle, ref IntPtr baseAddress, ref IntPtr regionSize,
            uint newProtect)
        {
            uint oldProtect = 0;
            object[] parameters = { processHandle, baseAddress, regionSize, newProtect, oldProtect };

            _ = (uint)Generic.DynamicAPIInvoke("ntdll.dll", "NtProtectVirtualMemory",
                typeof(Delegates.NtProtectVirtualMemory), ref parameters);
            
            oldProtect = (uint)parameters[4];
            return oldProtect;
        }

        public static uint NtWriteVirtualMemory(IntPtr processHandle, IntPtr baseAddress, IntPtr buffer,
            uint bufferLength)
        {
            uint bytesWritten = 0;
            object[] parameters = { processHandle, baseAddress, buffer, bufferLength, bytesWritten };

            _ = (uint)Generic.DynamicAPIInvoke("ntdll.dll", "NtWriteVirtualMemory",
                typeof(Delegates.NtWriteVirtualMemory), ref parameters);
            
            bytesWritten = (uint)parameters[4];
            return bytesWritten;
        }

        public static uint NtReadVirtualMemory(IntPtr processHandle, IntPtr baseAddress, IntPtr buffer,
            ref uint numberOfBytesToRead)
        {
            uint numberOfBytesRead = 0;
            object[] parameters = { processHandle, baseAddress, buffer, numberOfBytesToRead, numberOfBytesRead };

            _ = (uint)Generic.DynamicAPIInvoke("ntdll.dll", "NtReadVirtualMemory",
                typeof(Delegates.NtReadVirtualMemory), ref parameters);

            numberOfBytesRead = (uint)parameters[4];
            return numberOfBytesRead;
        }

        public static IntPtr NtAllocateVirtualMemory(IntPtr processHandle, ref IntPtr baseAddress, IntPtr zeroBits,
            ref IntPtr regionSize, uint allocationType, uint protect)
        {
            object[] parameters = { processHandle, baseAddress, zeroBits, regionSize, allocationType, protect };

            _ = (Data.Native.NTSTATUS)Generic.DynamicAPIInvoke("ntdll.dll", "NtAllocateVirtualMemory",
                typeof(Delegates.NtAllocateVirtualMemory), ref parameters);

            baseAddress = (IntPtr)parameters[1];
            return baseAddress;
        }

        public static uint NtResumeThread(IntPtr hThread, IntPtr suspendCount)
        {
            object[] parameters = { hThread, suspendCount };
            
            return (uint)Generic.DynamicAPIInvoke("ntdll.dll", "NtResumeThread", typeof(Delegates.NtResumeThread),
                ref parameters);
        }

        public static Data.Native.NTSTATUS NtCreateThreadEx(ref IntPtr threadHandle,
            Data.Win32.ACCESS_MASK desiredAccess, IntPtr objectAttributes, IntPtr processHandle, IntPtr startAddress,
            IntPtr parameter, bool createSuspended, int stackZeroBits, int sizeOfStack, int maximumStackSize,
            IntPtr attributeList)
        {
            object[] parameters =
            {
                threadHandle, desiredAccess, objectAttributes, processHandle, startAddress, parameter, createSuspended,
                stackZeroBits,
                sizeOfStack, maximumStackSize, attributeList
            };

            var result = (Data.Native.NTSTATUS)Generic.DynamicAPIInvoke("ntdll.dll", "NtCreateThreadEx",
                typeof(Delegates.NtCreateThreadEx), ref parameters);

            threadHandle = (IntPtr)parameters[0];
            return result;
        }
    }
}