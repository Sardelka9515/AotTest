using System.Diagnostics;
using System.Runtime.InteropServices;
using static PInvoke.Kernel32;
using Console = System.Console;
using System.Linq;
namespace AOT
{
    public class Main
    {
        private const string Dir = @"C:\";
        public static unsafe uint Init(void* lpParam)
        {

            Thread.Sleep(200);
            Console.WriteLine("Thread started from DllMain!");
            Console.WriteLine("Directories in " + Dir);
            foreach (var d in Directory.GetDirectories(Dir))
            {
                Console.WriteLine(d);
            }
            return 0;
        }

        [UnmanagedCallersOnly(EntryPoint = "Hello")]
        public static void Hello()
        {
            Console.WriteLine("Hello!");
            try
            {

            }
            catch(Exception ex)
            {
                // stuff
            }
        }
        [DllImport("kernel32.dll")]
        public static extern bool GetModuleHandleEx(GetModuleHandleExFlags dwFlags, IntPtr lpName, out IntPtr handle);


        [UnmanagedCallersOnly(EntryPoint = "DllMain")]
        public static bool DllMain(IntPtr hModule, uint ul_reason_for_call, IntPtr lpReserved)
        {
            // Console.WriteLine("DllMain: "+ul_reason_for_call);
            switch (ul_reason_for_call)
            {
                case 1:
                    // Note that we run the init function in another thread so it don't cause a dead-lock
                    // More info: https://learn.microsoft.com/en-us/windows/win32/dlls/dllmain
                    // CreateThread(null, (UIntPtr)0, Init, null, CreateThreadFlags.None, null);
                    break;
            }
            return true;
        }
    }
}