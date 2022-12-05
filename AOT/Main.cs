using System.Runtime.InteropServices;
using static PInvoke.Kernel32;
namespace AOT
{
    public class Main
    {
        private const string Dir = @"C:\";
        public static unsafe uint Init(void* lpParam)
        {
            Console.WriteLine("Thread started from DllMain!");

            // Simple filesystem test
            Console.WriteLine("Directories in "+Dir);
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
        }

        [UnmanagedCallersOnly(EntryPoint = "DllMain")]
        public static unsafe bool DllMain(IntPtr hModule, uint ul_reason_for_call, IntPtr lpReserved)
        {
            switch (ul_reason_for_call)
            {
                case 1:
                    // Note that we run the init function in another thread so it don't cause a dead-lock
                    // More info: https://learn.microsoft.com/en-us/windows/win32/dlls/dllmain
                    CreateThread(null, (UIntPtr)0, Init, null, CreateThreadFlags.None, null);
                    break;
                default:
                    break;
            }
            return true;
        }
    }
}