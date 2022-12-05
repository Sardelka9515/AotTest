using System.Runtime.InteropServices;

namespace AotTest
{
    internal class Program
    {
        static void Main(string[] args)
        {
            Hello();
        }

        [DllImport("AOT.dll")]
        public static extern void Hello();
    }
}