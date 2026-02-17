using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;
using System.Threading;
using System.Linq;

namespace UEAesKeyFinder
{
    class Program
    {
        [DllImport("ntdll.dll", PreserveSig = false)]
        public static extern void NtSuspendProcess(IntPtr processHandle);

        public static byte[] GetHex(string hex)
        {
            if (hex.StartsWith("0x")) hex = hex.Substring(2);
            var r = new byte[hex.Length / 2];
            for (var i = 0; i < r.Length; i++) r[i] = Convert.ToByte(hex.Substring(i * 2, 2), 16);
            return r;
        }

        static void Main(string[] args)
        {
            Searcher searcher = null;
            Console.WriteLine("=== UE AES Key Finder (PC/Android) ===");
            Console.Write("0: Memory\n1: File\n2: Dump\n3: libUE4.so\n4: APK\nUse: ");
            
            char method = Console.ReadKey().KeyChar;
            Console.WriteLine("\n");

            try {
                switch (method)
                {
                    case '0':
                        Console.Write("Enter process name: ");
                        string procName = Console.ReadLine();
                        Process target = Process.GetProcesses().FirstOrDefault(p => p.ProcessName.Contains(procName));
                        if (target == null) throw new Exception("Process not found");
                        searcher = new Searcher(target);
                        break;
                    case '1':
                    case '2':
                    case '3':
                    case '4':
                        Console.Write("Enter path: ");
                        string path = Console.ReadLine().Replace("\"", "");
                        if (!File.Exists(path)) throw new Exception("File not found");
                        
                        bool isAndroid = (method == '3' || method == '4');
                        searcher = new Searcher(File.ReadAllBytes(path), isAndroid);
                        searcher.SetFilePath(path);
                        break;
                    default: return;
                }

                var keys = searcher.FindAllPattern(out long took);
                Console.WriteLine($"Found {keys.Count} keys in {took}ms\n");

                foreach (var k in keys)
                {
                    byte[] bytes = GetHex(k.Value);
                    string b64 = Convert.ToBase64String(bytes);
                    Console.WriteLine($"HEX: {k.Value}");
                    Console.WriteLine($"B64: {b64}");
                    Console.WriteLine($"Offset: 0x{k.Key:X}\n");
                }
            } catch (Exception ex) { Console.WriteLine("Error: " + ex.Message); }

            Console.WriteLine("Done. Press Enter.");
            Console.ReadLine();
        }
    }
}
