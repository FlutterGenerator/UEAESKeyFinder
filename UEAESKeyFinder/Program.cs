using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;
using System.Threading;

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
            Searcher searcher = new Searcher();
            Process game = null;

            Console.WriteLine("AES Key Finder (PC/Android)");
            Console.Write("0: Memory\n1: File\n2: Dump\n3: LibUE4.so\n4: APK\nUse: ");
            
            char method = Console.ReadKey().KeyChar;
            Console.WriteLine("\n");

            string path = "";
            string saveName = "Keys";

            try {
                switch (method)
                {
                    case '0':
                        Console.Write("Enter process name: ");
                        string procName = Console.ReadLine();
                        Process target = Process.GetProcesses().FirstOrDefault(p => p.ProcessName.Contains(procName));
                        if (target == null) throw new Exception("Process not found");
                        searcher = new Searcher(target);
                        saveName = target.ProcessName;
                        break;
                    case '1':
                        Console.Write("Enter exe path: ");
                        path = Console.ReadLine().Replace("\"", "");
                        game = Process.Start(path);
                        Thread.Sleep(2000);
                        NtSuspendProcess(game.Handle);
                        searcher = new Searcher(game);
                        searcher.SetFilePath(path);
                        saveName = Path.GetFileNameWithoutExtension(path);
                        break;
                    case '2':
                    case '3':
                    case '4':
                        Console.Write("Enter file path: ");
                        path = Console.ReadLine().Replace("\"", "");
                        bool isAndroid = (method == '3' || method == '4');
                        searcher = new Searcher(File.ReadAllBytes(path), isAndroid, method == '4');
                        searcher.SetFilePath(path);
                        saveName = Path.GetFileNameWithoutExtension(path);
                        break;
                    default: return;
                }

                Console.WriteLine($"Engine Version: {searcher.SearchEngineVersion()}");
                var keys = searcher.FindAllPattern(out long took);

                Console.ForegroundColor = ConsoleColor.Green;
                Console.WriteLine($"\nFound {keys.Count} keys in {took}ms:");
                Console.ResetColor();

                string writeToFile = "";
                foreach (var k in keys)
                {
                    string b64 = Convert.ToBase64String(GetHex(k.Value));
                    string output = $"{k.Value} ({b64}) at {k.Key}";
                    Console.WriteLine(output);
                    writeToFile += output + Environment.NewLine;
                }

                File.WriteAllText(saveName + "_aes.txt", writeToFile);
            }
            catch (Exception ex) { Console.WriteLine("Error: " + ex.Message); }

            if (game != null) try { game.Kill(); } catch { }
            Console.WriteLine("\nDone. Press Enter.");
            Console.ReadLine();
        }
    }
}
