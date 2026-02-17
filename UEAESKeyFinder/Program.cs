using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;
using System.Threading;
using System.Text;
// Добавлено для поддержки LINQ на всякий случай
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
            Searcher searcher = new Searcher();
            Process game = null;

            Console.WriteLine("=== UE AES Key Finder ===");
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
                        Process target = null;
                        // Замена FirstOrDefault на обычный цикл для избежания ошибок
                        foreach (Process p in Process.GetProcesses())
                        {
                            if (p.ProcessName.IndexOf(procName, StringComparison.OrdinalIgnoreCase) >= 0)
                            {
                                target = p;
                                break;
                            }
                        }
                        
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
                        if (!File.Exists(path)) throw new Exception("File not found at path: " + path);
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

                StringBuilder writeToFile = new StringBuilder();
                foreach (var k in keys)
                {
                    string hexOnly = k.Value.StartsWith("0x") ? k.Value.Substring(2) : k.Value;
                    string b64 = Convert.ToBase64String(GetHex(hexOnly));
                    string output = $"{k.Value} ({b64}) at 0x{k.Key:X}";
                    Console.WriteLine(output);
                    writeToFile.AppendLine(output);
                }

                File.WriteAllText(saveName + "_aes.txt", writeToFile.ToString());
            }
            catch (Exception ex) { Console.WriteLine("Error: " + ex.Message); }

            if (game != null) try { game.Kill(); } catch { }
            Console.WriteLine("\nDone. Press Enter to exit.");
            Console.ReadLine();
        }
    }
}
