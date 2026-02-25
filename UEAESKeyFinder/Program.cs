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
            // Убираем 0x если он есть в начале
            if (hex.StartsWith("0x")) hex = hex.Substring(2);
            var r = new byte[hex.Length / 2];
            for (var i = 0; i < r.Length; i++) r[i] = Convert.ToByte(hex.Substring(i * 2, 2), 16);
            return r;
        }

        static void Main(string[] args)
        {
            Searcher searcher = new Searcher();
            Process game = new Process();

            Console.WriteLine("=== Unreal Engine AES Key Finder ===");
            Console.Write("Select method:\n0: Memory (Running Process)\n1: File (Start & Suspend)\n2: Dump File\n3: Lib File (libUE4.so / libUnreal.so)\n4: APK File\nUse: ");

            // Используем ReadKey для более чистого ввода
            char method = Console.ReadKey().KeyChar;
            Console.WriteLine();

            string path;
            string EngineVersion = "4.18.0";
            string saveName = "result";

            switch (method)
            {
                case '0':
                    Console.Write("Enter process name or ID: ");
                    string ProcessName = Console.ReadLine();
                    bool found = false;
                    foreach (Process p in Process.GetProcesses())
                    {
                        if (p.ProcessName.Equals(ProcessName, StringComparison.OrdinalIgnoreCase) || p.Id.ToString() == ProcessName)
                        {
                            Console.WriteLine($"\nFound: {p.ProcessName} (PID: {p.Id})");
                            saveName = p.ProcessName;
                            searcher = new Searcher(p);
                            found = true;
                            break;
                        }
                    }
                    if (!found) { ErrorExit("Process not found."); return; }
                    break;

                case '1':
                    path = GetFilePath();
                    saveName = Path.GetFileName(path);
                    game = new Process() { StartInfo = { FileName = path } };
                    game.Start();
                    Thread.Sleep(1500); // Даем немного времени на инициализацию
                    NtSuspendProcess(game.Handle);
                    searcher = new Searcher(game);
                    searcher.SetFilePath(path);
                    break;

                case '2':
                    path = GetFilePath();
                    saveName = Path.GetFileName(path);
                    searcher = new Searcher(File.ReadAllBytes(path));
                    searcher.SetFilePath(path);
                    break;

                case '3': // Теперь поддерживает и libUE4.so, и libUnreal.so
                    path = GetFilePath();
                    saveName = Path.GetFileName(path);
                    searcher = new Searcher(File.ReadAllBytes(path), true);
                    break;

                case '4': // Анализ APK (найдет и libUE4, и libUnreal внутри)
                    path = GetFilePath();
                    saveName = Path.GetFileName(path);
                    searcher = new Searcher(File.ReadAllBytes(path), true, true);
                    break;

                default:
                    ErrorExit("Invalid selection.");
                    return;
            }

            // Пытаемся определить версию движка
            EngineVersion = searcher.SearchEngineVersion();
            if (!string.IsNullOrEmpty(EngineVersion))
                Console.WriteLine($"Detected Engine Version: {EngineVersion}");

            Console.WriteLine("Searching for patterns... please wait.");
            Dictionary<ulong, string> aesKeys = searcher.FindAllPattern(out long took);

            if (aesKeys.Count > 0)
            {
                ProcessResults(aesKeys, took, saveName, EngineVersion);
            }
            else
            {
                Console.ForegroundColor = ConsoleColor.Red;
                Console.WriteLine("\n[!] No AES Keys found.");
            }

            if (method == '1') try { game.Kill(); } catch { }
            Console.ResetColor();
            Console.WriteLine("\nPress Enter to exit.");
            Console.ReadLine();
        }

        static string GetFilePath()
        {
            Console.Write("Enter file path: ");
            return Console.ReadLine().Trim(' ', '\"');
        }

        static void ErrorExit(string msg)
        {
            Console.ForegroundColor = ConsoleColor.Red;
            Console.WriteLine($"\n[Error] {msg}");
            Console.ReadLine();
        }

        static void ProcessResults(Dictionary<ulong, string> keys, long time, string name, string version)
        {
            string output = $"Found {keys.Count} key(s) in {time}ms\n\n";
            Console.ForegroundColor = ConsoleColor.Green;
            Console.Write(output);
            Console.ResetColor();

            int verMajor = 18; // Default
            if (!string.IsNullOrEmpty(version) && version.Contains("."))
                int.TryParse(version.Split('.')[1], out verMajor);

            foreach (var entry in keys)
            {
                string keyStr = entry.Value;
                string base64 = "";
                
                // Для новых версий (4.18+) добавляем Base64 представление ключа
                if (verMajor >= 18 && keyStr.StartsWith("0x") && keyStr.Length > 10)
                {
                    try {
                        base64 = $" (Base64: {Convert.ToBase64String(GetHex(keyStr))})";
                    } catch { }
                }

                string line = $"Offset: 0x{entry.Key:X} | Key: {keyStr}{base64}\n";
                Console.Write(line);
                output += line;
            }

            File.WriteAllText(name + "_aes_keys.txt", output);
            Console.WriteLine($"\nResults saved to {name}_aes_keys.txt");
        }
    }
}
