using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;
using System.Threading;
using System.Text;

namespace UEAesKeyFinder
{
    class Program
    {
        [DllImport("ntdll.dll", PreserveSig = false)]
        public static extern void NtSuspendProcess(IntPtr processHandle);

        // Вспомогательный метод для конвертации HEX строки в массив байт (для Base64)
        public static byte[] GetHex(string hex)
        {
            // Убираем 0x если есть
            if (hex.StartsWith("0x")) hex = hex.Substring(2);
            
            var r = new byte[hex.Length / 2];
            for (var i = 0; i < r.Length; i++) 
                r[i] = Convert.ToByte(hex.Substring(i * 2, 2), 16);
            return r;
        }

        static void Main(string[] args)
        {
            Searcher searcher = new Searcher();
            Process game = new Process();

            Console.WriteLine("=== Unreal Engine AES Key Finder (Universal 4.18 - 4.27) ===");
            Console.Write("0: Memory\n1: File (.exe)\n2: Dump File (.dmp/.bin)\n3: LibUE4.so File\n4: APK File\nSelect Method: ");

            char method = (char)Console.Read();
            // Очистка буфера ввода после Console.Read
            Console.ReadLine(); 

            string path;
            string EngineVersion = "";
            string saveName = "Result";

            switch (method)
            {
                case '0':
                    Console.Write("Enter Process Name or ID: ");
                    string processInput = Console.ReadLine();
                    bool found = false;
                    foreach (Process p in Process.GetProcesses())
                    {
                        if (p.ProcessName.Equals(processInput, StringComparison.OrdinalIgnoreCase) || p.Id.ToString() == processInput)
                        {
                            Console.WriteLine($"\n[+] Found Process: {p.ProcessName} (PID: {p.Id})");
                            saveName = p.ProcessName;
                            searcher = new Searcher(p);
                            found = true;
                            break;
                        }
                    }
                    if (!found) { ErrorExit("Process not found."); return; }
                    break;

                case '1':
                case '2':
                    Console.Write("Enter File Path: ");
                    path = Console.ReadLine().Replace("\"", "");
                    if (!File.Exists(path)) { ErrorExit("File not found."); return; }
                    saveName = Path.GetFileName(path);

                    if (method == '1')
                    {
                        game = Process.Start(path);
                        Thread.Sleep(2000); // Даем время на инициализацию
                        try { NtSuspendProcess(game.Handle); } catch { }
                        searcher = new Searcher(game);
                    }
                    else
                    {
                        searcher = new Searcher(File.ReadAllBytes(path));
                    }
                    searcher.SetFilePath(path);
                    break;

                case '3':
                    Console.Write("Enter libUE4.so Path: ");
                    path = Console.ReadLine().Replace("\"", "");
                    if (!File.Exists(path)) { ErrorExit("File not found."); return; }
                    saveName = Path.GetFileName(path);
                    searcher = new Searcher(File.ReadAllBytes(path), true);
                    break;

                case '4':
                    Console.Write("Enter APK Path: ");
                    path = Console.ReadLine().Replace("\"", "");
                    if (!File.Exists(path)) { ErrorExit("File not found."); return; }
                    saveName = Path.GetFileName(path);
                    searcher = new Searcher(File.ReadAllBytes(path), true, true);
                    break;

                default:
                    ErrorExit("Invalid method.");
                    return;
            }

            // Попытка определить версию (не критично, если не найдет)
            EngineVersion = searcher.SearchEngineVersion();
            if (!string.IsNullOrEmpty(EngineVersion))
                Console.WriteLine($"Detected Engine Version: {EngineVersion}");

            Console.WriteLine("Searching for AES Keys...");
            Dictionary<ulong, string> aesKeys = searcher.FindAllPattern(out long took);

            if (aesKeys.Count > 0)
            {
                StringBuilder fileOutput = new StringBuilder();
                string header = $"\nFound {aesKeys.Count} potential AES Key(s) in {took}ms\n";
                Console.ForegroundColor = ConsoleColor.Green;
                Console.WriteLine(header);
                Console.ForegroundColor = ConsoleColor.White;
                fileOutput.AppendLine(header);

                foreach (var entry in aesKeys)
                {
                    string hexKey = entry.Value; // Это уже "0x..."
                    string base64Key = "";

                    try 
                    {
                        // Пытаемся сделать Base64 (необходимо для некоторых инструментов распаковки)
                        base64Key = Convert.ToBase64String(GetHex(hexKey));
                    }
                    catch { base64Key = "N/A"; }

                    string resultLine = $"Address: 0x{entry.Key:X} | HEX: {hexKey} | Base64: {base64Key}";
                    Console.WriteLine(resultLine);
                    fileOutput.AppendLine(resultLine);
                }

                string fileName = $"{saveName}_AES_Keys.txt";
                File.WriteAllText(fileName, fileOutput.ToString());
                Console.WriteLine($"\n[!] Keys saved to: {fileName}");
            }
            else
            {
                Console.ForegroundColor = ConsoleColor.Red;
                Console.WriteLine("\n[-] No AES Keys found. The game might not be encrypted or uses custom protection.");
            }

            if (method == '1' && game != null) try { game.Kill(); } catch { }
            Console.ResetColor();
            Console.WriteLine("\nPress Enter to exit...");
            Console.ReadLine();
        }

        static void ErrorExit(string message)
        {
            Console.ForegroundColor = ConsoleColor.Red;
            Console.WriteLine($"\nError: {message}");
            Console.ResetColor();
            Console.ReadLine();
        }
    }
}
