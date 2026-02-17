using System;
using System.Diagnostics;
using System.IO;
using System.Text;
using System.Threading;
using System.Runtime.InteropServices;

namespace UEAesKeyFinder
{
    class Program
    {
        [DllImport("ntdll.dll", PreserveSig = false)]
        public static extern void NtSuspendProcess(IntPtr processHandle);

        public static byte[] HexToBytes(string hex)
        {
            if (hex.StartsWith("0x")) hex = hex.Substring(2);
            var r = new byte[hex.Length / 2];
            for (int i = 0; i < r.Length; i++)
                r[i] = Convert.ToByte(hex.Substring(i * 2, 2), 16);
            return r;
        }

        static void Main(string[] args)
        {
            Searcher searcher = new Searcher();
            Process game = null;

            Console.WriteLine("=== Unreal Engine AES Key Finder (Universal 4.18 - 4.27) ===");
            Console.Write("0: Memory\n1: File (.exe)\n2: Dump File (.dmp/.bin)\n3: LibUE4.so File\n4: APK File\nSelect Method: ");
            char method = (char)Console.Read();
            Console.ReadLine();

            string path;
            string saveName = "Result";

            switch (method)
            {
                case '0':
                    Console.Write("Enter Process Name or ID: ");
                    string procInput = Console.ReadLine();
                    bool found = false;
                    foreach (Process p in Process.GetProcesses())
                    {
                        if (p.ProcessName.Equals(procInput, StringComparison.OrdinalIgnoreCase) || p.Id.ToString() == procInput)
                        {
                            searcher = new Searcher(p);
                            saveName = p.ProcessName;
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
                        Thread.Sleep(2000);
                        try { NtSuspendProcess(game.Handle); } catch { }
                        searcher = new Searcher(game);
                    }
                    else
                        searcher = new Searcher(File.ReadAllBytes(path));
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
                    ErrorExit("Invalid method."); return;
            }

            Console.WriteLine("Searching for AES Key...");
            string key = searcher.FindSingleKey(out long elapsed);

            if (!string.IsNullOrEmpty(key))
            {
                string base64Key = Convert.ToBase64String(HexToBytes(key));
                Console.ForegroundColor = ConsoleColor.Green;
                Console.WriteLine($"\n[+] AES Key Found ({elapsed} ms):\nHEX: {key}\nBase64: {base64Key}");

                string fileName = $"{saveName}_AES_Key.txt";
                File.WriteAllText(fileName, $"HEX: {key}\nBase64: {base64Key}");
                Console.WriteLine($"\n[!] Key saved to: {fileName}");
            }
            else
            {
                Console.ForegroundColor = ConsoleColor.Red;
                Console.WriteLine("\n[-] No AES Key found.");
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
