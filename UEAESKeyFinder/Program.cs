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
            Searcher searcher = new Searcher();
            Process game = null;

            Console.Write("Please select from where you want to get the AES Key\n0: Memory\n1: File\n2: Dump File\n3. LibUE4.so File\n4. APK File\nUse: ");
            
            string input = Console.ReadLine();
            char method = string.IsNullOrEmpty(input) ? ' ' : input[0];
            
            string path;
            string EngineVersion = "4.18.0";
            string saveName = "result";

            switch (method)
            {
                case '0':
                    Console.Write("Enter the name or id of the process: ");
                    string ProcessName = Console.ReadLine();
                    Process p = Process.GetProcesses().FirstOrDefault(x => x.ProcessName.Equals(ProcessName, StringComparison.OrdinalIgnoreCase) || x.Id.ToString() == ProcessName);
                    if (p != null) {
                        Console.WriteLine($"\nFound {p.ProcessName}");
                        saveName = p.ProcessName;
                        searcher = new Searcher(p);
                    } else {
                        Console.WriteLine("Failed to find the process.");
                        return;
                    }
                    break;
                case '1':
                case '2':
                case '3':
                case '4':
                    Console.Write("Please enter the file path: ");
                    path = Console.ReadLine().Replace("\"", "");
                    if (!File.Exists(path)) { Console.WriteLine("File not found."); return; }
                    saveName = Path.GetFileNameWithoutExtension(path);
                    
                    if (method == '1') {
                        game = new Process() { StartInfo = { FileName = path } };
                        game.Start(); Thread.Sleep(1500); NtSuspendProcess(game.Handle);
                        searcher = new Searcher(game);
                    }
                    else if (method == '2') searcher = new Searcher(File.ReadAllBytes(path));
                    else if (method == '3') searcher = new Searcher(File.ReadAllBytes(path), true);
                    else if (method == '4') searcher = new Searcher(File.ReadAllBytes(path), true, true);
                    break;
            }

            EngineVersion = searcher.SearchEngineVersion();
            if (!string.IsNullOrEmpty(EngineVersion)) Console.WriteLine($"Engine Version: {EngineVersion}");

            Dictionary<ulong, string> aesKeys = searcher.FindAllPattern(out long took);

            if (aesKeys.Count > 0)
            {
                string WriteToFile = "";
                string txt = $"Found {aesKeys.Count} AES Key{(aesKeys.Count > 1 ? "s" : "")} in {took}ms\n";
                Console.ForegroundColor = ConsoleColor.Green;
                Console.Write("\n" + txt);
                Console.ForegroundColor = ConsoleColor.White;
                WriteToFile += txt;

                foreach (var o in aesKeys)
                {
                    string b64 = Convert.ToBase64String(GetHex(o.Value));
                    // ФОРМАТ: 0xКЛЮЧ (BASE64) at АДРЕС
                    string line = $"{o.Value} ({b64}) at {o.Key}\n";
                    Console.Write(line);
                    WriteToFile += line;
                }
                File.WriteAllText(saveName + "_aes_keys.txt", WriteToFile);
            }
            else Console.WriteLine("\nFailed to find any AES Keys.");

            if (game != null) try { game.Kill(); } catch { }
            Console.WriteLine("\nDone. Press Enter to exit.");
            Console.ReadLine();
        }
    }
}
