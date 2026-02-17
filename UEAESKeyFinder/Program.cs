using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;

namespace UEAesKeyFinder
{
    class Program
    {
        static void Main(string[] args)
        {
            Console.Title = "Universal UE AES Finder | PC - SO - APK";
            Console.WriteLine("=== Universal UE AES Key Finder (4.18 - 5.4) ===");
            Console.WriteLine("Select Mode:");
            Console.WriteLine("0: PC Process (Memory Scan)");
            Console.WriteLine("1: PC File (.exe / .dump)");
            Console.WriteLine("2: Android Library (.so)");
            Console.WriteLine("3: Android Package (.apk)");
            Console.Write("\nChoice: ");

            char mode = Console.ReadKey().KeyChar;
            Console.WriteLine("\n");

            try
            {
                Searcher searcher = null;
                string input = "";

                switch (mode)
                {
                    case '0':
                        Console.Write("Enter Process Name (e.g. FortniteClient): ");
                        input = Console.ReadLine();
                        Process target = Process.GetProcesses().FirstOrDefault(p => p.ProcessName.Contains(input, StringComparison.OrdinalIgnoreCase));
                        if (target == null) throw new Exception("Process not found!");
                        searcher = new Searcher(target);
                        break;

                    case '1':
                    case '2':
                        Console.Write("Enter File Path: ");
                        input = Console.ReadLine().Replace("\"", "");
                        if (!File.Exists(input)) throw new Exception("File not found!");
                        searcher = new Searcher(File.ReadAllBytes(input), mode == '2');
                        break;

                    case '3':
                        Console.Write("Enter APK Path: ");
                        input = Console.ReadLine().Replace("\"", "");
                        if (!File.Exists(input)) throw new Exception("APK file not found!");
                        Console.WriteLine("Extracting library from APK...");
                        byte[] soData = Searcher.ExtractSoFromApk(input);
                        searcher = new Searcher(soData, true);
                        break;

                    default:
                        Console.WriteLine("Invalid mode.");
                        return;
                }

                Console.WriteLine("Scanning... Please wait.");
                var keys = searcher.FindAllPattern(out long ms);

                Console.ForegroundColor = ConsoleColor.Green;
                Console.WriteLine($"\nFound {keys.Count} keys in {ms} ms:");
                Console.ResetColor();

                foreach (var k in keys)
                {
                    string hex = k.Value;
                    byte[] keyBytes = Enumerable.Range(0, hex.Length)
                                     .Where(x => x % 2 == 0)
                                     .Select(x => Convert.ToByte(hex.Substring(x, 2), 16))
                                     .ToArray();

                    Console.WriteLine("--------------------------------------------------");
                    Console.WriteLine($"HEX:    0x{hex}");
                    Console.WriteLine($"Base64: {Convert.ToBase64String(keyBytes)}");
                    Console.WriteLine($"Offset: 0x{k.Key:X}");
                }
            }
            catch (Exception ex)
            {
                Console.ForegroundColor = ConsoleColor.Red;
                Console.WriteLine($"\nError: {ex.Message}");
                Console.ResetColor();
            }

            Console.WriteLine("\nPress Enter to exit.");
            Console.ReadLine();
        }
    }
}
