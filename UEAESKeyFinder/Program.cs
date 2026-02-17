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
            Console.Title = "Universal UE AES Finder | Save to key.txt";
            Console.WriteLine("=== Universal UE AES Key Finder (4.18 - 5.4) ===");
            Console.WriteLine("0: PC Process\n1: PC File (.exe)\n2: Android (.so)\n3: APK File");
            Console.Write("\nSelect mode: ");
            
            char mode = Console.ReadKey().KeyChar;
            Console.WriteLine("\n\nEnter Target Name or Path:");
            string input = Console.ReadLine()?.Replace("\"", "");

            try
            {
                Searcher searcher = null;

                if (mode == '0') {
                    var p = Process.GetProcessesByName(input).FirstOrDefault();
                    if (p == null) throw new Exception("Process not found!");
                    searcher = new Searcher(p);
                }
                else if (mode == '1' || mode == '2') {
                    searcher = new Searcher(File.ReadAllBytes(input), mode == '2');
                }
                else if (mode == '3') {
                    Console.WriteLine("Extracting .so from APK...");
                    searcher = new Searcher(Searcher.ExtractSoFromApk(input), true);
                }

                Console.WriteLine("Searching for keys...");
                var keys = searcher.FindAllPattern(out long ms);

                // ЗАПИСЬ В ФАЙЛ
                using (StreamWriter sw = new StreamWriter("key.txt"))
                {
                    sw.WriteLine($"Search results | Found {keys.Count} keys in {ms}ms");
                    sw.WriteLine(new string('=', 40));

                    foreach (var k in keys)
                    {
                        byte[] bytes = Enumerable.Range(0, 32)
                            .Select(x => Convert.ToByte(k.Value.Substring(x * 2, 2), 16)).ToArray();
                        string b64 = Convert.ToBase64String(bytes);

                        string result = $"HEX: 0x{k.Value}\nB64: {b64}\nOffset: 0x{k.Key:X}\n";
                        
                        Console.WriteLine(result);
                        sw.WriteLine(result + "------------------------------------");
                    }
                }

                Console.ForegroundColor = ConsoleColor.Green;
                Console.WriteLine($"\nSuccess! {keys.Count} keys saved to 'key.txt'");
                Console.ResetColor();
            }
            catch (Exception ex) {
                Console.ForegroundColor = ConsoleColor.Red;
                Console.WriteLine("\nError: " + ex.Message);
                Console.ResetColor();
            }

            Console.WriteLine("Press Enter to exit.");
            Console.ReadLine();
        }
    }
}
