using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.IO.Compression;
using System.Text;
using System.Text.RegularExpressions;
using System.Runtime.InteropServices;

public class Searcher
{
    private bool useUE4Lib = false;

    private IntPtr hProcess;
    private Process Process;
    private ulong AllocationBase;
    private byte[] ProcessMemory;
    private string FilePath;

    public Searcher() { }

    public Searcher(Process p)
    {
        Process = p;
        hProcess = p.Handle;
        AllocationBase = (ulong)p.MainModule.BaseAddress.ToInt64();
        ProcessMemory = new byte[p.MainModule.ModuleMemorySize];

        for (int i = 0; i < ProcessMemory.Length; i += 2048)
        {
            int bytesToRead = Math.Min(2048, ProcessMemory.Length - i);
            byte[] bytes = new byte[bytesToRead];
            // FIX: адрес как IntPtr — работает на x86 (XP 32-bit) и x64
            IntPtr readAddr = new IntPtr(unchecked((long)(AllocationBase + (ulong)i)));
            int bytesRead;
            if (Win32.ReadProcessMemory(hProcess, readAddr, bytes, bytesToRead, out bytesRead))
                Array.Copy(bytes, 0, ProcessMemory, i, bytesToRead);
        }
    }

    public Searcher(byte[] bytes)
    {
        AllocationBase = 0;
        ProcessMemory = bytes;
    }

    public Searcher(byte[] bytes, bool useAndroid, bool isAPK = false)
    {
        if (isAPK)
        {
            int sigBlockOffset = 0;
            byte[] apkSigBlock = Encoding.ASCII.GetBytes("APK Sig Block");

            for (int i = bytes.Length - apkSigBlock.Length - 1; i >= 0; i--)
            {
                bool matched = true;
                for (int j = 0; j < apkSigBlock.Length; j++)
                {
                    if (bytes[i + j] != apkSigBlock[j]) { matched = false; break; }
                }
                if (matched) { sigBlockOffset = i; break; }
            }

            if (sigBlockOffset == 0)
                throw new Exception("Failed to read APK: APK Sig Block not found!");

            string[] targetLibs = { "lib/arm64-v8a/libUE4.so", "lib/arm64-v8a/libUnreal.so" };
            int foundOffset = 0;

            foreach (string libName in targetLibs)
            {
                byte[] pattern = Encoding.ASCII.GetBytes(libName);
                for (int i = sigBlockOffset; i < bytes.Length - pattern.Length - 4; i++)
                {
                    bool matched = true;
                    for (int ii = 0; ii < pattern.Length; ii++)
                    {
                        if (bytes[i + ii] != pattern[ii]) { matched = false; break; }
                    }
                    if (matched) { foundOffset = BitConverter.ToInt32(bytes, i - 4); break; }
                }
                if (foundOffset != 0) break;
            }

            if (foundOffset == 0)
                throw new Exception("Engine library (libUE4.so or libUnreal.so) not found in APK!");

            int compressed   = BitConverter.ToInt32(bytes, foundOffset + 18);
            int uncompressed = BitConverter.ToInt32(bytes, foundOffset + 22);
            short fileNameLen = BitConverter.ToInt16(bytes, foundOffset + 26);
            short extraLen    = BitConverter.ToInt16(bytes, foundOffset + 28);
            int dataStart = foundOffset + 30 + fileNameLen + extraLen;

            using (var compressedStream = new MemoryStream(bytes, dataStart, compressed))
            using (var deflateStream = new DeflateStream(compressedStream, CompressionMode.Decompress))
            using (var uncompressedLib = new MemoryStream())
            {
                // Stream.CopyTo недоступен в .NET 3.5 — читаем вручную
                byte[] buf = new byte[81920];
                int read;
                while ((read = deflateStream.Read(buf, 0, buf.Length)) > 0)
                    uncompressedLib.Write(buf, 0, read);

                if (uncompressedLib.Length != uncompressed)
                    throw new Exception("Decompression failed: Size mismatch!");
                ProcessMemory = uncompressedLib.ToArray();
            }
        }
        else
        {
            ProcessMemory = bytes;
        }

        useUE4Lib = useAndroid;
    }

    public void SetFilePath(string path) { FilePath = path; }

    public string SearchEngineVersion()
    {
        if (FilePath != null)
            return FileVersionInfo.GetVersionInfo(FilePath).FileVersion;

        byte[] ProductVersion = new byte[]
        {
            0x01, 0x00, 0x50, 0x00, 0x72, 0x00, 0x6F, 0x00,
            0x64, 0x00, 0x75, 0x00, 0x63, 0x00, 0x74, 0x00,
            0x56, 0x00, 0x65, 0x00, 0x72, 0x00, 0x73, 0x00,
            0x69, 0x00, 0x6F, 0x00, 0x6E, 0x00, 0x00, 0x00
        };

        for (int i = ProcessMemory.Length - ProductVersion.Length - 1; i >= 0; i--)
        {
            bool matched = true;
            for (int j = 0; j < ProductVersion.Length; j++)
            {
                if (ProcessMemory[i + j] != ProductVersion[j]) { matched = false; break; }
            }
            if (!matched) continue;

            var enc = new UnicodeEncoding();
            return enc.GetString(ProcessMemory, i + ProductVersion.Length - 2, 12);
        }

        return "";
    }

    public int FollowJMP(int addr)
    {
        int offset = BitConverter.ToInt32(ProcessMemory, addr + 1);
        int newAddr = addr + offset + 5;
        if (newAddr + 4 < ProcessMemory.Length && ProcessMemory[newAddr] == 0x0F && ProcessMemory[newAddr + 4] == 0xE9)
            return FollowJMP(newAddr + 4);
        return newAddr;
    }

    public ulong DecodeADRP(int adrp)
    {
        const int mask19 = (1 << 19) - 1;
        const int mask2 = 3;

        int imm = ((adrp >> 29) & mask2) | (((adrp >> 5) & mask19) << 2);
        int msbt = (imm >> 20) & 1;
        int value = imm << 12;

        long signedValue = (long)value;
        if (msbt == 1) signedValue |= -1L << 33;

        return (ulong)signedValue;
    }

    public ulong DecodeADD(int add)
    {
        var imm12 = (add & 0x3ffc00) >> 10;
        if ((imm12 & 0xc00000) != 0) imm12 <<= 12;
        return (ulong)imm12;
    }

    public int GetADRLAddress(int ADRPLoc)
    {
        ulong ADRP = DecodeADRP(BitConverter.ToInt32(ProcessMemory, ADRPLoc));
        ulong ADD  = DecodeADD(BitConverter.ToInt32(ProcessMemory, ADRPLoc + 4));
        return (int)((((ulong)ADRPLoc & 0xFFFFF000) + ADRP + ADD) & 0xFFFFFFFF);
    }

    public Dictionary<ulong, string> FindAllPattern(out long elapsedMilliseconds)
    {
        var timer = Stopwatch.StartNew();
        var offsets = new Dictionary<ulong, string>();

        if (useUE4Lib)
        {
            for (int i = 0; i < ProcessMemory.Length - 12; i++)
            {
                if (ProcessMemory[i]      != 0x01) continue;
                if (ProcessMemory[i + 1]  != 0x01) continue;
                if (ProcessMemory[i + 2]  != 0x40) continue;
                if (ProcessMemory[i + 3]  != 0xAD) continue;
                if (ProcessMemory[i + 4]  != 0x01) continue;
                if (ProcessMemory[i + 5]  != 0x00) continue;
                if (ProcessMemory[i + 6]  != 0x00) continue;
                if (ProcessMemory[i + 7]  != 0xAD) continue;
                if (ProcessMemory[i + 8]  != 0xC0) continue;
                if (ProcessMemory[i + 9]  != 0x03) continue;
                if (ProcessMemory[i + 10] != 0x5F) continue;
                if (ProcessMemory[i + 11] != 0xD6) continue;

                int aesKeyAddr = GetADRLAddress(i - 8);
                if (aesKeyAddr < 0 || aesKeyAddr + 32 > ProcessMemory.Length) continue;

                string aesKey = BitConverter.ToString(ProcessMemory, aesKeyAddr, 32).Replace("-", "");
                offsets.Add(AllocationBase + (ulong)aesKeyAddr, "0x" + aesKey);

                aesKeyAddr += 0x1000;
                if (aesKeyAddr + 32 > ProcessMemory.Length) continue;

                aesKey = BitConverter.ToString(ProcessMemory, aesKeyAddr, 32).Replace("-", "");
                offsets.Add(AllocationBase + (ulong)aesKeyAddr, "0x" + aesKey);
            }
        }
        else
        {
            string EngineVersionStr = SearchEngineVersion();
            int EngineVersion = 17;
            if (!string.IsNullOrEmpty(EngineVersionStr))
            {
                string[] parts = EngineVersionStr.Split('.');
                if (parts.Length > 1)
                    int.TryParse(parts[1], out EngineVersion);
            }

            if (EngineVersion < 18)
            {
                for (int i = 0; i < ProcessMemory.Length - 10; i++)
                {
                    if (ProcessMemory[i] != 0x00 || ProcessMemory[i + 1] != 0x30 || ProcessMemory[i + 2] != 0x78) continue;

                    int start = i;
                    while (start > 0 && ProcessMemory[start - 1] == 0x00) start--;

                    if (start - 65 < 0 || ProcessMemory[start - 65] != 0x00) continue;

                    string aesKey = Encoding.Default.GetString(ProcessMemory, start - 64, 64);
                    if (Regex.IsMatch(aesKey, @"^[a-zA-Z0-9]+$"))
                    {
                        offsets.Add(AllocationBase + (ulong)(start - 64), aesKey);
                        break;
                    }
                }
            }

            int verify_1 = 0xC7;
            for (int i = 7; i < ProcessMemory.Length - 10; i++)
            {
                try
                {
                    if (ProcessMemory[i - 3] == 0x00 && ProcessMemory[i - 2] == 0x00 && ProcessMemory[i - 1] == 0x00) continue;
                    if (ProcessMemory[i] != verify_1 || (ProcessMemory[i + 1] != 0x45 && ProcessMemory[i + 1] != 0x01)) continue;

                    int verify_2 = ProcessMemory[i + 1] == 0x01 ? 0x41 : 0x45;
                    int verify_3 = ProcessMemory[i + 1] == 0x01 ? 0    : 0xD0;

                    if (ProcessMemory[i + 1] == 0x45 && ProcessMemory[i + 2] != verify_3) continue;
                    if (ProcessMemory[i - 7] == verify_1 && ProcessMemory[i - 6] == verify_2) continue;

                    verify_3 += 0x04;
                    bool invalid = false;
                    int addr = i + 4 + 2 + (ProcessMemory[i + 1] == 0x01 ? 0 : 1);
                    string aesKey = BitConverter.ToString(ProcessMemory, addr - 4, 4).Replace("-", "");

                    while (aesKey.Length != 64)
                    {
                        if (ProcessMemory[addr] != verify_1 && ProcessMemory[addr] != 0xE9)
                        {
                            if (addr + 4 < ProcessMemory.Length && ProcessMemory[addr] == 0x0F && ProcessMemory[addr + 4] == 0xE9)
                            {
                                addr += 4;
                                addr = FollowJMP(addr);
                                if (ProcessMemory[addr] != verify_1 && ProcessMemory[addr + 1] != verify_2 && ProcessMemory[addr + 2] != verify_3)
                                    invalid = true;
                            }
                            else if (addr + 6 < ProcessMemory.Length &&
                                     ProcessMemory[addr + 4] != verify_1 &&
                                     ProcessMemory[addr + 5] != verify_2 &&
                                     ProcessMemory[addr + 6] != verify_3)
                            {
                                invalid = true;
                            }
                            else
                            {
                                addr += 4;
                            }
                        }

                        if (ProcessMemory[addr] == 0xE9)
                            addr = FollowJMP(addr);
                        else
                        {
                            if (ProcessMemory[addr + 1] != verify_2 || ProcessMemory[addr + 2] != verify_3) invalid = true;
                            aesKey += BitConverter.ToString(ProcessMemory, addr + 3, 4).Replace("-", "");
                            addr += 7;
                            verify_3 += 0x04;
                        }

                        if (aesKey.Length == 64)
                        {
                            if (ProcessMemory[addr] == 0xE9) addr = FollowJMP(addr);
                            if (ProcessMemory[addr] != 0xC3 && ProcessMemory[addr] != 0x48)
                            {
                                if (ProcessMemory[addr] != 0x0F) invalid = true;
                                bool found2 = false;
                                for (int xx = 0; xx < 30 && addr + xx + 1 < ProcessMemory.Length; xx++)
                                {
                                    if (ProcessMemory[addr + xx] == 0x48 && ProcessMemory[addr + xx + 1] == 0x8D)
                                    { found2 = true; break; }
                                }
                                if (!found2) invalid = true;
                            }
                        }

                        if (invalid) break;
                    }

                    if (invalid) continue;
                    offsets.Add(AllocationBase + (ulong)i, "0x" + aesKey);
                }
                catch { }
            }
        }

        timer.Stop();
        elapsedMilliseconds = timer.ElapsedMilliseconds;
        return offsets;
    }

    public static class Win32
    {
        // FIX: lpBaseAddress = IntPtr (не ulong!) — работает корректно на x86 И x64
        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool ReadProcessMemory(
            IntPtr hProcess,
            IntPtr lpBaseAddress,
            [Out] byte[] lpBuffer,
            int nSize,
            out int lpNumberOfBytesRead);

        [DllImport("kernel32.dll")]
        public static extern IntPtr OpenProcess(int dwDesiredAccess, bool bInheritHandle, int dwProcessId);
    }
}
