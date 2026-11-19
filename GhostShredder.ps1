param(
    [string]$TargetPath = "",
    [switch]$DeepScanWorker,
    [switch]$MapScanWorker,
    [string]$CandidatePids = ""
)

# GhostShredder v0.3.0-alpha3
# Standalone Windows force-delete utility. No realtime protection, no antivirus hooks.
# Windows PowerShell 5.1+ / Windows 10-11 x64 recommended.

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

function Test-IsAdministrator {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    $p = New-Object Security.Principal.WindowsPrincipal($id)
    return $p.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

if (-not (Test-IsAdministrator)) {
    $ps = "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe"
    $arg = "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`""
    if ($TargetPath) {
        $safe = $TargetPath.Replace('"','\"')
        $arg += " -TargetPath `"$safe`""
    }
    if ($DeepScanWorker) { $arg += " -DeepScanWorker" }
    if ($MapScanWorker) { $arg += " -MapScanWorker" }
    if ($CandidatePids) { $arg += " -CandidatePids `"$CandidatePids`"" }
    Start-Process -FilePath $ps -Verb RunAs -ArgumentList $arg
    exit
}

Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing

$nativeSource = @"
using System;
using System.Text;
using System.IO;
using System.Diagnostics;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;

public static class GhostNative
{
    public static int LastCwdUnreadable = 0;
    public static int LastCwdUnduplicable = 0;
    public static int LastHandleProcessesInaccessible = 0;
    public static int LastHandlePathResolutionFailures = 0;
    public static int LastMappingProcessesInaccessible = 0;
    const int SystemExtendedHandleInformation = 64;
    const int ProcessBasicInformation = 0;
    const int ProcessWow64Information = 26;
    const int STATUS_INFO_LENGTH_MISMATCH = unchecked((int)0xC0000004);

    const uint PROCESS_DUP_HANDLE = 0x0040;
    const uint PROCESS_VM_READ = 0x0010;
    const uint PROCESS_QUERY_INFORMATION = 0x0400;
    const uint PROCESS_QUERY_LIMITED_INFORMATION = 0x1000;

    const uint DUPLICATE_CLOSE_SOURCE = 0x00000001;
    const uint DUPLICATE_SAME_ACCESS = 0x00000002;

    const uint TOKEN_ADJUST_PRIVILEGES = 0x20;
    const uint TOKEN_QUERY = 0x8;
    const uint SE_PRIVILEGE_ENABLED = 0x2;

    const uint DELETE = 0x00010000;
    const uint FILE_READ_ATTRIBUTES = 0x80;
    const uint FILE_SHARE_READ = 0x1;
    const uint FILE_SHARE_WRITE = 0x2;
    const uint FILE_SHARE_DELETE = 0x4;
    const uint OPEN_EXISTING = 3;
    const uint FILE_FLAG_BACKUP_SEMANTICS = 0x02000000;
    const uint FILE_ATTRIBUTE_NORMAL = 0x80;

    const int FileDispositionInfoEx = 21;
    const uint FILE_DISPOSITION_FLAG_DELETE = 0x00000001;
    const uint FILE_DISPOSITION_FLAG_POSIX_SEMANTICS = 0x00000002;
    const uint FILE_DISPOSITION_FLAG_IGNORE_READONLY_ATTRIBUTE = 0x00000010;

    const uint MOVEFILE_DELAY_UNTIL_REBOOT = 0x00000004;
    const uint FILE_TYPE_DISK = 0x0001;

    const uint MEM_COMMIT = 0x1000;
    const uint MEM_MAPPED = 0x40000;
    const uint MEM_IMAGE = 0x1000000;

    [StructLayout(LayoutKind.Sequential)]
    struct SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX
    {
        public IntPtr Object;
        public UIntPtr UniqueProcessId;
        public UIntPtr HandleValue;
        public uint GrantedAccess;
        public ushort CreatorBackTraceIndex;
        public ushort ObjectTypeIndex;
        public uint HandleAttributes;
        public uint Reserved;
    }

    [StructLayout(LayoutKind.Sequential)]
    struct PROCESS_BASIC_INFORMATION
    {
        public IntPtr Reserved1;
        public IntPtr PebBaseAddress;
        public IntPtr Reserved2_0;
        public IntPtr Reserved2_1;
        public IntPtr UniqueProcessId;
        public IntPtr Reserved3;
    }

    [StructLayout(LayoutKind.Sequential)]
    struct LUID { public uint LowPart; public int HighPart; }

    [StructLayout(LayoutKind.Sequential)]
    struct LUID_AND_ATTRIBUTES { public LUID Luid; public uint Attributes; }

    [StructLayout(LayoutKind.Sequential)]
    struct TOKEN_PRIVILEGES { public uint PrivilegeCount; public LUID_AND_ATTRIBUTES Privileges; }

    [StructLayout(LayoutKind.Sequential)]
    struct FILE_DISPOSITION_INFO_EX { public uint Flags; }

    [StructLayout(LayoutKind.Sequential)]
    struct MEMORY_BASIC_INFORMATION
    {
        public IntPtr BaseAddress;
        public IntPtr AllocationBase;
        public uint AllocationProtect;
        public UIntPtr RegionSize;
        public uint State;
        public uint Protect;
        public uint Type;
    }

    public class CwdLock
    {
        public int Pid;
        public string ProcessName;
        public string CurrentDirectory;
        public ulong HandleValue;
        public override string ToString() { return ProcessName + " (PID " + Pid + ")  cwd=" + CurrentDirectory + "  handle=0x" + HandleValue.ToString("X"); }
    }

    public class HandleLock
    {
        public int Pid;
        public string ProcessName;
        public string Path;
        public ulong HandleValue;
        public override string ToString() { return ProcessName + " (PID " + Pid + ")  handle=0x" + HandleValue.ToString("X") + "  " + Path; }
    }

    public class MappingLock
    {
        public int Pid;
        public string ProcessName;
        public string Path;
        public string MappingType;
        public ulong BaseAddress;
        public override string ToString() { return ProcessName + " (PID " + Pid + ")  " + MappingType + "  base=0x" + BaseAddress.ToString("X") + "  " + Path; }
    }

    [DllImport("ntdll.dll")]
    static extern int NtQuerySystemInformation(int SystemInformationClass, IntPtr SystemInformation, int SystemInformationLength, ref int ReturnLength);

    [DllImport("ntdll.dll")]
    static extern int NtQueryInformationProcess(IntPtr ProcessHandle, int ProcessInformationClass, IntPtr ProcessInformation, int ProcessInformationLength, ref int ReturnLength);

    [DllImport("kernel32.dll", SetLastError=true)]
    static extern IntPtr OpenProcess(uint dwDesiredAccess, bool bInheritHandle, int dwProcessId);

    [DllImport("kernel32.dll", SetLastError=true)]
    static extern bool ReadProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, int dwSize, out IntPtr lpNumberOfBytesRead);

    [DllImport("kernel32.dll", SetLastError=true)]
    static extern bool DuplicateHandle(IntPtr hSourceProcessHandle, IntPtr hSourceHandle, IntPtr hTargetProcessHandle, out IntPtr lpTargetHandle, uint dwDesiredAccess, bool bInheritHandle, uint dwOptions);

    [DllImport("kernel32.dll")]
    static extern IntPtr GetCurrentProcess();

    [DllImport("kernel32.dll", SetLastError=true)]
    static extern bool CloseHandle(IntPtr hObject);

    [DllImport("kernel32.dll", CharSet=CharSet.Unicode, SetLastError=true)]
    static extern uint GetFinalPathNameByHandle(IntPtr hFile, StringBuilder lpszFilePath, uint cchFilePath, uint dwFlags);

    [DllImport("kernel32.dll")]
    static extern uint GetFileType(IntPtr hFile);

    [DllImport("advapi32.dll", SetLastError=true)]
    static extern bool OpenProcessToken(IntPtr ProcessHandle, uint DesiredAccess, out IntPtr TokenHandle);

    [DllImport("advapi32.dll", CharSet=CharSet.Unicode, SetLastError=true)]
    static extern bool LookupPrivilegeValue(string lpSystemName, string lpName, out LUID lpLuid);

    [DllImport("advapi32.dll", SetLastError=true)]
    static extern bool AdjustTokenPrivileges(IntPtr TokenHandle, bool DisableAllPrivileges, ref TOKEN_PRIVILEGES NewState, int BufferLength, IntPtr PreviousState, IntPtr ReturnLength);

    [DllImport("kernel32.dll", CharSet=CharSet.Unicode, SetLastError=true)]
    static extern IntPtr CreateFile(string lpFileName, uint dwDesiredAccess, uint dwShareMode, IntPtr lpSecurityAttributes, uint dwCreationDisposition, uint dwFlagsAndAttributes, IntPtr hTemplateFile);

    [DllImport("kernel32.dll", SetLastError=true)]
    static extern bool SetFileInformationByHandle(IntPtr hFile, int FileInformationClass, ref FILE_DISPOSITION_INFO_EX lpFileInformation, uint dwBufferSize);

    [DllImport("kernel32.dll", CharSet=CharSet.Unicode, SetLastError=true)]
    static extern bool MoveFileEx(string lpExistingFileName, string lpNewFileName, uint dwFlags);

    [DllImport("kernel32.dll", SetLastError=true)]
    static extern UIntPtr VirtualQueryEx(IntPtr hProcess, IntPtr lpAddress, out MEMORY_BASIC_INFORMATION lpBuffer, UIntPtr dwLength);

    [DllImport("psapi.dll", CharSet=CharSet.Unicode, SetLastError=true)]
    static extern uint GetMappedFileName(IntPtr hProcess, IntPtr lpv, StringBuilder lpFilename, uint nSize);

    [DllImport("kernel32.dll", CharSet=CharSet.Unicode, SetLastError=true)]
    static extern uint QueryDosDevice(string lpDeviceName, StringBuilder lpTargetPath, int ucchMax);

    static readonly IntPtr INVALID_HANDLE_VALUE = new IntPtr(-1);

    public static bool EnableDebugPrivilege()
    {
        IntPtr token;
        if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, out token)) return false;
        try {
            LUID luid;
            if (!LookupPrivilegeValue(null, "SeDebugPrivilege", out luid)) return false;
            TOKEN_PRIVILEGES tp = new TOKEN_PRIVILEGES();
            tp.PrivilegeCount = 1;
            tp.Privileges = new LUID_AND_ATTRIBUTES { Luid = luid, Attributes = SE_PRIVILEGE_ENABLED };
            return AdjustTokenPrivileges(token, false, ref tp, Marshal.SizeOf(typeof(TOKEN_PRIVILEGES)), IntPtr.Zero, IntPtr.Zero);
        } finally { CloseHandle(token); }
    }

    public static string NormalizePath(string path)
    {
        if (String.IsNullOrWhiteSpace(path)) return path;
        string p = path.Trim().TrimEnd('\\');
        if (p.StartsWith("\\\\?\\UNC\\", StringComparison.OrdinalIgnoreCase)) p = "\\\\" + p.Substring(8);
        else if (p.StartsWith("\\\\?\\", StringComparison.OrdinalIgnoreCase)) p = p.Substring(4);
        return p.TrimEnd('\\');
    }

    static bool IsTargetOrChild(string candidate, string target)
    {
        if (String.IsNullOrEmpty(candidate)) return false;
        candidate = NormalizePath(candidate);
        target = NormalizePath(target);
        if (candidate.Equals(target, StringComparison.OrdinalIgnoreCase)) return true;
        return candidate.StartsWith(target + "\\", StringComparison.OrdinalIgnoreCase);
    }

    static byte[] ReadBytes(IntPtr process, long address, int count)
    {
        byte[] b = new byte[count];
        IntPtr read;
        if (!ReadProcessMemory(process, new IntPtr(address), b, count, out read) || read.ToInt64() < count) return null;
        return b;
    }

    static ulong ReadPtr64(IntPtr process, long address)
    {
        byte[] b = ReadBytes(process, address, 8); if (b == null) return 0; return BitConverter.ToUInt64(b,0);
    }
    static uint ReadPtr32(IntPtr process, long address)
    {
        byte[] b = ReadBytes(process, address, 4); if (b == null) return 0; return BitConverter.ToUInt32(b,0);
    }
    static string ReadUnicode(IntPtr process, long address, int byteLen)
    {
        if (address == 0 || byteLen <= 0 || byteLen > 32766) return null;
        byte[] b = ReadBytes(process, address, byteLen); if (b == null) return null;
        return Encoding.Unicode.GetString(b).TrimEnd('\0');
    }

    static bool TryReadCurrentDirectory(int pid, out string cwd, out ulong handleValue)
    {
        cwd = null; handleValue = 0;
        IntPtr h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, false, pid);
        if (h == IntPtr.Zero) return false;
        try {
            // If ProcessWow64Information returns nonzero, process uses 32-bit PEB.
            IntPtr wowBuf = Marshal.AllocHGlobal(IntPtr.Size);
            try {
                Marshal.WriteIntPtr(wowBuf, IntPtr.Zero);
                int ret = 0;
                int stWow = NtQueryInformationProcess(h, ProcessWow64Information, wowBuf, IntPtr.Size, ref ret);
                IntPtr peb32 = stWow == 0 ? Marshal.ReadIntPtr(wowBuf) : IntPtr.Zero;
                if (peb32 != IntPtr.Zero) {
                    uint pp = ReadPtr32(h, peb32.ToInt64() + 0x10);
                    if (pp == 0) return false;
                    byte[] us = ReadBytes(h, pp + 0x24, 12);
                    if (us == null) return false;
                    ushort len = BitConverter.ToUInt16(us,0);
                    uint buf = BitConverter.ToUInt32(us,4);
                    handleValue = BitConverter.ToUInt32(us,8);
                    cwd = ReadUnicode(h, buf, len);
                    return !String.IsNullOrEmpty(cwd);
                }
            } finally { Marshal.FreeHGlobal(wowBuf); }

            PROCESS_BASIC_INFORMATION pbi = new PROCESS_BASIC_INFORMATION();
            IntPtr pbiBuf = Marshal.AllocHGlobal(Marshal.SizeOf(typeof(PROCESS_BASIC_INFORMATION)));
            try {
                int ret = 0;
                int st = NtQueryInformationProcess(h, ProcessBasicInformation, pbiBuf, Marshal.SizeOf(typeof(PROCESS_BASIC_INFORMATION)), ref ret);
                if (st != 0) return false;
                pbi = (PROCESS_BASIC_INFORMATION)Marshal.PtrToStructure(pbiBuf, typeof(PROCESS_BASIC_INFORMATION));
                if (pbi.PebBaseAddress == IntPtr.Zero) return false;
                ulong pp = ReadPtr64(h, pbi.PebBaseAddress.ToInt64() + 0x20);
                if (pp == 0) return false;
                byte[] us = ReadBytes(h, (long)pp + 0x38, 24);
                if (us == null) return false;
                ushort len = BitConverter.ToUInt16(us,0);
                ulong buf = BitConverter.ToUInt64(us,8);
                handleValue = BitConverter.ToUInt64(us,16);
                cwd = ReadUnicode(h, (long)buf, len);
                return !String.IsNullOrEmpty(cwd);
            } finally { Marshal.FreeHGlobal(pbiBuf); }
        }
        finally { CloseHandle(h); }
    }

    static bool IsRemoteHandleOpen(int pid, ulong handleValue)
    {
        if (handleValue == 0) return false;
        IntPtr ph = OpenProcess(PROCESS_DUP_HANDLE, false, pid);
        if (ph == IntPtr.Zero) return false;
        try {
            IntPtr dup;
            bool ok = DuplicateHandle(ph, new IntPtr(unchecked((long)handleValue)), GetCurrentProcess(), out dup, 0, false, DUPLICATE_SAME_ACCESS);
            if (ok && dup != IntPtr.Zero) CloseHandle(dup);
            return ok;
        }
        finally { CloseHandle(ph); }
    }

    public static CwdLock[] FindCurrentDirectoryLocks(string target)
    {
        EnableDebugPrivilege();
        LastCwdUnreadable = 0;
        LastCwdUnduplicable = 0;
        List<CwdLock> found = new List<CwdLock>();
        int self = Process.GetCurrentProcess().Id;
        foreach (Process p in Process.GetProcesses()) {
            try {
                if (p.Id == self || p.Id == 0) continue;
                string cwd; ulong hv;
                if (!TryReadCurrentDirectory(p.Id, out cwd, out hv)) { LastCwdUnreadable++; continue; }
                if (!IsTargetOrChild(cwd, target)) continue;
                if (!IsRemoteHandleOpen(p.Id, hv)) { LastCwdUnduplicable++; continue; }
                string name = "pid" + p.Id;
                try { name = p.ProcessName; } catch {}
                found.Add(new CwdLock { Pid=p.Id, ProcessName=name, CurrentDirectory=NormalizePath(cwd), HandleValue=hv });
            } catch {}
            finally { try { p.Dispose(); } catch {} }
        }
        return found.ToArray();
    }

    static IntPtr QueryHandleTable(out int entryCount)
    {
        entryCount = 0;
        int len = 1024 * 1024;
        IntPtr buf = IntPtr.Zero;
        for (int i=0; i<8; i++) {
            if (buf != IntPtr.Zero) Marshal.FreeHGlobal(buf);
            buf = Marshal.AllocHGlobal(len);
            int retLen = 0;
            int st = NtQuerySystemInformation(SystemExtendedHandleInformation, buf, len, ref retLen);
            if (st == 0) {
                long n = IntPtr.Size == 8 ? Marshal.ReadInt64(buf) : Marshal.ReadInt32(buf);
                if (n > Int32.MaxValue) n = Int32.MaxValue;
                entryCount = (int)n;
                return buf;
            }
            if (st != STATUS_INFO_LENGTH_MISMATCH) break;
            len = Math.Max(len * 2, retLen + 65536);
        }
        if (buf != IntPtr.Zero) Marshal.FreeHGlobal(buf);
        return IntPtr.Zero;
    }

    static ushort GetFileObjectTypeIndex()
    {
        string tmp = Path.Combine(Path.GetTempPath(), "ghostshredder-typeprobe-" + Guid.NewGuid().ToString("N") + ".tmp");
        IntPtr h = CreateFile(tmp, 0x80000000, FILE_SHARE_READ|FILE_SHARE_WRITE|FILE_SHARE_DELETE, IntPtr.Zero, 2, FILE_ATTRIBUTE_NORMAL, IntPtr.Zero);
        if (h == INVALID_HANDLE_VALUE) return 0;
        try {
            int count;
            IntPtr table = QueryHandleTable(out count);
            if (table == IntPtr.Zero) return 0;
            try {
                int pid = Process.GetCurrentProcess().Id;
                ulong hv = (ulong)h.ToInt64();
                int header = IntPtr.Size * 2;
                int size = Marshal.SizeOf(typeof(SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX));
                for (int i=0; i<count; i++) {
                    IntPtr ep = new IntPtr(table.ToInt64() + header + (long)i * size);
                    SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX e = (SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX)Marshal.PtrToStructure(ep, typeof(SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX));
                    if (e.UniqueProcessId.ToUInt64() == (ulong)pid && e.HandleValue.ToUInt64() == hv) return e.ObjectTypeIndex;
                }
                return 0;
            }
            finally { Marshal.FreeHGlobal(table); }
        }
        finally {
            CloseHandle(h);
            try { File.Delete(tmp); } catch {}
        }
    }

    static string GetHandlePath(IntPtr remoteProcess, ulong handleValue)
    {
        IntPtr dup;
        if (!DuplicateHandle(remoteProcess, new IntPtr(unchecked((long)handleValue)), GetCurrentProcess(), out dup, 0, false, DUPLICATE_SAME_ACCESS)) return null;
        try {
            if (GetFileType(dup) != FILE_TYPE_DISK) return null;
            StringBuilder sb = new StringBuilder(32768);
            uint n = GetFinalPathNameByHandle(dup, sb, (uint)sb.Capacity, 0);
            if (n == 0 || n >= sb.Capacity) return null;
            return NormalizePath(sb.ToString());
        }
        finally { CloseHandle(dup); }
    }

    static HandleLock[] FindPathHandlesInternal(string target, HashSet<int> pidFilter)
    {
        EnableDebugPrivilege();
        LastHandleProcessesInaccessible = 0;
        LastHandlePathResolutionFailures = 0;
        List<HandleLock> found = new List<HandleLock>();
        ushort fileType = GetFileObjectTypeIndex();
        int count;
        IntPtr table = QueryHandleTable(out count);
        if (table == IntPtr.Zero) return found.ToArray();
        try {
            int header = IntPtr.Size * 2;
            int size = Marshal.SizeOf(typeof(SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX));
            Dictionary<int,IntPtr> procHandles = new Dictionary<int,IntPtr>();
            Dictionary<int,string> procNames = new Dictionary<int,string>();
            int self = Process.GetCurrentProcess().Id;
            try {
                for (int i=0; i<count; i++) {
                    IntPtr ep = new IntPtr(table.ToInt64() + header + (long)i * size);
                    SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX e = (SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX)Marshal.PtrToStructure(ep, typeof(SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX));
                    if (fileType != 0 && e.ObjectTypeIndex != fileType) continue;
                    int pid;
                    try { pid = unchecked((int)e.UniqueProcessId.ToUInt64()); } catch { continue; }
                    if (pid <= 0 || pid == self) continue;
                    if (pidFilter != null && !pidFilter.Contains(pid)) continue;

                    IntPtr ph;
                    if (!procHandles.TryGetValue(pid, out ph)) {
                        ph = OpenProcess(PROCESS_DUP_HANDLE | PROCESS_QUERY_LIMITED_INFORMATION, false, pid);
                        if (ph == IntPtr.Zero) LastHandleProcessesInaccessible++;
                        procHandles[pid] = ph;
                        string name = "pid" + pid;
                        try { using (Process proc = Process.GetProcessById(pid)) name = proc.ProcessName; } catch {}
                        procNames[pid] = name;
                    }
                    if (ph == IntPtr.Zero) continue;

                    string hp = null;
                    try { hp = GetHandlePath(ph, e.HandleValue.ToUInt64()); } catch {}
                    if (hp == null) { LastHandlePathResolutionFailures++; continue; }
                    if (IsTargetOrChild(hp, target)) {
                        found.Add(new HandleLock { Pid=pid, ProcessName=procNames[pid], Path=hp, HandleValue=e.HandleValue.ToUInt64() });
                    }
                }
            }
            finally {
                foreach (IntPtr ph in procHandles.Values) if (ph != IntPtr.Zero) CloseHandle(ph);
            }
        }
        finally { Marshal.FreeHGlobal(table); }
        return found.ToArray();
    }

    public static HandleLock[] FindPathHandles(string target)
    {
        return FindPathHandlesInternal(target, null);
    }

    public static HandleLock[] FindPathHandlesForPids(string target, int[] pids)
    {
        if (pids == null || pids.Length == 0) return FindPathHandles(target);
        HashSet<int> filter = new HashSet<int>(pids);
        return FindPathHandlesInternal(target, filter);
    }

    static Dictionary<string,string> BuildDeviceMap()
    {
        Dictionary<string,string> map = new Dictionary<string,string>(StringComparer.OrdinalIgnoreCase);
        for (char c='A'; c<='Z'; c++) {
            string drive = c + ":";
            StringBuilder sb = new StringBuilder(4096);
            uint n = QueryDosDevice(drive, sb, sb.Capacity);
            if (n == 0) continue;
            string device = sb.ToString();
            int z = device.IndexOf('\0');
            if (z >= 0) device = device.Substring(0,z);
            if (!String.IsNullOrEmpty(device)) map[device] = drive;
        }
        return map;
    }

    static string DevicePathToDos(string path, Dictionary<string,string> map)
    {
        if (String.IsNullOrEmpty(path)) return path;
        foreach (KeyValuePair<string,string> kv in map) {
            if (path.StartsWith(kv.Key, StringComparison.OrdinalIgnoreCase)) {
                return NormalizePath(kv.Value + path.Substring(kv.Key.Length));
            }
        }
        const string mup = "\\Device\\Mup\\";
        if (path.StartsWith(mup, StringComparison.OrdinalIgnoreCase)) return NormalizePath("\\\\" + path.Substring(mup.Length));
        return NormalizePath(path);
    }

    public static MappingLock[] FindMappedPaths(string target)
    {
        EnableDebugPrivilege();
        LastMappingProcessesInaccessible = 0;
        List<MappingLock> found = new List<MappingLock>();
        HashSet<string> seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        Dictionary<string,string> deviceMap = BuildDeviceMap();
        int self = Process.GetCurrentProcess().Id;
        foreach (Process p in Process.GetProcesses()) {
            IntPtr ph = IntPtr.Zero;
            try {
                if (p.Id <= 0 || p.Id == self) continue;
                ph = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, false, p.Id);
                if (ph == IntPtr.Zero) { LastMappingProcessesInaccessible++; continue; }
                ulong addr = 0;
                const ulong maxUser = 0x00007FFFFFFFFFFFUL;
                int mbiSize = Marshal.SizeOf(typeof(MEMORY_BASIC_INFORMATION));
                while (addr < maxUser) {
                    MEMORY_BASIC_INFORMATION mbi;
                    UIntPtr got = VirtualQueryEx(ph, new IntPtr(unchecked((long)addr)), out mbi, (UIntPtr)mbiSize);
                    if (got == UIntPtr.Zero) { addr += 0x1000; continue; }
                    ulong baseAddr = (ulong)mbi.BaseAddress.ToInt64();
                    ulong region = mbi.RegionSize.ToUInt64();
                    if (region == 0) break;
                    if (mbi.State == MEM_COMMIT && (mbi.Type == MEM_MAPPED || mbi.Type == MEM_IMAGE)) {
                        StringBuilder sb = new StringBuilder(32768);
                        uint n = GetMappedFileName(ph, mbi.BaseAddress, sb, (uint)sb.Capacity);
                        if (n > 0 && n < sb.Capacity) {
                            string hp = DevicePathToDos(sb.ToString(), deviceMap);
                            if (IsTargetOrChild(hp, target)) {
                                string mt = mbi.Type == MEM_IMAGE ? "IMAGE" : "MAPPED";
                                string key = p.Id + "|" + mt + "|" + hp;
                                if (seen.Add(key)) {
                                    string name = "pid" + p.Id;
                                    try { name = p.ProcessName; } catch {}
                                    found.Add(new MappingLock { Pid=p.Id, ProcessName=name, Path=hp, MappingType=mt, BaseAddress=baseAddr });
                                }
                            }
                        }
                    }
                    ulong next = baseAddr + region;
                    if (next <= addr) break;
                    addr = next;
                }
            } catch {}
            finally { if (ph != IntPtr.Zero) CloseHandle(ph); try { p.Dispose(); } catch {} }
        }
        return found.ToArray();
    }

    public static bool ProbeDeleteAccess(string path, out int error)
    {
        error = 0;
        string p = path;
        if (p.StartsWith("\\\\") && !p.StartsWith("\\\\?\\")) p = "\\\\?\\UNC\\" + p.Substring(2);
        else if (!p.StartsWith("\\\\?\\")) p = "\\\\?\\" + p;
        IntPtr h = CreateFile(p, DELETE | FILE_READ_ATTRIBUTES, FILE_SHARE_READ|FILE_SHARE_WRITE|FILE_SHARE_DELETE, IntPtr.Zero, OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS, IntPtr.Zero);
        if (h == INVALID_HANDLE_VALUE) { error = Marshal.GetLastWin32Error(); return false; }
        CloseHandle(h);
        return true;
    }

    public static bool CloseRemoteHandle(int pid, ulong handleValue)
    {
        EnableDebugPrivilege();
        IntPtr ph = OpenProcess(PROCESS_DUP_HANDLE, false, pid);
        if (ph == IntPtr.Zero) return false;
        try {
            IntPtr dup;
            bool ok = DuplicateHandle(ph, new IntPtr(unchecked((long)handleValue)), GetCurrentProcess(), out dup, 0, false, DUPLICATE_SAME_ACCESS | DUPLICATE_CLOSE_SOURCE);
            if (ok && dup != IntPtr.Zero) CloseHandle(dup);
            return ok;
        }
        finally { CloseHandle(ph); }
    }

    public static bool TryPosixDelete(string path, out int error)
    {
        error = 0;
        string p = path;
        if (p.StartsWith("\\\\") && !p.StartsWith("\\\\?\\")) p = "\\\\?\\UNC\\" + p.Substring(2);
        else if (!p.StartsWith("\\\\?\\")) p = "\\\\?\\" + p;
        IntPtr h = CreateFile(p, DELETE | FILE_READ_ATTRIBUTES, FILE_SHARE_READ|FILE_SHARE_WRITE|FILE_SHARE_DELETE, IntPtr.Zero, OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS, IntPtr.Zero);
        if (h == INVALID_HANDLE_VALUE) { error = Marshal.GetLastWin32Error(); return false; }
        try {
            FILE_DISPOSITION_INFO_EX info = new FILE_DISPOSITION_INFO_EX();
            info.Flags = FILE_DISPOSITION_FLAG_DELETE | FILE_DISPOSITION_FLAG_POSIX_SEMANTICS | FILE_DISPOSITION_FLAG_IGNORE_READONLY_ATTRIBUTE;
            bool ok = SetFileInformationByHandle(h, FileDispositionInfoEx, ref info, (uint)Marshal.SizeOf(typeof(FILE_DISPOSITION_INFO_EX)));
            if (!ok) error = Marshal.GetLastWin32Error();
            return ok;
        }
        finally { CloseHandle(h); }
    }

    public static bool ScheduleDeleteOnReboot(string path)
    {
        return MoveFileEx(path, null, MOVEFILE_DELAY_UNTIL_REBOOT);
    }
}
"@

try {
    Add-Type -TypeDefinition $nativeSource -Language CSharp -ErrorAction Stop
} catch {
    if ($DeepScanWorker) {
        [Console]::Error.WriteLine("NATIVE_COMPILE_ERROR|" + $_.Exception.Message)
    } else {
        [System.Windows.Forms.MessageBox]::Show("Native helper compile failed:`r`n$($_.Exception.Message)", "GhostShredder", 'OK', 'Error') | Out-Null
    }
    exit 1
}


$restartManagerSource = @"
using System;
using System.Text;
using System.Runtime.InteropServices;
using System.Collections.Generic;

public static class GhostRestartManager
{
    const int CCH_RM_SESSION_KEY = 32;
    const int CCH_RM_MAX_APP_NAME = 255;
    const int CCH_RM_MAX_SVC_NAME = 63;
    const int ERROR_SUCCESS = 0;
    const int ERROR_MORE_DATA = 234;

    [StructLayout(LayoutKind.Sequential)]
    struct FILETIME {
        public uint dwLowDateTime;
        public uint dwHighDateTime;
    }

    [StructLayout(LayoutKind.Sequential)]
    struct RM_UNIQUE_PROCESS {
        public int dwProcessId;
        public FILETIME ProcessStartTime;
    }

    enum RM_APP_TYPE {
        RmUnknownApp = 0,
        RmMainWindow = 1,
        RmOtherWindow = 2,
        RmService = 3,
        RmExplorer = 4,
        RmConsole = 5,
        RmCritical = 1000
    }

    [StructLayout(LayoutKind.Sequential, CharSet=CharSet.Unicode)]
    struct RM_PROCESS_INFO {
        public RM_UNIQUE_PROCESS Process;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst=CCH_RM_MAX_APP_NAME + 1)]
        public string strAppName;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst=CCH_RM_MAX_SVC_NAME + 1)]
        public string strServiceShortName;
        public RM_APP_TYPE ApplicationType;
        public uint AppStatus;
        public uint TSSessionId;
        [MarshalAs(UnmanagedType.Bool)]
        public bool bRestartable;
    }

    public class LockingProcess {
        public int Pid;
        public string AppName;
        public string ServiceName;
        public override string ToString() {
            string n = String.IsNullOrWhiteSpace(AppName) ? ("pid" + Pid) : AppName;
            return n + " (PID " + Pid + ")";
        }
    }

    [DllImport("rstrtmgr.dll", CharSet=CharSet.Unicode)]
    static extern int RmStartSession(out uint pSessionHandle, int dwSessionFlags, StringBuilder strSessionKey);

    [DllImport("rstrtmgr.dll", CharSet=CharSet.Unicode)]
    static extern int RmRegisterResources(
        uint dwSessionHandle,
        uint nFiles,
        [MarshalAs(UnmanagedType.LPArray, ArraySubType=UnmanagedType.LPWStr)] string[] rgsFileNames,
        uint nApplications,
        IntPtr rgApplications,
        uint nServices,
        IntPtr rgsServiceNames);

    [DllImport("rstrtmgr.dll")]
    static extern int RmGetList(
        uint dwSessionHandle,
        out uint pnProcInfoNeeded,
        ref uint pnProcInfo,
        [In, Out] RM_PROCESS_INFO[] rgAffectedApps,
        ref uint lpdwRebootReasons);

    [DllImport("rstrtmgr.dll")]
    static extern int RmEndSession(uint pSessionHandle);

    public static int LastError = 0;

    public static LockingProcess[] FindLockingProcesses(string fullFilePath)
    {
        LastError = 0;
        if (String.IsNullOrWhiteSpace(fullFilePath)) return new LockingProcess[0];

        uint handle;
        StringBuilder key = new StringBuilder(CCH_RM_SESSION_KEY + 1);
        int rc = RmStartSession(out handle, 0, key);
        if (rc != ERROR_SUCCESS) {
            LastError = rc;
            return new LockingProcess[0];
        }

        try {
            rc = RmRegisterResources(handle, 1, new string[] { fullFilePath }, 0, IntPtr.Zero, 0, IntPtr.Zero);
            if (rc != ERROR_SUCCESS) {
                LastError = rc;
                return new LockingProcess[0];
            }

            uint needed = 0;
            uint count = 0;
            uint reasons = 0;
            rc = RmGetList(handle, out needed, ref count, null, ref reasons);
            if (rc == ERROR_SUCCESS && needed == 0) return new LockingProcess[0];
            if (rc != ERROR_MORE_DATA) {
                LastError = rc;
                return new LockingProcess[0];
            }

            RM_PROCESS_INFO[] infos = new RM_PROCESS_INFO[needed];
            count = needed;
            rc = RmGetList(handle, out needed, ref count, infos, ref reasons);
            if (rc != ERROR_SUCCESS) {
                LastError = rc;
                return new LockingProcess[0];
            }

            Dictionary<int,LockingProcess> unique = new Dictionary<int,LockingProcess>();
            for (int i = 0; i < count; i++) {
                int pid = infos[i].Process.dwProcessId;
                if (pid <= 0) continue;
                if (!unique.ContainsKey(pid)) {
                    unique[pid] = new LockingProcess {
                        Pid = pid,
                        AppName = infos[i].strAppName,
                        ServiceName = infos[i].strServiceShortName
                    };
                }
            }
            LockingProcess[] result = new LockingProcess[unique.Count];
            unique.Values.CopyTo(result, 0);
            return result;
        }
        finally {
            RmEndSession(handle);
        }
    }
}
"@

try {
    Add-Type -TypeDefinition $restartManagerSource -Language CSharp -ErrorAction Stop
    $script:RestartManagerCompileError = $null
} catch {
    $script:RestartManagerCompileError = $_.Exception.Message
}

$script:DropHelperCompileError = $null
$script:NativeDropStatus = $null

$dropSource = @"
using System;
using System.Text;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Windows.Forms;

public sealed class GhostDropEventArgs : EventArgs
{
    public string[] Paths { get; private set; }
    public GhostDropEventArgs(string[] paths) { Paths = paths ?? new string[0]; }
}

// WinForms AllowDrop uses OLE drag/drop, which Windows UIPI normally blocks when
// Explorer runs at medium integrity and GhostShredder is elevated.  This helper
// additionally enables the classic WM_DROPFILES path and explicitly allows the
// required messages through the elevated window's message filter.
public sealed class GhostElevatedDropTarget : NativeWindow, IDisposable
{
    const int WM_DROPFILES = 0x0233;
    const uint WM_COPYGLOBALDATA = 0x0049;
    const uint WM_COPYDATA = 0x004A;
    const uint MSGFLT_ALLOW = 1;

    [DllImport("shell32.dll")]
    static extern void DragAcceptFiles(IntPtr hWnd, bool fAccept);

    [DllImport("shell32.dll", CharSet = CharSet.Unicode)]
    static extern uint DragQueryFile(IntPtr hDrop, uint iFile, StringBuilder lpszFile, uint cch);

    [DllImport("shell32.dll")]
    static extern void DragFinish(IntPtr hDrop);

    [DllImport("user32.dll", SetLastError = true)]
    static extern bool ChangeWindowMessageFilterEx(IntPtr hWnd, uint message, uint action, IntPtr changeInfo);

    public event EventHandler<GhostDropEventArgs> FilesDropped;
    public bool DropMessageAllowed { get; private set; }
    public bool CopyGlobalAllowed { get; private set; }
    public bool CopyDataAllowed { get; private set; }

    public GhostElevatedDropTarget(IntPtr hwnd)
    {
        AssignHandle(hwnd);
        // WM_DROPFILES carries the HDROP; WM_COPYGLOBALDATA is required by the
        // shell for cross-integrity global-memory transfer on UAC systems.
        DropMessageAllowed = ChangeWindowMessageFilterEx(hwnd, (uint)WM_DROPFILES, MSGFLT_ALLOW, IntPtr.Zero);
        CopyGlobalAllowed = ChangeWindowMessageFilterEx(hwnd, WM_COPYGLOBALDATA, MSGFLT_ALLOW, IntPtr.Zero);
        CopyDataAllowed = ChangeWindowMessageFilterEx(hwnd, WM_COPYDATA, MSGFLT_ALLOW, IntPtr.Zero);
        DragAcceptFiles(hwnd, true);
    }

    protected override void WndProc(ref Message m)
    {
        if (m.Msg == WM_DROPFILES)
        {
            IntPtr hDrop = m.WParam;
            try
            {
                uint count = DragQueryFile(hDrop, 0xFFFFFFFF, null, 0);
                List<string> paths = new List<string>((int)count);
                for (uint i = 0; i < count; i++)
                {
                    uint len = DragQueryFile(hDrop, i, null, 0);
                    StringBuilder sb = new StringBuilder((int)len + 1);
                    if (DragQueryFile(hDrop, i, sb, (uint)sb.Capacity) > 0)
                        paths.Add(sb.ToString());
                }
                EventHandler<GhostDropEventArgs> handler = FilesDropped;
                if (handler != null && paths.Count > 0)
                    handler(this, new GhostDropEventArgs(paths.ToArray()));
            }
            finally { DragFinish(hDrop); }
            return;
        }
        base.WndProc(ref m);
    }

    public void Dispose()
    {
        try { if (Handle != IntPtr.Zero) DragAcceptFiles(Handle, false); } catch { }
        try { ReleaseHandle(); } catch { }
    }
}
"@

try {
    Add-Type -TypeDefinition $dropSource -Language CSharp -ReferencedAssemblies @('System.Windows.Forms.dll','System.dll') -ErrorAction Stop
} catch {
    # Do not abort the utility if the optional elevated drag/drop helper fails to
    # compile.  File/folder buttons and manual path entry remain available.
    $script:DropHelperCompileError = $_.Exception.Message
}

# Deep handle-name resolution is deliberately isolated in a child PowerShell.
# Some filesystem/filter-driver handles can block path resolution indefinitely;
# killing the worker must never freeze the GUI or the main shredding path.
if ($DeepScanWorker) {
    try {
        $candidateArray = @()
        if ($CandidatePids) {
            foreach ($piece in ($CandidatePids -split ',')) {
                $v = 0
                if ([int]::TryParse($piece.Trim(), [ref]$v) -and $v -gt 0) { $candidateArray += $v }
            }
        }
        $items = if ($candidateArray.Count -gt 0) {
            @([GhostNative]::FindPathHandlesForPids($TargetPath, [int[]]$candidateArray))
        } else {
            @([GhostNative]::FindPathHandles($TargetPath))
        }
        foreach ($x in $items) {
            $name = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes([string]$x.ProcessName))
            $path = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes([string]$x.Path))
            [Console]::Out.WriteLine("GS_HANDLE|$($x.Pid)|$($x.HandleValue)|$name|$path")
        }
        [Console]::Out.WriteLine("GS_HANDLEMETA|$([GhostNative]::LastHandleProcessesInaccessible)|$([GhostNative]::LastHandlePathResolutionFailures)")
        exit 0
    } catch {
        [Console]::Error.WriteLine("DEEP_SCAN_ERROR|" + $_.Exception.Message)
        exit 2
    }
}

if ($MapScanWorker) {
    try {
        $items = @([GhostNative]::FindMappedPaths($TargetPath))
        foreach ($x in $items) {
            $name = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes([string]$x.ProcessName))
            $path = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes([string]$x.Path))
            [Console]::Out.WriteLine("GS_MAP|$($x.Pid)|$($x.MappingType)|$($x.BaseAddress)|$name|$path")
        }
        [Console]::Out.WriteLine("GS_MAPMETA|$([GhostNative]::LastMappingProcessesInaccessible)")
        exit 0
    } catch {
        [Console]::Error.WriteLine("MAP_SCAN_ERROR|" + $_.Exception.Message)
        exit 3
    }
}

function Get-NormalPath([string]$Path) {
    if ([string]::IsNullOrWhiteSpace($Path)) { return $null }
    $raw = $Path.Trim('"').Trim()
    # "C:" is drive-relative in Win32, not the same thing as "C:\". Keep it explicit.
    if ($raw -match '^[A-Za-z]:$') { return $raw }
    try {
        $full = [System.IO.Path]::GetFullPath($raw)
        $root = [System.IO.Path]::GetPathRoot($full)
        if ($root -and ($full.TrimEnd('\') -ieq $root.TrimEnd('\'))) { return $root }
        return $full.TrimEnd('\')
    } catch {
        return $raw.TrimEnd('\')
    }
}

function Test-IsRootPath([string]$Path) {
    if ([string]::IsNullOrWhiteSpace($Path)) { return $false }
    $raw = $Path.Trim('"').Trim()
    if ($raw -match '^[A-Za-z]:$') { return $true }
    try {
        $full = [System.IO.Path]::GetFullPath($raw)
        $root = [System.IO.Path]::GetPathRoot($full)
        if (-not $root) { return $false }
        return ($full.TrimEnd('\') -ieq $root.TrimEnd('\'))
    } catch { return $false }
}

function Assert-SafeTarget([string]$Path, [switch]$ForMutation) {
    $p = Get-NormalPath $Path
    if (-not $p) { Write-Log '目标路径为空。'; return $null }
    if ($ForMutation -and (Test-IsRootPath $p)) {
        Write-Log "安全保护：拒绝对盘符根目录 / UNC share 根目录执行句柄修改或删除操作：$p"
        [System.Windows.Forms.MessageBox]::Show(
            "GhostShredder 拒绝对盘符根目录或 UNC share 根目录执行解除占用、删除或粉碎。`r`n`r`n目标：$p",
            'GhostShredder - 根目录保护',
            [System.Windows.Forms.MessageBoxButtons]::OK,
            [System.Windows.Forms.MessageBoxIcon]::Stop
        ) | Out-Null
        return $null
    }
    return $p
}

$script:LastAnalysisSnapshot = $null

function Invalidate-AnalysisSnapshot([string]$Reason = '目标状态已被修改', [switch]$Log) {
    # 快照失效属于内部状态迁移。默认静默，避免在已明确记录“句柄已关闭”后重复打印因果说明。
    # 仅在调用方确实需要向用户解释快照为何不可复用时，显式使用 -Log。
    if ($Log -and $script:LastAnalysisSnapshot) {
        Write-Log "分析快照已失效：$Reason"
    }
    $script:LastAnalysisSnapshot = $null
}

function Get-AnalysisSnapshotText([string]$Path) {
    $p = Get-NormalPath $Path
    $snap = $script:LastAnalysisSnapshot
    if (-not $snap -or -not $p -or $snap.Path -ine $p) { return $null }

    $age = [Math]::Max(0, [int]((Get-Date) - $snap.Timestamp).TotalSeconds)
    $lines = New-Object System.Collections.Generic.List[string]
    $lines.Add("最近一次完整分析快照：$($snap.Timestamp.ToString('HH:mm:ss'))（约 ${age}s 前；仅代表当次观测）")

    $cwd = @($snap.Cwd)
    if ($cwd.Count) { $lines.Add("  A/CWD：发现 $($cwd.Count) 个") }
    elseif ($snap.CwdUnreadable -gt 0 -or $snap.CwdUnduplicable -gt 0) { $lines.Add("  A/CWD：本次暂未发现可确认命中（受限进程=$($snap.CwdUnreadable)，不可复制目标句柄=$($snap.CwdUnduplicable)）") }
    else { $lines.Add('  A/CWD：本次暂未发现') }

    if ($snap.HandleScan.TimedOut) { $lines.Add('  B/普通句柄：本次扫描未完成（超时），未形成结论') }
    elseif (@($snap.HandleScan.Locks).Count) { $lines.Add("  B/普通句柄：发现 $(@($snap.HandleScan.Locks).Count) 个") }
    elseif ($snap.HandleScan.Inaccessible -gt 0 -or $snap.HandleScan.PathFailures -gt 0) { $lines.Add("  B/普通句柄：本次暂未发现可确认命中（不可访问进程=$($snap.HandleScan.Inaccessible)，路径解析失败=$($snap.HandleScan.PathFailures)）") }
    else { $lines.Add('  B/普通句柄：本次暂未发现') }

    if ($snap.MapScan.TimedOut) { $lines.Add('  C/Mapping：本次扫描未完成（超时），未形成结论') }
    elseif (@($snap.MapScan.Locks).Count) { $lines.Add("  C/Mapping：发现 $(@($snap.MapScan.Locks).Count) 个") }
    elseif ($snap.MapScan.Inaccessible -gt 0) { $lines.Add("  C/Mapping：本次暂未发现可确认命中（不可访问进程=$($snap.MapScan.Inaccessible)）") }
    else { $lines.Add('  C/Mapping：本次暂未发现') }

    switch ($snap.Smb.Status) {
        'OK' { if (@($snap.Smb.Locks).Count) { $lines.Add("  D/SMB：发现 $(@($snap.Smb.Locks).Count) 个远程打开项") } else { $lines.Add('  D/SMB：本次暂未发现远程打开项') } }
        'REMOTE_TARGET' { $lines.Add('  D/SMB：目标位于远程路径；本机不对远端占用形成结论') }
        default { $lines.Add('  D/SMB：本次未形成可用结论') }
    }
    if ($snap.Filters.Status -eq 'OK') { $lines.Add("  E/Filter：诊断信息；本次解析到 $(@($snap.Filters.Names).Count) 个实例（不等于占用）") }
    else { $lines.Add('  E/Filter：本次未形成可用诊断结果') }

    $lines.Add('提示：占用状态会动态变化；以上不是“此刻仍然如此”的保证。')
    return ($lines -join "`r`n")
}

function Format-HandlePreview([object[]]$Locks, [int]$MaxItems = 8) {
    $items = @($Locks)
    if ($items.Count -eq 0) { return '本次普通句柄扫描暂未发现可确认命中。' }
    $lines = New-Object System.Collections.Generic.List[string]
    $lines.Add("发现 $($items.Count) 个普通文件/目录句柄：")
    $n = [Math]::Min($items.Count, $MaxItems)
    for ($i = 0; $i -lt $n; $i++) {
        $x = $items[$i]
        $lines.Add("  • $($x.ProcessName) PID=$($x.Pid) handle=0x$($x.HandleValue.ToString('X'))`r`n    $($x.Path)")
    }
    if ($items.Count -gt $MaxItems) { $lines.Add("  • ……另有 $($items.Count - $MaxItems) 个") }
    return ($lines -join "`r`n")
}

function Get-QuickCwdPreview([string]$Path) {
    $p = Get-NormalPath $Path
    if (-not $p -or -not (Test-TargetExists $p)) { return @() }
    try {
        [GhostNative]::EnableDebugPrivilege() | Out-Null
        return @([GhostNative]::FindCurrentDirectoryLocks($p))
    } catch { return @() }
}

function Format-CwdPreview([object[]]$Locks, [int]$MaxItems = 6) {
    $items = @($Locks)
    if ($items.Count -eq 0) { return '快速预检：本次暂未发现 CWD 占用。其他类别尚未进行本次预检。' }
    $lines = New-Object System.Collections.Generic.List[string]
    $lines.Add("快速预检：发现 $($items.Count) 个 CWD 占用：")
    $n = [Math]::Min($items.Count, $MaxItems)
    for ($i = 0; $i -lt $n; $i++) {
        $x = $items[$i]
        $lines.Add("  • $($x.ProcessName)  PID=$($x.Pid)  handle=0x$($x.HandleValue.ToString('X'))")
    }
    if ($items.Count -gt $MaxItems) { $lines.Add("  • ……另有 $($items.Count - $MaxItems) 个") }
    return ($lines -join "`r`n")
}

function Show-Confirm([string]$Message, [string]$Title, [System.Windows.Forms.MessageBoxIcon]$Icon = [System.Windows.Forms.MessageBoxIcon]::Warning) {
    return ([System.Windows.Forms.MessageBox]::Show(
        $Message,
        $Title,
        [System.Windows.Forms.MessageBoxButtons]::YesNo,
        $Icon,
        [System.Windows.Forms.MessageBoxDefaultButton]::Button2
    ) -eq [System.Windows.Forms.DialogResult]::Yes)
}

function Get-ExtendedPath([string]$Path) {
    $p = Get-NormalPath $Path
    if ($p.StartsWith('\\')) { return '\\?\UNC\' + $p.Substring(2) }
    if ($p.StartsWith('\\?\')) { return $p }
    return '\\?\' + $p
}

$form = New-Object System.Windows.Forms.Form
$form.Text = 'GhostShredder v0.3.0-alpha3 - 幽灵粉碎器'
$form.Size = New-Object System.Drawing.Size(1040, 760)
$form.StartPosition = 'CenterScreen'
$form.MinimumSize = New-Object System.Drawing.Size(900, 650)
$form.AllowDrop = $false

$lbl = New-Object System.Windows.Forms.Label
$lbl.Text = '目标列表（支持同时添加文件 / 文件夹；可从资源管理器直接拖拽多个项目到列表）：'
$lbl.Location = New-Object System.Drawing.Point(16, 16)
$lbl.AutoSize = $true
$form.Controls.Add($lbl)

$targetList = New-Object System.Windows.Forms.ListView
$targetList.Location = New-Object System.Drawing.Point(16, 40)
$targetList.Size = New-Object System.Drawing.Size(988, 190)
$targetList.Anchor = 'Top,Left,Right'
$targetList.View = [System.Windows.Forms.View]::Details
$targetList.FullRowSelect = $true
$targetList.GridLines = $true
$targetList.MultiSelect = $true
$targetList.HideSelection = $false
$targetList.AllowDrop = $false
[void]$targetList.Columns.Add('类型', 90)
[void]$targetList.Columns.Add('路径', 690)
[void]$targetList.Columns.Add('状态', 190)
$form.Controls.Add($targetList)

$pathInput = New-Object System.Windows.Forms.TextBox
$pathInput.Location = New-Object System.Drawing.Point(16, 238)
$pathInput.Size = New-Object System.Drawing.Size(540, 28)
$pathInput.Anchor = 'Top,Left,Right'
$form.Controls.Add($pathInput)

$addPath = New-Object System.Windows.Forms.Button
$addPath.Text = '添加路径'
$addPath.Location = New-Object System.Drawing.Point(566, 236)
$addPath.Size = New-Object System.Drawing.Size(95, 32)
$addPath.Anchor = 'Top,Right'
$form.Controls.Add($addPath)

$browseFile = New-Object System.Windows.Forms.Button
$browseFile.Text = '添加文件'
$browseFile.Location = New-Object System.Drawing.Point(671, 236)
$browseFile.Size = New-Object System.Drawing.Size(105, 32)
$browseFile.Anchor = 'Top,Right'
$form.Controls.Add($browseFile)

$browse = New-Object System.Windows.Forms.Button
$browse.Text = '添加文件夹'
$browse.Location = New-Object System.Drawing.Point(786, 236)
$browse.Size = New-Object System.Drawing.Size(110, 32)
$browse.Anchor = 'Top,Right'
$form.Controls.Add($browse)

$removeSelected = New-Object System.Windows.Forms.Button
$removeSelected.Text = '移除选中'
$removeSelected.Location = New-Object System.Drawing.Point(16, 276)
$removeSelected.Size = New-Object System.Drawing.Size(105, 32)
$form.Controls.Add($removeSelected)

$clearTargets = New-Object System.Windows.Forms.Button
$clearTargets.Text = '清空列表'
$clearTargets.Location = New-Object System.Drawing.Point(131, 276)
$clearTargets.Size = New-Object System.Drawing.Size(105, 32)
$form.Controls.Add($clearTargets)

$targetCount = New-Object System.Windows.Forms.Label
$targetCount.Text = '目标：0 项'
$targetCount.Location = New-Object System.Drawing.Point(250, 283)
$targetCount.Size = New-Object System.Drawing.Size(754, 24)
$targetCount.TextAlign = 'MiddleRight'
$targetCount.Anchor = 'Top,Left,Right'
$form.Controls.Add($targetCount)

$analyze = New-Object System.Windows.Forms.Button
$analyze.Text = '分析占用'
$analyze.Location = New-Object System.Drawing.Point(16, 320)
$analyze.Size = New-Object System.Drawing.Size(118, 36)
$form.Controls.Add($analyze)

$unlock = New-Object System.Windows.Forms.Button
$unlock.Text = '解除占用'
$unlock.Location = New-Object System.Drawing.Point(144, 320)
$unlock.Size = New-Object System.Drawing.Size(118, 36)
$form.Controls.Add($unlock)

$delete = New-Object System.Windows.Forms.Button
$delete.Text = '强制删除'
$delete.Location = New-Object System.Drawing.Point(272, 320)
$delete.Size = New-Object System.Drawing.Size(118, 36)
$form.Controls.Add($delete)

$ghost = New-Object System.Windows.Forms.Button
$ghost.Text = '幽灵粉碎'
$ghost.Location = New-Object System.Drawing.Point(400, 320)
$ghost.Size = New-Object System.Drawing.Size(118, 36)
$form.Controls.Add($ghost)

$reboot = New-Object System.Windows.Forms.Button
$reboot.Text = '下次启动删除'
$reboot.Location = New-Object System.Drawing.Point(528, 320)
$reboot.Size = New-Object System.Drawing.Size(132, 36)
$form.Controls.Add($reboot)

$clear = New-Object System.Windows.Forms.Button
$clear.Text = '清日志'
$clear.Location = New-Object System.Drawing.Point(670, 320)
$clear.Size = New-Object System.Drawing.Size(92, 36)
$form.Controls.Add($clear)

$stop = New-Object System.Windows.Forms.Button
$stop.Text = '停止当前任务'
$stop.Location = New-Object System.Drawing.Point(772, 320)
$stop.Size = New-Object System.Drawing.Size(132, 36)
$stop.Enabled = $false
$form.Controls.Add($stop)

$warning = New-Object System.Windows.Forms.Label
$warning.Text = '批量模式：功能按钮默认处理列表中的全部目标，并按顺序逐项执行；不会并行关闭句柄或删除。执行期间列表与其他功能会锁定，只保留“停止当前任务”。'
$warning.Location = New-Object System.Drawing.Point(16, 366)
$warning.Size = New-Object System.Drawing.Size(988, 42)
$warning.Anchor = 'Top,Left,Right'
$form.Controls.Add($warning)

$log = New-Object System.Windows.Forms.TextBox
$log.Location = New-Object System.Drawing.Point(16, 412)
$log.Size = New-Object System.Drawing.Size(988, 286)
$log.Anchor = 'Top,Bottom,Left,Right'
$log.Multiline = $true
$log.ScrollBars = 'Both'
$log.ReadOnly = $true
$log.WordWrap = $false
$log.Font = New-Object System.Drawing.Font('Consolas', 10)
$form.Controls.Add($log)

function Write-Log([string]$Text) {
    $stamp = (Get-Date).ToString('HH:mm:ss')
    $log.AppendText("[$stamp] $Text`r`n")
    $log.SelectionStart = $log.TextLength
    $log.ScrollToCaret()
    [System.Windows.Forms.Application]::DoEvents()
}


# ---- multi-target queue helpers ----
function Update-TargetCount {
    $targetCount.Text = "目标：$($targetList.Items.Count) 项"
}

function Get-TargetKind([string]$Path) {
    if ([System.IO.Directory]::Exists($Path)) { return '文件夹' }
    if ([System.IO.File]::Exists($Path)) { return '文件' }
    return '不存在'
}

function Find-TargetItem([string]$Path) {
    $p = Get-NormalPath $Path
    foreach ($item in $targetList.Items) {
        if ([string]$item.Tag -ieq $p) { return $item }
    }
    return $null
}

function Add-TargetPath([string]$Path, [switch]$Quiet) {
    if ([string]::IsNullOrWhiteSpace($Path)) { return $false }
    $p = Get-NormalPath ($Path.Trim().Trim('"'))
    if (-not $p) { return $false }
    if (Find-TargetItem $p) {
        if (-not $Quiet) { Write-Log "目标已在列表中，已忽略重复项：$p" }
        return $false
    }

    $kind = Get-TargetKind $p
    $item = New-Object System.Windows.Forms.ListViewItem($kind)
    [void]$item.SubItems.Add($p)
    [void]$item.SubItems.Add('待处理')
    $item.Tag = $p
    [void]$targetList.Items.Add($item)
    Update-TargetCount
    return $true
}

function Add-TargetPaths([string[]]$Paths) {
    $added = 0
    foreach ($p in @($Paths)) {
        if (Add-TargetPath $p -Quiet) { $added++ }
    }
    if ($added -gt 0) { Write-Log "已添加 $added 个目标；当前列表共 $($targetList.Items.Count) 项。" }
    elseif (@($Paths).Count -gt 0) { Write-Log '拖入/选择的目标均已存在于列表中，未重复添加。' }
}

function Get-TargetPaths {
    $result = New-Object System.Collections.Generic.List[string]
    foreach ($item in $targetList.Items) { [void]$result.Add([string]$item.Tag) }
    return $result.ToArray()
}

function Set-TargetStatus([string]$Path, [string]$Status) {
    $item = Find-TargetItem $Path
    if (-not $item) { return }
    $item.SubItems[0].Text = Get-TargetKind ([string]$item.Tag)
    $item.SubItems[2].Text = $Status
    try {
        $item.Selected = $true
        $item.EnsureVisible()
    } catch {}
    [System.Windows.Forms.Application]::DoEvents()
}

function Reset-TargetSelection {
    foreach ($item in $targetList.Items) { $item.Selected = $false }
}

function Get-TargetPreview([string[]]$Paths, [int]$MaxItems = 10) {
    $items = @($Paths)
    if ($items.Count -eq 0) { return '(无目标)' }
    $lines = New-Object System.Collections.Generic.List[string]
    $n = [Math]::Min($items.Count, $MaxItems)
    for ($i=0; $i -lt $n; $i++) { $lines.Add("  • $($items[$i])") }
    if ($items.Count -gt $MaxItems) { $lines.Add("  • ……另有 $($items.Count - $MaxItems) 项") }
    return ($lines -join "`r`n")
}

function Get-BatchTargetsOrLog {
    $paths = @(Get-TargetPaths)
    if ($paths.Count -eq 0) {
        Write-Log '目标列表为空。请先添加或拖入文件/文件夹。'
        return @()
    }
    return $paths
}

function Get-SafeMutationBatch([string[]]$Paths) {
    $valid = New-Object System.Collections.Generic.List[string]
    foreach ($raw in @($Paths)) {
        $p = Assert-SafeTarget $raw -ForMutation
        if (-not $p) { Set-TargetStatus $raw '已跳过（安全保护）'; continue }
        if (-not (Test-TargetExists $p)) { Set-TargetStatus $raw '不存在 / 已消失'; continue }
        [void]$valid.Add($p)
    }
    return $valid.ToArray()
}

function Invoke-TargetBatch([string]$OperationName, [string[]]$Paths, [scriptblock]$Action) {
    $items = @($Paths)
    $total = $items.Count
    for ($i=0; $i -lt $total; $i++) {
        Assert-NotCancelled
        $p = $items[$i]
        Reset-TargetSelection
        Set-TargetStatus $p "$OperationName 中…"
        Write-Log "========== [$($i+1)/$total] $OperationName：$p =========="
        try {
            $status = & $Action $p ($i+1) $total
            if ([string]::IsNullOrWhiteSpace([string]$status)) { $status = '完成' }
            Set-TargetStatus $p ([string]$status)
        } catch [System.OperationCanceledException] {
            Set-TargetStatus $p '已停止'
            for ($j=$i+1; $j -lt $total; $j++) { Set-TargetStatus $items[$j] '未执行（批次已停止）' }
            throw
        } catch {
            Set-TargetStatus $p '失败'
            Write-Log "[$($i+1)/$total] $OperationName 失败：$($_.Exception.Message)"
        }
    }
    Reset-TargetSelection
}

function Invoke-DropAdd([System.Windows.Forms.DragEventArgs]$EventArgs) {
    if ($script:TaskRunning) { return }
    $paths = $EventArgs.Data.GetData([System.Windows.Forms.DataFormats]::FileDrop)
    if ($paths -and $paths.Length -gt 0) { Add-TargetPaths ([string[]]$paths) }
}

# ---- UI task / cancellation state ----
$script:TaskRunning = $false
$script:CancelRequested = $false
$script:CancelLogged = $false
$script:ActiveWorkerProcess = $null
$script:ActiveTaskName = ''

function Set-TaskUiState([bool]$Busy, [string]$Name = '') {
    $script:TaskRunning = $Busy
    $script:ActiveTaskName = if ($Busy) { $Name } else { '' }

    foreach ($ctl in @($analyze,$unlock,$delete,$ghost,$reboot,$addPath,$browseFile,$browse,$removeSelected,$clearTargets,$clear,$targetList,$pathInput)) {
        try { $ctl.Enabled = -not $Busy } catch {}
    }
    $stop.Enabled = $Busy
    $stop.Text = if ($Busy -and $script:CancelRequested) { '正在停止…' } else { '停止当前任务' }
    try { $form.UseWaitCursor = $Busy } catch {}
}

function Test-CancelRequested([switch]$WriteLog) {
    if (-not $script:CancelRequested) { return $false }
    if ($WriteLog -and -not $script:CancelLogged) {
        $script:CancelLogged = $true
        Write-Log "收到停止请求：当前任务“$($script:ActiveTaskName)”将在当前不可中断步骤结束后停止。"
    }
    return $true
}

function Stop-ActiveWorkerProcess {
    $proc = $script:ActiveWorkerProcess
    if (-not $proc) { return }
    try {
        $proc.Refresh()
        if (-not $proc.HasExited) {
            Write-Log "正在终止当前隔离扫描子进程：PID=$($proc.Id)"
            try { & "$env:SystemRoot\System32\taskkill.exe" /PID $proc.Id /T /F 2>$null | Out-Null }
            catch { try { $proc.Kill() } catch {} }
        }
    } catch {}
}

function Invoke-UiTask([string]$Name, [scriptblock]$Action) {
    if ($script:TaskRunning) {
        Write-Log "已有任务正在执行：$($script:ActiveTaskName)。本次请求已忽略。"
        return
    }

    $script:CancelRequested = $false
    $script:CancelLogged = $false
    $script:ActiveWorkerProcess = $null
    Set-TaskUiState $true $Name
    try {
        & $Action
    } catch [System.OperationCanceledException] {
        Write-Log "任务已停止：$Name"
    } catch {
        Write-Log "$Name 失败：$($_.Exception.Message)"
    } finally {
        Stop-ActiveWorkerProcess
        $script:ActiveWorkerProcess = $null
        if ($script:CancelRequested -and -not $script:CancelLogged) {
            Write-Log "任务已停止：$Name"
        }
        $script:CancelRequested = $false
        $script:CancelLogged = $false
        Set-TaskUiState $false
    }
}

function Assert-NotCancelled {
    if (Test-CancelRequested -WriteLog) {
        throw [System.OperationCanceledException]::new('User requested cancellation.')
    }
}

function Invoke-CancellableExternalProcess([string]$FilePath, [string]$Arguments, [switch]$Quiet, [System.Text.Encoding]$OutputEncoding = $null) {
    Assert-NotCancelled
    $outFile = Join-Path $env:TEMP ("GhostShredder-exec-" + [Guid]::NewGuid().ToString('N') + '.out')
    $errFile = Join-Path $env:TEMP ("GhostShredder-exec-" + [Guid]::NewGuid().ToString('N') + '.err')
    $proc = $null
    try {
        $proc = Start-Process -FilePath $FilePath -ArgumentList $Arguments -WindowStyle Hidden -PassThru -RedirectStandardOutput $outFile -RedirectStandardError $errFile
        $script:ActiveWorkerProcess = $proc
        while (-not $proc.HasExited) {
            Start-Sleep -Milliseconds 80
            [System.Windows.Forms.Application]::DoEvents()
            if (Test-CancelRequested) {
                Stop-ActiveWorkerProcess
                return [pscustomobject]@{ Cancelled=$true; ExitCode=$null; Output=@() }
            }
            try { $proc.Refresh() } catch {}
        }
        try { $exitCode = $proc.ExitCode } catch { $exitCode = $null }
        $lines = New-Object System.Collections.Generic.List[string]
        if (-not $Quiet) {
            $enc = if ($OutputEncoding) { $OutputEncoding } else { [Text.Encoding]::UTF8 }
            if (Test-Path -LiteralPath $outFile) {
                foreach ($line in [IO.File]::ReadAllLines($outFile, $enc)) { if ($line) { $lines.Add($line) } }
            }
            if (Test-Path -LiteralPath $errFile) {
                foreach ($line in [IO.File]::ReadAllLines($errFile, $enc)) { if ($line) { $lines.Add($line) } }
            }
        }
        return [pscustomobject]@{ Cancelled=$false; ExitCode=$exitCode; Output=$lines.ToArray() }
    } finally {
        if ($script:ActiveWorkerProcess -eq $proc) { $script:ActiveWorkerProcess = $null }
        if ($proc) { try { $proc.Dispose() } catch {} }
        Remove-Item -LiteralPath $outFile,$errFile -Force -ErrorAction SilentlyContinue
    }
}

function Test-TargetExists([string]$Path) {
    try { return [System.IO.File]::Exists($Path) -or [System.IO.Directory]::Exists($Path) } catch { return $false }
}

function Invoke-DirectDelete([string]$Path) {
    Assert-NotCancelled
    $p = Get-NormalPath $Path
    if (-not (Test-TargetExists $p)) { Write-Log '目标已经不存在。'; return $true }

    Write-Log '第一阶段：清理只读/隐藏/系统属性。'
    try {
        $r = Invoke-CancellableExternalProcess (Join-Path $env:SystemRoot 'System32\attrib.exe') ("-R -S -H `"$p`" /S /D") -Quiet
        if ($r.Cancelled) { Assert-NotCancelled }
    } catch [System.OperationCanceledException] { throw } catch {}
    Assert-NotCancelled

    Write-Log '尝试 Win32 FileDispositionInfoEx / POSIX semantics。'
    $err = 0
    try {
        if ([GhostNative]::TryPosixDelete($p, [ref]$err)) {
            Start-Sleep -Milliseconds 100
            if (-not (Test-TargetExists $p)) { Write-Log '原生删除成功。'; return $true }
        } else { Write-Log "原生删除未完成，Win32 error=$err" }
    } catch { Write-Log "原生删除异常：$($_.Exception.Message)" }
    Assert-NotCancelled

    $ext = Get-ExtendedPath $p
    try {
        $cmdExe = Join-Path $env:SystemRoot 'System32\cmd.exe'
        if ([System.IO.Directory]::Exists($p)) {
            Write-Log '尝试 rd /s /q（扩展路径）。'
            $r = Invoke-CancellableExternalProcess $cmdExe ("/u /d /c rd /s /q `"$ext`"") -OutputEncoding ([Text.Encoding]::Unicode)
        } else {
            Write-Log '尝试 del /f /q（扩展路径）。'
            $r = Invoke-CancellableExternalProcess $cmdExe ("/u /d /c del /f /q `"$ext`"") -OutputEncoding ([Text.Encoding]::Unicode)
        }
        if ($r.Cancelled) { Assert-NotCancelled }
        foreach ($line in @($r.Output)) { if ($line) { Write-Log $line } }
    } catch [System.OperationCanceledException] { throw } catch { Write-Log "cmd 删除异常：$($_.Exception.Message)" }
    Assert-NotCancelled

    Start-Sleep -Milliseconds 100
    if (-not (Test-TargetExists $p)) { Write-Log '删除成功。'; return $true }
    Write-Log '目标仍存在。'
    return $false
}

function Get-RestartManagerCandidates([string]$Path) {
    $p = Get-NormalPath $Path
    if (-not $p) { return @{ Supported=$false; Status='INVALID'; Processes=@(); Error=0 } }
    if ([System.IO.Directory]::Exists($p)) {
        # Restart Manager's RmGetList returns ERROR_ACCESS_DENIED for directory resources.
        return @{ Supported=$false; Status='DIRECTORY'; Processes=@(); Error=5 }
    }
    if (-not [System.IO.File]::Exists($p)) {
        return @{ Supported=$false; Status='NOT_FILE'; Processes=@(); Error=0 }
    }
    if ($script:RestartManagerCompileError) {
        return @{ Supported=$false; Status='COMPILE_ERROR'; Processes=@(); Error=0 }
    }
    try {
        $items = @([GhostRestartManager]::FindLockingProcesses($p))
        $err = [GhostRestartManager]::LastError
        if ($err -ne 0) {
            return @{ Supported=$true; Status='ERROR'; Processes=@(); Error=$err }
        }
        return @{ Supported=$true; Status='OK'; Processes=$items; Error=0 }
    } catch {
        return @{ Supported=$true; Status='ERROR'; Processes=@(); Error=-1; Message=$_.Exception.Message }
    }
}

function Invoke-SafeHandleScan([string]$Path, [int]$TimeoutSeconds = 8) {
    $p = Get-NormalPath $Path
    $outFile = Join-Path $env:TEMP ("GhostShredder-deepscan-" + [Guid]::NewGuid().ToString('N') + '.out')
    $errFile = Join-Path $env:TEMP ("GhostShredder-deepscan-" + [Guid]::NewGuid().ToString('N') + '.err')
    $ps = "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe"
    $rm = Get-RestartManagerCandidates $p
    $candidateCsv = ""
    if ($rm.Status -eq 'OK' -and @($rm.Processes).Count -gt 0) {
        $candidateCsv = (@($rm.Processes | ForEach-Object { [string]$_.Pid }) -join ',')
        $desc = (@($rm.Processes | ForEach-Object { "$($_.AppName) (PID $($_.Pid))" }) -join '; ')
        Write-Log "B/RM 快速定位：本次发现 $(@($rm.Processes).Count) 个正在使用该文件的进程：$desc"
    } elseif ($rm.Status -eq 'OK') {
        Write-Log 'B/RM 快速定位：本次暂未发现 Restart Manager 可见的文件使用进程；继续使用全局句柄扫描兜底。'
    } elseif ($rm.Status -eq 'DIRECTORY') {
        Write-Log 'B/RM 快速定位：目标是目录，Restart Manager 不接受目录资源；使用全局句柄扫描。'
    } elseif ($rm.Status -eq 'ERROR') {
        Write-Log "B/RM 快速定位未形成结论（Win32 error=$($rm.Error)）；继续使用全局句柄扫描。"
    }

    $arg = "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`" -DeepScanWorker -TargetPath `"$p`""
    if ($candidateCsv) { $arg += " -CandidatePids `"$candidateCsv`"" }
    $proc = $null
    try {
        $proc = Start-Process -FilePath $ps -ArgumentList $arg -WindowStyle Hidden -PassThru -RedirectStandardOutput $outFile -RedirectStandardError $errFile
        $script:ActiveWorkerProcess = $proc
        $deadline = (Get-Date).AddSeconds($TimeoutSeconds)
        while (-not $proc.HasExited -and (Get-Date) -lt $deadline) {
            Start-Sleep -Milliseconds 100
            [System.Windows.Forms.Application]::DoEvents()
            if (Test-CancelRequested) {
                Stop-ActiveWorkerProcess
                return @{ Cancelled=$true; TimedOut=$false; Locks=@(); Inaccessible=0; PathFailures=0; RestartManager=$rm; Targeted=([bool]$candidateCsv) }
            }
            try { $proc.Refresh() } catch {}
        }
        if (-not $proc.HasExited) {
            Write-Log "普通句柄扫描超过 ${TimeoutSeconds}s，已终止隔离扫描进程；本次该类别扫描未完成，主界面不会被拖死。"
            try { & "$env:SystemRoot\System32\taskkill.exe" /PID $proc.Id /T /F 2>$null | Out-Null } catch { try { $proc.Kill() } catch {} }
            return @{ Cancelled=$false; TimedOut=$true; Locks=@(); Inaccessible=0; PathFailures=0; RestartManager=$rm; Targeted=([bool]$candidateCsv) }
        }

        $locks = @()
        $inaccessible = 0
        $pathFailures = 0
        if (Test-Path -LiteralPath $outFile) {
            foreach ($line in [IO.File]::ReadAllLines($outFile)) {
                if ($line -like 'GS_HANDLEMETA|*') {
                    $m = $line.Split('|')
                    if ($m.Count -ge 3) { try { $inaccessible=[int]$m[1]; $pathFailures=[int]$m[2] } catch {} }
                    continue
                }
                if ($line -notlike 'GS_HANDLE|*') { continue }
                $parts = $line.Split('|', 5)
                if ($parts.Count -ne 5) { continue }
                try {
                    $name = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($parts[3]))
                    $hp = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($parts[4]))
                    $locks += [pscustomobject]@{
                        Pid = [int]$parts[1]
                        HandleValue = [uint64]$parts[2]
                        ProcessName = $name
                        Path = $hp
                    }
                } catch {}
            }
        }
        if (Test-Path -LiteralPath $errFile) {
            $errs = ([IO.File]::ReadAllText($errFile)).Trim()
            if ($errs) { Write-Log "深度扫描诊断：$errs" }
        }
        return @{ Cancelled=$false; TimedOut=$false; Locks=$locks; Inaccessible=$inaccessible; PathFailures=$pathFailures; RestartManager=$rm; Targeted=([bool]$candidateCsv) }
    } catch {
        Write-Log "启动隔离深度扫描失败：$($_.Exception.Message)"
        return @{ Cancelled=$false; TimedOut=$false; Locks=@(); Inaccessible=0; PathFailures=0; RestartManager=$rm; Targeted=([bool]$candidateCsv) }
    } finally {
        if ($script:ActiveWorkerProcess -eq $proc) { $script:ActiveWorkerProcess = $null }
        if ($proc) { try { $proc.Dispose() } catch {} }
        Remove-Item -LiteralPath $outFile,$errFile -Force -ErrorAction SilentlyContinue
    }
}

function Invoke-SafeMapScan([string]$Path, [int]$TimeoutSeconds = 6) {
    $p = Get-NormalPath $Path
    $outFile = Join-Path $env:TEMP ("GhostShredder-mapscan-" + [Guid]::NewGuid().ToString('N') + '.out')
    $errFile = Join-Path $env:TEMP ("GhostShredder-mapscan-" + [Guid]::NewGuid().ToString('N') + '.err')
    $ps = "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe"
    $arg = "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`" -MapScanWorker -TargetPath `"$p`""
    $proc = $null
    try {
        $proc = Start-Process -FilePath $ps -ArgumentList $arg -WindowStyle Hidden -PassThru -RedirectStandardOutput $outFile -RedirectStandardError $errFile
        $script:ActiveWorkerProcess = $proc
        $deadline = (Get-Date).AddSeconds($TimeoutSeconds)
        while (-not $proc.HasExited -and (Get-Date) -lt $deadline) {
            Start-Sleep -Milliseconds 100
            [System.Windows.Forms.Application]::DoEvents()
            if (Test-CancelRequested) {
                Stop-ActiveWorkerProcess
                return @{ Cancelled=$true; TimedOut=$false; Locks=@(); Inaccessible=0 }
            }
            try { $proc.Refresh() } catch {}
        }
        if (-not $proc.HasExited) {
            try { & "$env:SystemRoot\System32\taskkill.exe" /PID $proc.Id /T /F 2>$null | Out-Null } catch { try { $proc.Kill() } catch {} }
            return @{ Cancelled=$false; TimedOut=$true; Locks=@(); Inaccessible=0 }
        }
        $locks = @()
        $inaccessible = 0
        if (Test-Path -LiteralPath $outFile) {
            foreach ($line in [IO.File]::ReadAllLines($outFile)) {
                if ($line -like 'GS_MAPMETA|*') {
                    $m = $line.Split('|')
                    if ($m.Count -ge 2) { try { $inaccessible=[int]$m[1] } catch {} }
                    continue
                }
                if ($line -notlike 'GS_MAP|*') { continue }
                $parts = $line.Split('|', 6)
                if ($parts.Count -ne 6) { continue }
                try {
                    $name = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($parts[4]))
                    $hp = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($parts[5]))
                    $locks += [pscustomobject]@{
                        Pid=[int]$parts[1]; MappingType=$parts[2]; BaseAddress=[uint64]$parts[3]; ProcessName=$name; Path=$hp
                    }
                } catch {}
            }
        }
        if (Test-Path -LiteralPath $errFile) {
            $errs = ([IO.File]::ReadAllText($errFile)).Trim()
            if ($errs) { Write-Log "映射扫描诊断：$errs" }
        }
        return @{ Cancelled=$false; TimedOut=$false; Locks=$locks; Inaccessible=$inaccessible }
    } catch {
        Write-Log "启动隔离映射扫描失败：$($_.Exception.Message)"
        return @{ Cancelled=$false; TimedOut=$false; Locks=@(); Inaccessible=0 }
    } finally {
        if ($script:ActiveWorkerProcess -eq $proc) { $script:ActiveWorkerProcess = $null }
        if ($proc) { try { $proc.Dispose() } catch {} }
        Remove-Item -LiteralPath $outFile,$errFile -Force -ErrorAction SilentlyContinue
    }
}

function Test-IsRemoteTarget([string]$Path) {
    $p = Get-NormalPath $Path
    if (-not $p) { return $false }
    if ($p.StartsWith('\\')) { return $true }
    try {
        $root = [IO.Path]::GetPathRoot($p)
        if ($root) {
            $di = New-Object IO.DriveInfo($root)
            return ($di.DriveType -eq [IO.DriveType]::Network)
        }
    } catch {}
    return $false
}

function Test-PathMatch([string]$Candidate, [string]$Target) {
    if ([string]::IsNullOrWhiteSpace($Candidate)) { return $false }
    $c = (Get-NormalPath $Candidate)
    $t = (Get-NormalPath $Target)
    if (-not $c -or -not $t) { return $false }
    if ($c -ieq $t) { return $true }
    return $c.StartsWith($t.TrimEnd('\\') + '\\', [StringComparison]::OrdinalIgnoreCase)
}

function Get-SmbServerLocks([string]$Path) {
    $p = Get-NormalPath $Path
    if (Test-IsRemoteTarget $p) { return @{ Status='REMOTE_TARGET'; Locks=@() } }
    $cmd = Get-Command Get-SmbOpenFile -ErrorAction SilentlyContinue
    if (-not $cmd) { return @{ Status='UNAVAILABLE'; Locks=@() } }
    try {
        $locks = @(Get-SmbOpenFile -ErrorAction Stop | Where-Object { Test-PathMatch ([string]$_.Path) $p } | ForEach-Object {
            [pscustomobject]@{ FileId=$_.FileId; ClientComputerName=$_.ClientComputerName; ClientUserName=$_.ClientUserName; Path=$_.Path }
        })
        return @{ Status='OK'; Locks=$locks }
    } catch { return @{ Status='ERROR'; Error=$_.Exception.Message; Locks=@() } }
}

function Get-FilterSnapshot([string]$Path) {
    $p = Get-NormalPath $Path
    $volume = $null
    if (Test-IsRemoteTarget $p) { $volume = '\Device\Mup' }
    else {
        try {
            $root = [IO.Path]::GetPathRoot($p)
            if ($root -match '^[A-Za-z]:\\') { $volume = $root.Substring(0,2) }
        } catch {}
    }
    if (-not $volume -or -not (Test-Path "$env:SystemRoot\System32\fltmc.exe")) { return @{ Status='UNAVAILABLE'; Names=@() } }
    try {
        $lines = @(& "$env:SystemRoot\System32\fltmc.exe" instances -v $volume 2>&1 | ForEach-Object { $_.ToString() })
        $names = New-Object System.Collections.Generic.List[string]
        foreach ($line in $lines) {
            if ($line -match '^\\s*([A-Za-z0-9_.-]+)\\s+' -and $line -notmatch '^-{3,}' -and $matches[1] -notin @('Filter','筛选器','Instance','实例')) {
                if (-not $names.Contains($matches[1])) { $names.Add($matches[1]) }
            }
        }
        return @{ Status='OK'; Volume=$volume; Names=@($names) }
    } catch { return @{ Status='ERROR'; Volume=$volume; Error=$_.Exception.Message; Names=@() } }
}

function Get-DeleteAccessProbe([string]$Path) {
    $err = 0
    try {
        $ok = [GhostNative]::ProbeDeleteAccess((Get-NormalPath $Path), [ref]$err)
        return @{ Ok=$ok; Error=$err }
    } catch { return @{ Ok=$false; Error=-1; Message=$_.Exception.Message } }
}

function Get-NonOccupancyDiagnostics([string]$Path) {
    $p = Get-NormalPath $Path
    $result = [ordered]@{ Attributes='unknown'; ReparsePoint=$false; Owner='unknown' }
    try {
        $a = [IO.File]::GetAttributes($p)
        $result.Attributes = $a.ToString()
        $result.ReparsePoint = (($a -band [IO.FileAttributes]::ReparsePoint) -ne 0)
    } catch {}
    try {
        $acl = Get-Acl -LiteralPath $p -ErrorAction Stop
        $result.Owner = [string]$acl.Owner
    } catch {}
    return [pscustomobject]$result
}

function Write-OccupancyMatrix([string]$Path, [object[]]$Cwd, $HandleScan, $MapScan, $Smb, $Filters, $Probe, $Meta) {
    Write-Log '---------- 本次占用观测矩阵 ----------'
    $cwdText = if (@($Cwd).Count) {
        "发现 $(@($Cwd).Count) 个"
    } elseif ([GhostNative]::LastCwdUnreadable -gt 0 -or [GhostNative]::LastCwdUnduplicable -gt 0) {
        "本次暂未发现可确认命中；受限进程=$([GhostNative]::LastCwdUnreadable)，不可复制目标句柄=$([GhostNative]::LastCwdUnduplicable)"
    } else { '本次暂未发现' }
    Write-Log ("A CWD 当前目录          : $cwdText")

    $handleText = if ($HandleScan.TimedOut) {
        '本次扫描未完成（超时）；未形成该类别结论'
    } elseif (@($HandleScan.Locks).Count) {
        "发现 $(@($HandleScan.Locks).Count) 个；不可访问进程=$($HandleScan.Inaccessible)"
    } elseif ($HandleScan.Inaccessible -gt 0 -or $HandleScan.PathFailures -gt 0) {
        "本次暂未发现可确认命中；不可访问进程=$($HandleScan.Inaccessible)，路径解析失败=$($HandleScan.PathFailures)"
    } else { '本次暂未发现' }
    Write-Log ("B 文件/目录 Handle      : $handleText")

    $mapText = if ($MapScan.TimedOut) {
        '本次扫描未完成（超时）；未形成该类别结论'
    } elseif (@($MapScan.Locks).Count) {
        "发现 $(@($MapScan.Locks).Count) 个；不可访问进程=$($MapScan.Inaccessible)"
    } elseif ($MapScan.Inaccessible -gt 0) {
        "本次暂未发现可确认命中；不可访问进程=$($MapScan.Inaccessible)"
    } else { '本次暂未发现' }
    Write-Log ("C Memory Mapping/IMAGE  : $mapText")

    $smbText = switch ($Smb.Status) {
        'OK' { if (@($Smb.Locks).Count) { "发现 $(@($Smb.Locks).Count) 个远程打开项" } else { '本次暂未发现远程打开项' } }
        'REMOTE_TARGET' { '目标位于远程路径；本机不对远端占用形成否定结论' }
        'UNAVAILABLE' { '本次未获得 SMB Server 扫描能力' }
        default { '本次 SMB 扫描未形成可用结论' }
    }
    Write-Log ("D SMB Server Open       : $smbText")

    if ($Filters.Status -eq 'OK') {
        Write-Log ("E Filter / Minifilter    : 诊断信息；本次解析到 $(@($Filters.Names).Count) 个实例（不等于占用） on $($Filters.Volume)")
    } else {
        Write-Log ("E Filter / Minifilter    : 本次未形成可用诊断结果；状态=$($Filters.Status)")
    }

    if ($Probe.Ok) { Write-Log 'F DELETE-access probe     : OPEN_OK（目标本体当前可取得 DELETE access；不代表子项/映射/驱动没有阻塞）' }
    elseif ($Probe.Error -eq 32) { Write-Log 'F DELETE-access probe     : ERROR_SHARING_VIOLATION (32)' }
    elseif ($Probe.Error -eq 5) { Write-Log 'F DELETE-access probe     : ERROR_ACCESS_DENIED (5)' }
    else { Write-Log "F DELETE-access probe     : Win32 error=$($Probe.Error)" }
    Write-Log ("G 非占用诊断             : attrs=$($Meta.Attributes); reparse=$($Meta.ReparsePoint); owner=$($Meta.Owner)")

    if ($HandleScan.TimedOut -or $MapScan.TimedOut) {
        Write-Log '本次分析说明             : 至少一个类别扫描未完成；对未完成类别不作“有/无占用”结论。'
    } elseif (($HandleScan.Inaccessible -gt 0) -or ($MapScan.Inaccessible -gt 0) -or ([GhostNative]::LastCwdUnreadable -gt 0)) {
        Write-Log '本次分析说明             : 已完成的扫描仅代表可读取范围；“暂未发现”不等于全系统不存在。'
    } else {
        Write-Log '本次分析说明             : 用户态主要类别已完成本次扫描；结果仅代表本次观测，Filter 仍只是诊断信息。'
    }
    Write-Log '--------------------------------------'
}

function Invoke-Analyze([string]$Path) {
    Assert-NotCancelled
    $p = Get-NormalPath $Path
    if (-not (Test-TargetExists $p)) { Write-Log '目标不存在。'; return }
    Write-Log "========== 全类别占用分析：$p =========="
    [GhostNative]::EnableDebugPrivilege() | Out-Null

    Write-Log 'A/CWD：扫描 Current Working Directory……'
    $cwd = @([GhostNative]::FindCurrentDirectoryLocks($p))
    foreach ($x in $cwd) { Write-Log ("CWD LOCK  " + $x.ToString()) }
    if ($cwd.Count -eq 0) { Write-Log "CWD：本次暂未发现可确认命中。 unreadableProc=$([GhostNative]::LastCwdUnreadable) unduplicableTarget=$([GhostNative]::LastCwdUnduplicable)；仅代表本次可见范围。" }
    Assert-NotCancelled

    Write-Log 'B/Handle：启动隔离文件/目录句柄扫描（最长 6 秒）……'
    $handles = Invoke-SafeHandleScan $p 6
    if ($handles.Cancelled) { Assert-NotCancelled }
    if ($handles.TimedOut) { Write-Log 'Handle：本次扫描未完成（超时），未形成该类别占用结论。' }
    elseif (@($handles.Locks).Count -eq 0) { Write-Log "Handle：本次暂未发现可确认的目标/子路径文件句柄。 inaccessibleProc=$($handles.Inaccessible) pathResolveFail=$($handles.PathFailures)" }
    else { foreach ($x in @($handles.Locks)) { Write-Log ("HANDLE    $($x.ProcessName) (PID $($x.Pid)) handle=0x$($x.HandleValue.ToString('X'))  $($x.Path)") } }

    Assert-NotCancelled
    Write-Log 'C/Mapping：启动隔离 Memory Mapping / IMAGE 扫描（最长 6 秒）……'
    $maps = Invoke-SafeMapScan $p 6
    if ($maps.Cancelled) { Assert-NotCancelled }
    if ($maps.TimedOut) { Write-Log 'Mapping：本次扫描未完成（超时），未形成该类别占用结论。' }
    elseif (@($maps.Locks).Count -eq 0) { Write-Log "Mapping：本次暂未发现目标/子路径的 MEM_MAPPED 或 MEM_IMAGE。 inaccessibleProc=$($maps.Inaccessible)" }
    else { foreach ($x in @($maps.Locks)) { Write-Log ("MAP       $($x.ProcessName) (PID $($x.Pid)) $($x.MappingType) base=0x$($x.BaseAddress.ToString('X'))  $($x.Path)") } }

    Assert-NotCancelled
    Write-Log 'D/SMB：检查本机 SMB Server 为远程客户端保持的打开项……'
    $smb = Get-SmbServerLocks $p
    if ($smb.Status -eq 'OK' -and @($smb.Locks).Count) { foreach ($x in @($smb.Locks)) { Write-Log "SMB OPEN  FileId=$($x.FileId) client=$($x.ClientComputerName) user=$($x.ClientUserName)  $($x.Path)" } }
    elseif ($smb.Status -eq 'REMOTE_TARGET') { Write-Log 'SMB：目标位于远程/网络卷；本机扫描不对远端占用状态形成结论。' }
    elseif ($smb.Status -eq 'ERROR') { Write-Log "SMB：扫描失败：$($smb.Error)" }

    Assert-NotCancelled
    Write-Log 'E/Filter：读取目标卷上的文件系统 Filter/Minifilter（诊断信息，不等同于已占用）……'
    $filters = Get-FilterSnapshot $p
    if ($filters.Status -eq 'OK') { Write-Log ("FILTERS   " + ($(if (@($filters.Names).Count) { @($filters.Names) -join ', ' } else { '本次未解析到实例（不等于不存在）' }))) }
    elseif ($filters.Status -eq 'ERROR') { Write-Log "Filter：读取失败：$($filters.Error)" }

    $probe = Get-DeleteAccessProbe $p
    $meta = Get-NonOccupancyDiagnostics $p
    Assert-NotCancelled
    Write-OccupancyMatrix $p $cwd $handles $maps $smb $filters $probe $meta
    $script:LastAnalysisSnapshot = [pscustomobject]@{
        Path=$p; Timestamp=(Get-Date); Cwd=$cwd;
        CwdUnreadable=[GhostNative]::LastCwdUnreadable; CwdUnduplicable=[GhostNative]::LastCwdUnduplicable;
        HandleScan=$handles; MapScan=$maps; Smb=$smb; Filters=$filters; Probe=$probe; Meta=$meta
    }
    Write-Log '========== 分析完成 =========='
}

function Invoke-UnlockOnly([string]$Path) {
    Assert-NotCancelled
    $p = Get-NormalPath $Path
    if (-not (Test-TargetExists $p)) { Write-Log '目标不存在。'; return }

    Write-Log '========== 解除占用开始 =========='
    Write-Log '规则：逐层检测；只有发现当前版本能够修改的占用对象时才弹确认。未发现则静默进入下一层。'
    [GhostNative]::EnableDebugPrivilege() | Out-Null
    $closed = 0
    $detectedActionable = 0
    $declined = 0

    # A/CWD
    Write-Log 'A/CWD：快速扫描 Current Working Directory……'
    $cwdLocks = @([GhostNative]::FindCurrentDirectoryLocks($p))
    if ($cwdLocks.Count -gt 0) {
        $detectedActionable += $cwdLocks.Count
        foreach ($x in $cwdLocks) { Write-Log ("命中 CWD：" + $x.ToString()) }
        $cwdMsg = @"
检测到可解除的 CWD 占用。

目标：
$p

$(Format-CwdPreview $cwdLocks)

是否关闭以上 CWD 句柄？

只关闭列出的句柄，不删除目标。关闭后对应进程可能继续存活，但后续相对路径操作可能出现“句柄无效”等异常。
"@
        if (Show-Confirm $cwdMsg 'GhostShredder - 解除 CWD 占用' ([System.Windows.Forms.MessageBoxIcon]::Warning)) {
            foreach ($x in $cwdLocks) {
                if ($x.HandleValue -ne 0 -and [GhostNative]::CloseRemoteHandle($x.Pid, $x.HandleValue)) {
                    $closed++
                    Write-Log "已关闭 CWD 句柄：PID=$($x.Pid) handle=0x$($x.HandleValue.ToString('X'))"
                    Invalidate-AnalysisSnapshot '已关闭 CWD 句柄，旧占用快照不再代表当前状态。'
                } else {
                    Write-Log "关闭 CWD 句柄失败：PID=$($x.Pid) handle=0x$($x.HandleValue.ToString('X'))"
                }
            }
        } else {
            $declined += $cwdLocks.Count
            Write-Log '用户未授权关闭本次发现的 CWD 句柄；继续进行只读检测。'
        }
    } else {
        Write-Log 'A/CWD：本次暂未发现可确认命中；无需确认。'
    }

    Assert-NotCancelled

    # B/ordinary handles
    Write-Log 'B/Handle：启动隔离精确路径句柄扫描（最长 8 秒）……'
    $scan = Invoke-SafeHandleScan $p 8
    if ($scan.Cancelled) { Assert-NotCancelled }
    $locks = @($scan.Locks)
    if ($locks.Count -gt 0) {
        $detectedActionable += $locks.Count
        foreach ($x in $locks) { Write-Log ("发现普通句柄：$($x.ProcessName) (PID $($x.Pid)) handle=0x$($x.HandleValue.ToString('X'))  $($x.Path)") }
        $handleMsg = @"
检测到可解除的普通文件/目录句柄。

目标：
$p

$(Format-HandlePreview $locks)

是否关闭以上普通句柄？

只关闭当前列出的句柄，不删除目标。被关闭句柄的程序可能出现文件访问异常。
"@
        if (Show-Confirm $handleMsg 'GhostShredder - 解除普通句柄占用' ([System.Windows.Forms.MessageBoxIcon]::Warning)) {
            foreach ($x in $locks) {
                if ([GhostNative]::CloseRemoteHandle($x.Pid, $x.HandleValue)) {
                    $closed++
                    Write-Log "已关闭普通句柄：PID=$($x.Pid) handle=0x$($x.HandleValue.ToString('X'))"
                    Invalidate-AnalysisSnapshot '已关闭普通文件/目录句柄，旧占用快照不再代表当前状态。'
                } else {
                    Write-Log "关闭普通句柄失败：PID=$($x.Pid) handle=0x$($x.HandleValue.ToString('X'))"
                }
            }
        } else {
            $declined += $locks.Count
            Write-Log '用户未授权关闭本次发现的普通句柄；继续进行只读检测。'
        }
    } elseif ($scan.TimedOut) {
        Write-Log 'B/Handle：本次扫描未完成（超时），未形成该类别结论；未弹确认。'
    } else {
        Write-Log 'B/Handle：本次暂未发现可确认命中；无需确认。'
    }

    Assert-NotCancelled

    # C/Mapping: diagnostic only
    Write-Log 'C/Mapping：检查 Memory Mapping / IMAGE（只诊断，不远程 Unmap）……'
    $mapScan = Invoke-SafeMapScan $p 6
    if ($mapScan.Cancelled) { Assert-NotCancelled }
    if ($mapScan.TimedOut) {
        Write-Log 'C/Mapping：本次扫描未完成（超时），未形成该类别结论；无可执行修改动作，因此不弹确认。'
    } elseif (@($mapScan.Locks).Count -gt 0) {
        foreach ($x in @($mapScan.Locks)) { Write-Log "检测到映射占用：$($x.ProcessName) (PID $($x.Pid)) $($x.MappingType)  $($x.Path)" }
        Write-Log 'C/Mapping：当前版本仅诊断，不远程 Unmap；因此不弹“解除”确认。'
    } else {
        Write-Log 'C/Mapping：本次暂未发现映射占用。'
    }

    Assert-NotCancelled

    # D/SMB: diagnostic only
    Write-Log 'D/SMB：检查远程打开项……'
    $smb = Get-SmbServerLocks $p
    if ($smb.Status -eq 'OK' -and @($smb.Locks).Count -gt 0) {
        foreach ($x in @($smb.Locks)) { Write-Log "检测到 SMB 远程打开：FileId=$($x.FileId) client=$($x.ClientComputerName) $($x.Path)" }
        Write-Log 'D/SMB：当前版本仅诊断，不自动断开远程会话；因此不弹“解除”确认。'
    } elseif ($smb.Status -eq 'OK') {
        Write-Log 'D/SMB：本次暂未发现远程打开项。'
    } elseif ($smb.Status -eq 'REMOTE_TARGET') {
        Write-Log 'D/SMB：目标位于远程/网络卷，本机不对远端占用形成结论。'
    } else {
        Write-Log 'D/SMB：本次未形成可用结论。'
    }

    if ($closed -gt 0) {
        Write-Log "解除占用完成：共关闭 $closed 个已授权目标句柄。目标仍被保留。"
    } elseif ($detectedActionable -gt 0 -and $declined -gt 0) {
        Write-Log '本次检测到可解除占用，但用户未授权修改；未关闭任何句柄，目标保持原状。'
    } else {
        Write-Log '本次未发现当前版本可自动解除且需授权的 CWD / 普通句柄；未执行任何句柄修改，也无需弹出确认。'
    }
    Write-Log '========== 完成 =========='
}

function Invoke-GhostShred([string]$Path) {
    Assert-NotCancelled
    $p = Get-NormalPath $Path
    if (-not (Test-TargetExists $p)) { Write-Log '目标已经不存在。'; return }

    Write-Log '========== 幽灵粉碎开始 =========='
    Write-Log '策略：删除优先。每次解除已知占用后立即重试删除；只有删除仍失败时才继续下一轮。'

    # Phase 0: the cheapest possible outcome wins immediately.
    Write-Log '第 0 阶段：先直接尝试永久删除。'
    if (Invoke-DirectDelete $p) { Write-Log '========== 完成 =========='; return }

    [GhostNative]::EnableDebugPrivilege() | Out-Null
    $closed = 0
    $authorizedHandleKeys = New-Object 'System.Collections.Generic.HashSet[string]'

    # Initial unlock is not counted against the 3 retry rounds. This is the first response
    # to the initial delete failure. The 3-round chase starts only if deletion still fails.
    Assert-NotCancelled
    Write-Log '初次解除：优先处理当前 CWD 占用；解除后立即重试删除。'
    $cwdLocks = @([GhostNative]::FindCurrentDirectoryLocks($p))
    if ($cwdLocks.Count -gt 0) {
        foreach ($x in $cwdLocks) {
            Write-Log ('命中 CWD：' + $x.ToString())
            if ($x.HandleValue -ne 0) {
                if ([GhostNative]::CloseRemoteHandle($x.Pid, $x.HandleValue)) {
                    $closed++
                    Write-Log "已关闭 CWD 句柄：PID=$($x.Pid) handle=0x$($x.HandleValue.ToString('X'))"
                    Invalidate-AnalysisSnapshot '幽灵粉碎已关闭 CWD 句柄。'
                } else {
                    Write-Log "关闭 CWD 句柄失败：PID=$($x.Pid) handle=0x$($x.HandleValue.ToString('X'))"
                }
            }
        }
    } else {
        Write-Log '初次解除：本次暂未发现 CWD 占用。'
    }

    Assert-NotCancelled
    if (Invoke-DirectDelete $p) {
        Write-Log "粉碎成功：初次解除后即删除成功；共关闭 $closed 个目标句柄。"
        Write-Log '========== 完成 =========='
        return
    }

    Write-Log '初次解除后删除仍失败：进入最多 3 轮“重新检测 → 解除 → 立即删除”的追杀循环。'

    for ($round = 1; $round -le 3; $round++) {
        Assert-NotCancelled
        if (-not (Test-TargetExists $p)) {
            Write-Log "目标已不存在；在追杀循环第 $round 轮开始前确认删除成功。"
            Write-Log '========== 完成 =========='
            return
        }

        Write-Log "---------- 追杀循环 $round/3 ----------"
        $changedThisRound = 0

        # A/CWD: cheap and high-yield. If the process recreated its CWD handle, close it again.
        Write-Log "[$round/3] A/CWD：重新检查是否有进程重新建立当前目录占用……"
        $cwdLocks = @([GhostNative]::FindCurrentDirectoryLocks($p))
        if ($cwdLocks.Count -gt 0) {
            foreach ($x in $cwdLocks) {
                Write-Log ("[$round/3] CWD 命中：" + $x.ToString())
                if ($x.HandleValue -ne 0 -and [GhostNative]::CloseRemoteHandle($x.Pid, $x.HandleValue)) {
                    $closed++; $changedThisRound++
                    Write-Log "[$round/3] 已关闭 CWD 句柄：PID=$($x.Pid) handle=0x$($x.HandleValue.ToString('X'))"
                    Invalidate-AnalysisSnapshot "幽灵粉碎第 $round 轮已关闭 CWD 句柄。"
                } else {
                    Write-Log "[$round/3] 关闭 CWD 句柄失败：PID=$($x.Pid) handle=0x$($x.HandleValue.ToString('X'))"
                }
            }
        } else {
            Write-Log "[$round/3] CWD：本次暂未发现占用。"
        }

        # Do not wait for a 'stable unlock' verdict. Deletion itself is the authoritative test.
        Write-Log "[$round/3] CWD 处理后立即尝试删除……"
        if (Invoke-DirectDelete $p) {
            Write-Log "粉碎成功：第 $round 轮 CWD 处理后删除成功；共关闭 $closed 个目标句柄。"
            Write-Log '========== 完成 =========='
            return
        }

        # B/ordinary handles: only pay the expensive scan cost after immediate deletion still failed.
        Write-Log "[$round/3] B/Handle：删除仍失败，启动隔离精确路径句柄扫描（最长 8 秒）……"
        $scan = Invoke-SafeHandleScan $p 8
        if ($scan.Cancelled) { Assert-NotCancelled }
        $locks = @($scan.Locks)
        if ($locks.Count -gt 0) {
            foreach ($x in $locks) {
                Write-Log "[$round/3] 发现普通句柄：$($x.ProcessName) (PID $($x.Pid)) handle=0x$($x.HandleValue.ToString('X'))  $($x.Path)"
            }

            # Re-created handles previously authorized in this same GhostShred run do not need
            # another dialog. New process/path objects still require progressive authorization.
            $newLocks = @()
            $knownLocks = @()
            foreach ($x in $locks) {
                $key = ("{0}|{1}" -f $x.Pid, ([string]$x.Path).ToLowerInvariant())
                if ($authorizedHandleKeys.Contains($key)) { $knownLocks += $x } else { $newLocks += $x }
            }

            $allowNew = $true
            if ($newLocks.Count -gt 0) {
                $handleMsg = @"
“幽灵粉碎”第 $round/3 轮在删除仍失败后发现了新的普通文件/目录句柄：

目标：
$p

$(Format-HandlePreview $newLocks)

是否授权关闭以上新发现的句柄并继续永久删除？

同一轮“幽灵粉碎”中，已经授权过的同一 PID + 路径若重新建立句柄，后续重试可直接再次关闭，不重复弹窗。
选择“否”将停止进一步普通句柄修改；此前已经关闭的句柄不会自动恢复。
"@
                $allowNew = Show-Confirm $handleMsg 'GhostShredder - 幽灵粉碎升级授权' ([System.Windows.Forms.MessageBoxIcon]::Stop)
                if ($allowNew) {
                    foreach ($x in $newLocks) {
                        $key = ("{0}|{1}" -f $x.Pid, ([string]$x.Path).ToLowerInvariant())
                        [void]$authorizedHandleKeys.Add($key)
                    }
                } else {
                    Write-Log "[$round/3] 用户未授权关闭新发现的普通句柄；停止普通句柄追杀。"
                }
            }

            $toClose = @($knownLocks)
            if ($allowNew) { $toClose += @($newLocks) }

            foreach ($x in $toClose) {
                if ([GhostNative]::CloseRemoteHandle($x.Pid, $x.HandleValue)) {
                    $closed++; $changedThisRound++
                    Write-Log "[$round/3] 已关闭普通句柄：PID=$($x.Pid) handle=0x$($x.HandleValue.ToString('X'))"
                    Invalidate-AnalysisSnapshot "幽灵粉碎第 $round 轮已关闭普通句柄。"
                } else {
                    Write-Log "[$round/3] 关闭普通句柄失败：PID=$($x.Pid) handle=0x$($x.HandleValue.ToString('X'))"
                }
            }

            if ($toClose.Count -gt 0) {
                Write-Log "[$round/3] 普通句柄处理后立即尝试删除……"
                if (Invoke-DirectDelete $p) {
                    Write-Log "粉碎成功：第 $round 轮普通句柄处理后删除成功；共关闭 $closed 个目标句柄。"
                    Write-Log '========== 完成 =========='
                    return
                }
            }

            if (-not $allowNew -and $knownLocks.Count -eq 0) {
                Write-Log '没有获得继续修改普通句柄的授权；结束幽灵粉碎。'
                Write-Log '========== 完成 =========='
                return
            }
        } elseif ($scan.TimedOut) {
            Write-Log "[$round/3] B/Handle：本次扫描未完成（超时），未形成该类别结论。"
        } else {
            Write-Log "[$round/3] B/Handle：本次暂未发现可确认命中。"
        }

        # Even if no user-space object was found, try deletion once more at the end of the round:
        # races can disappear between scans and this is cheaper than starting the next diagnostic class.
        Write-Log "[$round/3] 本轮结束前再次尝试删除……"
        if (Invoke-DirectDelete $p) {
            Write-Log "粉碎成功：第 $round 轮结束检查删除成功；共关闭 $closed 个目标句柄。"
            Write-Log '========== 完成 =========='
            return
        }

        if ($changedThisRound -eq 0) {
            Write-Log "[$round/3] 本轮没有成功关闭新的 CWD / 普通句柄；仍保留剩余轮次，以处理瞬时重建或稍后出现的占用。"
        }
    }

    # Only after the delete/unlock chase is exhausted do the diagnostic-only categories matter.
    Write-Log '3 轮追杀结束后目标仍存在：进入 Mapping / SMB / Filter 等剩余类别诊断。'
    $maps = Invoke-SafeMapScan $p 6
    if ($maps.Cancelled) { Assert-NotCancelled }
    if (-not $maps.TimedOut -and @($maps.Locks).Count -gt 0) {
        foreach ($x in @($maps.Locks)) { Write-Log "MAP BLOCK? $($x.ProcessName) (PID $($x.Pid)) $($x.MappingType)  $($x.Path)" }
        Write-Log '发现 Memory Mapping/IMAGE：当前版本仅诊断，不远程 Unmap。'
    } elseif ($maps.TimedOut) {
        Write-Log 'Mapping：本次扫描未完成（超时），未形成映射占用结论。'
    } else {
        Write-Log 'Mapping：本次暂未发现映射占用。'
    }

    $smb = Get-SmbServerLocks $p
    if ($smb.Status -eq 'OK' -and @($smb.Locks).Count -gt 0) {
        foreach ($x in @($smb.Locks)) { Write-Log "SMB BLOCK? client=$($x.ClientComputerName) FileId=$($x.FileId) $($x.Path)" }
    } elseif ($smb.Status -eq 'REMOTE_TARGET') {
        Write-Log '目标为远程/网络路径：远端占用无法由本机否定。'
    } else {
        Write-Log 'SMB：本次暂未发现远程打开项。'
    }

    $filters = Get-FilterSnapshot $p
    if ($filters.Status -eq 'OK') { Write-Log ("目标卷 Filter（仅诊断）：" + (@($filters.Names) -join ', ')) }
    $probe = Get-DeleteAccessProbe $p
    if (-not $probe.Ok) { Write-Log "DELETE-access probe: Win32 error=$($probe.Error)" }
    Write-Log '仍然无法删除。此时不能把原因简化为 CWD；可能是映射、SMB、Filter/驱动、受保护对象、ACL/文件系统状态，或占用在重试窗口之外再次建立。'
    Write-Log '========== 完成 =========='
}

$addPath.Add_Click({
    if ($script:TaskRunning) { return }
    $raw = $pathInput.Text
    if ([string]::IsNullOrWhiteSpace($raw)) { return }
    Add-TargetPaths @($raw)
    $pathInput.Clear()
})

$pathInput.Add_KeyDown({
    if ($_.KeyCode -eq [System.Windows.Forms.Keys]::Enter -and -not $script:TaskRunning) {
        $_.SuppressKeyPress = $true
        $raw = $pathInput.Text
        if (-not [string]::IsNullOrWhiteSpace($raw)) {
            Add-TargetPaths @($raw)
            $pathInput.Clear()
        }
    }
})

$browseFile.Add_Click({
    $dlg = New-Object System.Windows.Forms.OpenFileDialog
    $dlg.Title = '选择要添加到 GhostShredder 的文件（可多选）'
    $dlg.CheckFileExists = $true
    $dlg.Multiselect = $true
    if ($dlg.ShowDialog() -eq 'OK') { Add-TargetPaths ([string[]]$dlg.FileNames) }
})

$browse.Add_Click({
    $dlg = New-Object System.Windows.Forms.FolderBrowserDialog
    $dlg.Description = '选择要添加到 GhostShredder 的文件夹；多个文件夹可重复添加，或直接从资源管理器批量拖入。'
    if ($dlg.ShowDialog() -eq 'OK') { Add-TargetPaths @($dlg.SelectedPath) }
})

$removeSelected.Add_Click({
    if ($script:TaskRunning) { return }
    $selected = @($targetList.SelectedItems)
    if ($selected.Count -eq 0) { return }
    foreach ($item in $selected) { $targetList.Items.Remove($item) }
    Update-TargetCount
    Write-Log "已从列表移除 $($selected.Count) 个目标（未删除磁盘内容）。"
})

$clearTargets.Add_Click({
    if ($script:TaskRunning) { return }
    if ($targetList.Items.Count -eq 0) { return }
    $count = $targetList.Items.Count
    $targetList.Items.Clear()
    Update-TargetCount
    Write-Log "已清空目标列表，共移除 $count 项（未删除磁盘内容）。"
})

$analyze.Add_Click({
    $targets = @(Get-BatchTargetsOrLog)
    if ($targets.Count -eq 0) { return }
    Invoke-UiTask "批量分析占用（$($targets.Count) 项）" {
        Invoke-TargetBatch '分析占用' $targets {
            param($p,$index,$total)
            if (-not (Test-TargetExists $p)) { Write-Log '目标不存在或已经消失。'; return '不存在 / 已消失' }
            Invoke-Analyze $p | Out-Null
            return '分析完成'
        }
    }
})

$unlock.Add_Click({
    $targets = @(Get-BatchTargetsOrLog)
    if ($targets.Count -eq 0) { return }
    Invoke-UiTask "批量解除占用（$($targets.Count) 项）" {
        $safe = @(Get-SafeMutationBatch $targets)
        if ($safe.Count -eq 0) { Write-Log '没有可执行解除占用的目标。'; return }
        Invoke-TargetBatch '解除占用' $safe {
            param($p,$index,$total)
            if (-not (Test-TargetExists $p)) { return '不存在 / 已消失' }
            Invoke-UnlockOnly $p
            return '处理完成'
        }
    }
})

$delete.Add_Click({
    $targets = @(Get-BatchTargetsOrLog)
    if ($targets.Count -eq 0) { return }
    Invoke-UiTask "批量强制删除（$($targets.Count) 项）" {
        $safe = @(Get-SafeMutationBatch $targets)
        if ($safe.Count -eq 0) { Write-Log '没有可执行强制删除的目标。'; return }
        $msg = @"
确定永久删除以下 $($safe.Count) 个目标？

$(Get-TargetPreview $safe)

“强制删除”不会主动关闭其他进程句柄；若目标仍被占用，对应项目可能删除失败，其余目标仍会继续处理。

批量任务按列表顺序逐项执行，不并行删除。
此操作不经过回收站，无法撤销。
"@
        if (-not (Show-Confirm $msg 'GhostShredder - 批量强制删除' ([System.Windows.Forms.MessageBoxIcon]::Warning))) {
            Write-Log '已取消“批量强制删除”。'
            return
        }
        Invoke-TargetBatch '强制删除' $safe {
            param($p,$index,$total)
            if (-not (Test-TargetExists $p)) { return '不存在 / 已消失' }
            if (Invoke-DirectDelete $p) { return '已删除' }
            return '删除失败'
        }
    }
})

$ghost.Add_Click({
    $targets = @(Get-BatchTargetsOrLog)
    if ($targets.Count -eq 0) { return }
    Invoke-UiTask "批量幽灵粉碎（$($targets.Count) 项）" {
        $safe = @(Get-SafeMutationBatch $targets)
        if ($safe.Count -eq 0) { Write-Log '没有可执行幽灵粉碎的目标。'; return }

        if ($safe.Count -eq 1) {
            $p0 = $safe[0]
            $cwdPreview = @(Get-QuickCwdPreview $p0)
            $previewText = Format-CwdPreview $cwdPreview
            $snapshotText = Get-AnalysisSnapshotText $p0
            if (-not $snapshotText) { $snapshotText = '最近一次完整分析：无可复用快照；除 CWD 外的类别尚未进行本次完整扫描。' }
            $msg = @"
确定执行“幽灵粉碎”？

目标：
$p0

$previewText

$snapshotText

执行流程：先尝试永久删除；失败后解除当前可处理占用并立即重删；若仍失败，最多再追杀 3 轮。新的普通文件/目录句柄仍会按渐进授权规则单独确认。

不会主动结束整个进程，但被关闭句柄的程序可能出现相对路径或文件访问异常。
此操作不经过回收站，无法撤销。
"@
        } else {
            $msg = @"
确定对列表中的 $($safe.Count) 个目标执行“幽灵粉碎”？

$(Get-TargetPreview $safe)

本次确认授权 GhostShredder 对以上目标逐项执行删除优先流程，并在需要时关闭命中的 CWD 句柄。若后续扫描发现新的普通文件/目录句柄，仍会列出进程 / PID / 路径并按渐进授权规则请求确认。

批量任务严格按列表顺序执行，不并行关闭句柄或删除；单个目标失败不会自动跳过剩余目标，除非用户停止整个批次。

被关闭句柄的程序可能继续存活，但后续相对路径或文件访问可能异常。
此操作不经过回收站，无法撤销。
"@
        }

        if (-not (Show-Confirm $msg 'GhostShredder - 批量幽灵粉碎（高风险）' ([System.Windows.Forms.MessageBoxIcon]::Stop))) {
            Write-Log '已取消“批量幽灵粉碎”。'
            return
        }

        Invoke-TargetBatch '幽灵粉碎' $safe {
            param($p,$index,$total)
            if (-not (Test-TargetExists $p)) { return '不存在 / 已消失' }
            Invoke-GhostShred $p
            if (Test-TargetExists $p) { return '仍存在' }
            return '已粉碎'
        }
    }
})

$reboot.Add_Click({
    $targets = @(Get-BatchTargetsOrLog)
    if ($targets.Count -eq 0) { return }
    Invoke-UiTask "批量下次启动删除（$($targets.Count) 项）" {
        $safe = @(Get-SafeMutationBatch $targets)
        if ($safe.Count -eq 0) { Write-Log '没有可登记下次启动删除的目标。'; return }
        $msg = @"
确定登记以下 $($safe.Count) 个目标在下次 Windows 启动时删除？

$(Get-TargetPreview $safe)

目标不会现在删除。即使很久以后才重启，登记仍会在那次启动阶段生效。
继续？
"@
        if (-not (Show-Confirm $msg 'GhostShredder - 批量下次启动删除' ([System.Windows.Forms.MessageBoxIcon]::Warning))) {
            Write-Log '已取消“批量下次启动删除”。'
            return
        }
        Invoke-TargetBatch '登记启动删除' $safe {
            param($p,$index,$total)
            if (-not (Test-TargetExists $p)) { return '不存在 / 已消失' }
            Assert-NotCancelled
            if ([GhostNative]::ScheduleDeleteOnReboot($p)) {
                Write-Log '已登记：下次 Windows 启动时删除。'
                return '已登记'
            }
            Write-Log "登记失败，Win32 error=$([Runtime.InteropServices.Marshal]::GetLastWin32Error())"
            return '登记失败'
        }
    }
})

$clear.Add_Click({
    if (-not $script:TaskRunning) { $log.Clear() }
})

$stop.Add_Click({
    if (-not $script:TaskRunning) { return }
    if ($script:CancelRequested) { return }
    $script:CancelRequested = $true
    $stop.Text = '正在停止…'
    $stop.Enabled = $false
    Write-Log "已请求停止当前任务：$($script:ActiveTaskName)。"
    Stop-ActiveWorkerProcess
})

$form.Add_FormClosing({
    if ($script:TaskRunning) {
        $_.Cancel = $true
        if (-not $script:CancelRequested) {
            $script:CancelRequested = $true
            $stop.Text = '正在停止…'
            $stop.Enabled = $false
            Write-Log "窗口关闭请求已转换为停止当前任务：$($script:ActiveTaskName)。任务结束后可再次关闭窗口。"
            Stop-ActiveWorkerProcess
        }
    }
})

$form.Add_FormClosed({
    foreach ($dropTarget in @($script:NativeDropTargets)) {
        try { $dropTarget.Dispose() } catch {}
    }
    $script:NativeDropTargets = @()
})

# GhostShredder runs elevated.  Do NOT register WinForms/OLE AllowDrop on the
# elevated form: Explorer normally runs at medium integrity and its OLE drop is
# blocked by UIPI before our managed DragDrop handler can run.  Instead use only
# the classic WM_DROPFILES path below, with WM_COPYGLOBALDATA explicitly allowed.
# This avoids the elevated OLE target competing with the legacy shell drop path.
$script:NativeDropTargets = @()
if (-not $script:DropHelperCompileError) {
    try {
        # Force handle creation before attaching NativeWindow hooks.  Register both
        # the ListView and the parent Form because the child under the mouse receives
        # WM_DROPFILES.
        [void]$form.Handle
        [void]$targetList.Handle
        $formDrop = New-Object GhostElevatedDropTarget($form.Handle)
        $listDrop = New-Object GhostElevatedDropTarget($targetList.Handle)
        $nativeDropHandler = {
            param($sender, $e)
            if (-not $script:TaskRunning -and $e -and $e.Paths) { Add-TargetPaths ([string[]]$e.Paths) }
        }
        $formDrop.add_FilesDropped($nativeDropHandler)
        $listDrop.add_FilesDropped($nativeDropHandler)
        $script:NativeDropTargets = @($formDrop, $listDrop)
        $script:NativeDropStatus = "form:drop=$($formDrop.DropMessageAllowed),copyglobal=$($formDrop.CopyGlobalAllowed); list:drop=$($listDrop.DropMessageAllowed),copyglobal=$($listDrop.CopyGlobalAllowed)"
    } catch {
        $script:DropHelperCompileError = $_.Exception.Message
    }
}

if ($TargetPath) { Add-TargetPaths @($TargetPath) }

Write-Log 'GhostShredder v0.3.0-alpha3 已启动（管理员权限）。'
Write-Log '占用模型：CWD / FileHandle / MemoryMapping / SMB / Filter 分类别报告；未发现某一类不等于没有其他占用。解除占用采用逐层检测、逐层授权；幽灵粉碎采用删除优先的追杀循环。'
Write-Log '批量目标：支持多文件/多文件夹列表、手动路径添加与资源管理器拖拽；管理员窗口额外启用 WM_DROPFILES/UIPI 消息白名单通道；所有功能默认按列表顺序逐项处理，不并行执行。'
if ($script:NativeDropStatus) { Write-Log ("拖拽通道：" + $script:NativeDropStatus) } elseif ($script:DropHelperCompileError) { Write-Log ("拖拽辅助初始化失败：" + $script:DropHelperCompileError) }
if ($script:DropHelperCompileError) { Write-Log "拖拽兼容层未启用：$($script:DropHelperCompileError)；仍可使用添加文件/文件夹按钮。" }
Write-Log '任务控制：单批次运行；执行期间目标列表与其他功能按钮自动锁定。“停止当前任务”会终止活动的隔离扫描/外部子进程，并在当前不可中断调用返回后退出整个批次。'
if ([IntPtr]::Size -ne 8) { Write-Log '警告：当前是 32 位 PowerShell。建议使用 64 位 Windows PowerShell。' }

[void]$form.ShowDialog()
