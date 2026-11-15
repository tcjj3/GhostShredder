# Creates a mapped view while deliberately closing the original file and mapping handles.
# The remaining mapped view is intended to exercise the Memory Mapping scanner.
$dir = Join-Path $env:TEMP 'GhostShredder-MappingTest'
$file = Join-Path $dir 'mapped.bin'
New-Item -ItemType Directory -Force -Path $dir | Out-Null
$bytes = New-Object byte[] (1024*1024)
[IO.File]::WriteAllBytes($file, $bytes)

$src = @"
using System;
using System.Runtime.InteropServices;
public static class MapOnlyTest {
    const uint GENERIC_READ=0x80000000, GENERIC_WRITE=0x40000000;
    const uint FILE_SHARE_READ=1, FILE_SHARE_WRITE=2, FILE_SHARE_DELETE=4;
    const uint OPEN_EXISTING=3, PAGE_READWRITE=0x04, FILE_MAP_WRITE=0x0002;
    static readonly IntPtr INVALID = new IntPtr(-1);
    [DllImport("kernel32.dll", CharSet=CharSet.Unicode, SetLastError=true)]
    static extern IntPtr CreateFile(string n,uint a,uint s,IntPtr sa,uint c,uint f,IntPtr t);
    [DllImport("kernel32.dll", SetLastError=true)] static extern IntPtr CreateFileMapping(IntPtr h,IntPtr a,uint p,uint hi,uint lo,string n);
    [DllImport("kernel32.dll", SetLastError=true)] static extern IntPtr MapViewOfFile(IntPtr h,uint a,uint hi,uint lo,UIntPtr n);
    [DllImport("kernel32.dll", SetLastError=true)] static extern bool UnmapViewOfFile(IntPtr p);
    [DllImport("kernel32.dll", SetLastError=true)] static extern bool CloseHandle(IntPtr h);
    public static IntPtr MapAndCloseHandles(string path) {
        IntPtr f=CreateFile(path,GENERIC_READ|GENERIC_WRITE,FILE_SHARE_READ|FILE_SHARE_WRITE|FILE_SHARE_DELETE,IntPtr.Zero,OPEN_EXISTING,0,IntPtr.Zero);
        if(f==INVALID) throw new Exception("CreateFile error="+Marshal.GetLastWin32Error());
        IntPtr m=CreateFileMapping(f,IntPtr.Zero,PAGE_READWRITE,0,0,null);
        if(m==IntPtr.Zero){ int e=Marshal.GetLastWin32Error(); CloseHandle(f); throw new Exception("CreateFileMapping error="+e); }
        IntPtr v=MapViewOfFile(m,FILE_MAP_WRITE,0,0,UIntPtr.Zero);
        int err=Marshal.GetLastWin32Error();
        CloseHandle(m); CloseHandle(f);
        if(v==IntPtr.Zero) throw new Exception("MapViewOfFile error="+err);
        return v;
    }
    public static void Unmap(IntPtr p){ if(p!=IntPtr.Zero) UnmapViewOfFile(p); }
}
"@
Add-Type -TypeDefinition $src -Language CSharp
$view = [MapOnlyTest]::MapAndCloseHandles($file)
Write-Host "Memory-mapped view active: $file"
Write-Host "PID=$PID  view=0x$($view.ToInt64().ToString('X'))"
Write-Host 'The original FILE and mapping handles have already been closed; the mapped view remains.'
Write-Host 'GhostShredder should classify this under C/Memory Mapping (MAPPED).'
Write-Host 'Press Enter to unmap.'
[void][Console]::ReadLine()
[MapOnlyTest]::Unmap($view)
Write-Host 'Unmapped.'
