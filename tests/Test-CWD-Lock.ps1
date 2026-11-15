# Creates a disposable directory and deliberately locks the directory handle without FILE_SHARE_DELETE.
# Close this PowerShell window to release the lock.
$dir = Join-Path $env:TEMP 'GhostShredder-LockTest'
New-Item -ItemType Directory -Force -Path $dir | Out-Null
Add-Type @"
using System;
using System.Runtime.InteropServices;
public static class LockDirNative {
  [DllImport("kernel32.dll", CharSet=CharSet.Unicode, SetLastError=true)]
  public static extern IntPtr CreateFile(string n, uint a, uint s, IntPtr sa, uint c, uint f, IntPtr t);
}
"@
$GENERIC_READ=[uint32]0x80000000
$FILE_SHARE_READ=1
$FILE_SHARE_WRITE=2
$OPEN_EXISTING=3
$FILE_FLAG_BACKUP_SEMANTICS=0x02000000
$h=[LockDirNative]::CreateFile($dir,$GENERIC_READ,$FILE_SHARE_READ -bor $FILE_SHARE_WRITE,[IntPtr]::Zero,$OPEN_EXISTING,$FILE_FLAG_BACKUP_SEMANTICS,[IntPtr]::Zero)
Write-Host "Locked directory: $dir"
Write-Host ("Handle: 0x{0:X}" -f $h.ToInt64())
Write-Host 'Try deleting it with GhostShredder. Press Enter here later to release the test lock.'
[void](Read-Host)
