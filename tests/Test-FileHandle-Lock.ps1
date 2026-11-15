# Creates a normal file-handle sharing lock without changing CWD.
$dir = Join-Path $env:TEMP 'GhostShredder-HandleTest'
$file = Join-Path $dir 'locked.txt'
New-Item -ItemType Directory -Force -Path $dir | Out-Null
[IO.File]::WriteAllText($file, 'GhostShredder normal handle lock test')

$fs = New-Object IO.FileStream(
    $file,
    [IO.FileMode]::Open,
    [IO.FileAccess]::ReadWrite,
    [IO.FileShare]::Read
)
Write-Host "Normal FILE handle lock active: $file"
Write-Host "PID=$PID  CWD=$((Get-Location).Path)"
Write-Host 'GhostShredder should classify this under B/File Handle, not CWD.'
Write-Host 'Press Enter to release the handle.'
[void][Console]::ReadLine()
$fs.Dispose()
Write-Host 'Released.'
