# Start the backend on Windows with the rights live collection needs.
#
#   powershell -ExecutionPolicy Bypass -File .\start-backend.ps1
#
# Reading the Security log and staging the safe test incident both need
# Administrator rights, so this re-launches itself elevated (UAC prompt)
# when it isn't already.

$ErrorActionPreference = 'Stop'

$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
           ).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    Write-Host 'Requesting Administrator rights...'
    Start-Process powershell.exe -Verb RunAs -ArgumentList @(
        '-NoExit', '-ExecutionPolicy', 'Bypass', '-File', "`"$PSCommandPath`""
    )
    exit
}

$backend = Join-Path $PSScriptRoot 'backend'
$python = Join-Path $backend 'venv\Scripts\python.exe'
if (-not (Test-Path $python)) {
    Write-Error "No virtual environment at $python. Set it up first (see README: Backend setup)."
}

Set-Location $backend
Write-Host 'Backend running as Administrator on http://127.0.0.1:8000  (Ctrl+C to stop)'
& $python -m uvicorn app.main:app --host 127.0.0.1 --port 8000
