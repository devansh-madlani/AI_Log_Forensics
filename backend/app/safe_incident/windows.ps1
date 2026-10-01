# Safe test incident - Windows.
#
# Generates genuine Security-log events, then removes everything it made:
#   4720  User Account Created
#   4732  Member Added to Security Group (Administrators)
#   4625  Failed Logon x5 (wrong password, against this machine only)
#   4733 / 4726  cleanup: removed from group, account deleted
#
# The account gets a random password that is never printed or stored, and
# exists for a few seconds. Nothing is downloaded or executed, and no audit
# or security policy is changed. Requires an elevated (Administrator) process.
# Each "STEP:" line is shown to the investigator in the dashboard.

$ErrorActionPreference = 'Stop'
$user = 'forensics_demo'

if (Get-LocalUser -Name $user -ErrorAction SilentlyContinue) {
    Write-Output "ERROR: a local user named '$user' already exists; refusing to touch it."
    exit 2
}

$pw = ConvertTo-SecureString ("Fd!" + [guid]::NewGuid().ToString('N')) -AsPlainText -Force
$adminGroup = (Get-LocalGroup -SID 'S-1-5-32-544').Name

try {
    New-LocalUser -Name $user -Password $pw -Description 'AI_Log_Forensics safe test incident - auto-deleted' | Out-Null
    Write-Output "STEP: Created temporary local user '$user' (event 4720)"

    Add-LocalGroupMember -Group $adminGroup -Member $user
    Write-Output "STEP: Added '$user' to $adminGroup (event 4732)"

    1..5 | ForEach-Object {
        cmd /c "net use \\127.0.0.1\IPC$ WrongPassword$_ /user:$env:COMPUTERNAME\$user >nul 2>&1"
        Start-Sleep -Milliseconds 300
    }
    Write-Output "STEP: 5 failed logons for '$user' with wrong passwords (event 4625)"
}
finally {
    Remove-LocalGroupMember -Group $adminGroup -Member $user -ErrorAction SilentlyContinue
    Remove-LocalUser -Name $user -ErrorAction SilentlyContinue
    if (Get-LocalUser -Name $user -ErrorAction SilentlyContinue) {
        Write-Output "WARNING: could not delete '$user'; remove it with: net user $user /delete"
    } else {
        Write-Output "STEP: Cleanup - removed '$user' from $adminGroup and deleted it (events 4733, 4726)"
    }
}
