<#
.SYNOPSIS
  Removes the Cherubyte agent service.
.DESCRIPTION
  Leaves the state directory alone by default: it holds the key this agent
  enrolled with, and deleting it means needing a fresh token to come back.
  Pass -Purge to remove it too.
#>
[CmdletBinding()]
param([switch] $Purge)

$ErrorActionPreference = 'Stop'
$ServiceName = 'CherubyteAgent'

if (Get-Service -Name $ServiceName -ErrorAction SilentlyContinue) {
    Stop-Service -Name $ServiceName -Force -ErrorAction SilentlyContinue
    sc.exe delete $ServiceName | Out-Null
    Write-Host 'Service removed.'
} else {
    Write-Host 'Service was not installed.'
}

# Older installs put these in the machine environment; clear them so an upgrade
# from such a version cannot leave a stale panel URL behind.
foreach ($v in 'PANEL_URL', 'ENROL_TOKEN', 'NAME', 'STATE_FILE') {
    [Environment]::SetEnvironmentVariable("CHERUBYTE_AGENT_$v", $null, 'Machine')
}
Remove-Item -Recurse -Force "$env:ProgramFiles\Cherubyte Agent" -ErrorAction SilentlyContinue

$StateDir = Join-Path $env:ProgramData 'Cherubyte Agent'
if ($Purge) {
    Remove-Item -Recurse -Force $StateDir -ErrorAction SilentlyContinue
    Write-Host 'Configuration and state removed — a new enrolment token will be needed.'
} elseif (Test-Path $StateDir) {
    Write-Host "State kept at $StateDir (pass -Purge to remove it)."
}
