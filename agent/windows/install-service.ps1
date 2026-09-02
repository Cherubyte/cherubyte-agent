<#
.SYNOPSIS
  Installs the Cherubyte agent as a Windows service.

.DESCRIPTION
  The agent is one executable and a service registration. It needs no Python,
  no Docker and no interactive login.

  Enrolment happens here, in this window, and that is deliberate. The agent
  can enrol itself by printing a link to approve - but a Windows service has
  nowhere to print to, so on this platform that link went to a log nobody was
  reading and the agent sat there waiting forever with no way to admit it.
  Doing it during install means there is a console to show the link in and a
  browser to open it with.

  Run from an elevated PowerShell.

.EXAMPLE
  .\install-service.ps1 -PanelUrl https://app.cherubyte.app

  Asks the panel for a code, opens your browser, and waits while you approve.

.EXAMPLE
  .\install-service.ps1 -PanelUrl https://app.cherubyte.app -EnrolToken abc123

  Unattended, for imaging a machine or a config management run. No browser and
  no waiting.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string] $PanelUrl,
    # Optional now. Without one, this asks you to approve the machine instead.
    [string] $EnrolToken,
    [string] $Name = $env:COMPUTERNAME,
    [string] $InstallDir = "$env:ProgramFiles\Cherubyte Agent",
    [string] $ExePath,
    # Skips opening a browser, for a machine you are on over Remote Desktop
    # or a session where launching one would go nowhere.
    [switch] $NoBrowser
)

$ErrorActionPreference = 'Stop'
$ServiceName = 'CherubyteAgent'
$PanelUrl = $PanelUrl.TrimEnd('/')

if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()
        ).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'Run this from an elevated PowerShell - registering a service needs it.'
}

if (-not $ExePath) { $ExePath = Join-Path $PSScriptRoot 'cherubyte-agent.exe' }
if (-not (Test-Path $ExePath)) {
    throw "cherubyte-agent.exe not found at $ExePath. Download it from the release, or pass -ExePath."
}

# ProgramData holds both the configuration and the key issued at enrolment.
# Outside the install directory on purpose: an upgrade replaces the binary, and
# the key has to survive it.
$DataDir = Join-Path $env:ProgramData 'Cherubyte Agent'
New-Item -ItemType Directory -Force -Path $DataDir | Out-Null
$ConfigFile = Join-Path $DataDir 'agent.env'
$StateFile = Join-Path $DataDir 'agent.json'

function Protect-File([string] $Path) {
    # Administrators and SYSTEM only: these carry a bearer credential for this
    # network's inventory.
    $acl = Get-Acl $Path
    $acl.SetAccessRuleProtection($true, $false)
    foreach ($who in 'BUILTIN\Administrators', 'NT AUTHORITY\SYSTEM') {
        $acl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule(
            $who, 'FullControl', 'Allow')))
    }
    Set-Acl -Path $Path -AclObject $acl
}

# ---------------------------------------------------------------- enrolment

function Invoke-DeviceEnrolment {
    Write-Host ''
    Write-Host 'Asking the panel to admit this machine...'
    $body = @{ name = $Name; version = '' } | ConvertTo-Json -Compress
    try {
        $start = Invoke-RestMethod -Method Post -Uri "$PanelUrl/api/agents/device-code" `
            -ContentType 'application/json' -Body $body -TimeoutSec 30
    } catch {
        throw "Could not reach the panel at $PanelUrl. $($_.Exception.Message)"
    }

    Write-Host ''
    Write-Host '  ------------------------------------------------------------'
    Write-Host '   Approve this machine at:' -ForegroundColor Cyan
    Write-Host ''
    Write-Host "     $($start.verification_url)" -ForegroundColor White
    Write-Host ''
    Write-Host "   Code: $($start.code)"
    Write-Host '  ------------------------------------------------------------'
    Write-Host ''

    if (-not $NoBrowser) {
        try { Start-Process $start.verification_url | Out-Null }
        catch { Write-Host '  (Could not open a browser - use the link above.)' }
    }

    Write-Host 'Waiting for you to approve it. Ctrl+C to give up.' -NoNewline
    $poll = @{ code = $start.code; poll_secret = $start.poll_secret } | ConvertTo-Json -Compress
    $deadline = (Get-Date).AddSeconds([int]$start.expires_in)
    while ((Get-Date) -lt $deadline) {
        Start-Sleep -Seconds ([Math]::Max(2, [int]$start.interval))
        Write-Host '.' -NoNewline
        try {
            $issued = Invoke-RestMethod -Method Post -Uri "$PanelUrl/api/agents/device-token" `
                -ContentType 'application/json' -Body $poll -TimeoutSec 30
        } catch {
            # 403: the code expired or was already used. Anything else is worth
            # retrying - a flaky link should not lose an approval you just gave.
            if ($_.Exception.Response.StatusCode.value__ -eq 403) {
                Write-Host ''
                throw 'The enrolment code expired or was already used. Run this again.'
            }
            continue
        }
        # A 202 carries a "waiting" message rather than a key, and is the
        # normal answer until somebody clicks approve.
        if ($issued.key) {
            Write-Host ''
            Write-Host "Approved. Enrolled as agent $($issued.agent_id)." -ForegroundColor Green
            return $issued
        }
    }
    Write-Host ''
    throw 'Nobody approved this machine in time. Run this again for a new code.'
}

$enrolledAs = $null
if (Test-Path $StateFile) {
    Write-Host 'Already enrolled on this machine - keeping the existing key.'
} elseif ($EnrolToken) {
    Write-Host 'Using the enrolment token supplied.'
} else {
    $enrolledAs = Invoke-DeviceEnrolment
}

# ------------------------------------------------------------------ install

Write-Host "Installing to $InstallDir"
New-Item -ItemType Directory -Force -Path $InstallDir | Out-Null

# The build is a folder: an executable with an _internal directory of
# libraries beside it. Copying only the executable gives a binary that starts,
# cannot load its own Python runtime, and says so in a way nothing catches.
$SourceDir = Split-Path -Parent $ExePath
if (Test-Path (Join-Path $SourceDir '_internal')) {
    Copy-Item -Path (Join-Path $SourceDir '*') -Destination $InstallDir -Recurse -Force
} else {
    # An older single-file build. Still supported, because somebody may be
    # pointing this at a binary they already had.
    Copy-Item -Path $ExePath -Destination (Join-Path $InstallDir 'cherubyte-agent.exe') -Force
}

# Configuration goes in a FILE, not in machine environment variables.
#
# The Service Control Manager caches its environment block, so a machine
# variable written here is invisible to the service registered moments later,
# until the machine reboots. The service would start on the built-in defaults,
# never find a panel, and sit there reporting itself alive - a failure with no
# error anywhere. A file also keeps a token out of the service's command line,
# where any user could read it with `sc qc` or Task Manager.
$lines = @(
    "CHERUBYTE_AGENT_PANEL_URL=$PanelUrl"
    "CHERUBYTE_AGENT_NAME=$Name"
)
if ($EnrolToken) { $lines += "CHERUBYTE_AGENT_ENROL_TOKEN=$EnrolToken" }
$lines | Set-Content -Path $ConfigFile -Encoding UTF8
Protect-File $ConfigFile

if ($enrolledAs) {
    # The service starts already enrolled, so it never has to print a link it
    # has nowhere to print to.
    @{ agent_id = $enrolledAs.agent_id; key = $enrolledAs.key } |
        ConvertTo-Json -Compress | Set-Content -Path $StateFile -Encoding ASCII
    Protect-File $StateFile
}

if (Get-Service -Name $ServiceName -ErrorAction SilentlyContinue) {
    Write-Host 'Service already exists - stopping it to upgrade'
    Stop-Service -Name $ServiceName -Force -ErrorAction SilentlyContinue
    sc.exe delete $ServiceName | Out-Null
    Start-Sleep -Seconds 2
}

# The executable registers itself: it speaks the Service Control Manager
# protocol, and `sc.exe create` over a plain console exe would install fine and
# then fail on start with error 1053.
# LocalSystem, because the ARP sweep needs raw sockets. Everything else the
# agent does is outbound HTTP.
$exe = Join-Path $InstallDir 'cherubyte-agent.exe'
& $exe --startup auto install
if ($LASTEXITCODE -ne 0) { throw "Service registration failed ($LASTEXITCODE)." }
# Restart on failure rather than staying down: a network that is briefly gone
# is the normal case, not an error worth a silent stop. It is also what brings
# the agent back after it replaces itself with a newer build.
sc.exe failure $ServiceName reset= 86400 actions= restart/5000/restart/15000/restart/60000 | Out-Null

Start-Service -Name $ServiceName

# ------------------------------------------------------------------- report
#
# There is no tray icon and no window, so this is the only place that tells you
# whether it worked. Say enough that nobody has to guess.

Start-Sleep -Seconds 3
$svc = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
function Get-AgentHealth {
    # The endpoint answers 503 when the agent is degraded, which is exactly
    # the case worth reporting - and Invoke-RestMethod throws on it. So the
    # body has to be dug out of the error, and the two PowerShell editions
    # put it in different places.
    try {
        return Invoke-RestMethod -Uri 'http://127.0.0.1:1002/health' -TimeoutSec 5
    } catch {
        if ($_.ErrorDetails -and $_.ErrorDetails.Message) {
            try { return $_.ErrorDetails.Message | ConvertFrom-Json } catch { }
        }
        $resp = $_.Exception.Response
        if ($resp -and $resp.GetResponseStream) {
            try {
                $reader = New-Object System.IO.StreamReader($resp.GetResponseStream())
                return $reader.ReadToEnd() | ConvertFrom-Json
            } catch { }
        }
        return $null
    }
}

$health = Get-AgentHealth

Write-Host ''
Write-Host "Cherubyte agent installed as '$Name'." -ForegroundColor Green
Write-Host "  Service:  $ServiceName - $($svc.Status)"
if ($health) {
    Write-Host "  Enrolled: $($health.enrolled)"
    if ($health.last_error) { Write-Host "  Note:     $($health.last_error)" -ForegroundColor Yellow }
} else {
    Write-Host '  Health:   not answering yet (it can take a few seconds)' -ForegroundColor Yellow
}
Write-Host "  Panel:    $PanelUrl"
Write-Host "  Config:   $ConfigFile"
Write-Host "  State:    $DataDir"
Write-Host ''
Write-Host 'To check on it later:'
Write-Host '  Get-Service CherubyteAgent'
Write-Host '  Invoke-RestMethod http://127.0.0.1:1002/health'
Write-Host '  Get-Content "$env:ProgramData\Cherubyte Agent\enrolment.txt"  # if it needs approving again'
Write-Host ''
Write-Host 'It should appear on the panel''s Agents page within a minute.'
