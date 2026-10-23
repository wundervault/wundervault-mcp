<#
    Give the secret broker its own account on Windows.

    Run from an Administrator prompt:

        powershell -ExecutionPolicy Bypass -File packaging\install-daemon-windows.ps1

    WHAT THIS BUILDS, AND WHY EACH PIECE IS THE SHAPE IT IS

    A local account `wundervault`, a state directory it alone can open, a run directory
    everyone can read, and a scheduled task that starts it at boot as that account. After
    this, the agents you run cannot open the directory holding your credentials -- which is
    the same claim Linux and macOS make, by a different mechanism.

    THE BOUNDARY IS AN NTFS ACL, NOT A FILE MODE. chmod on Windows is a no-op: ask for
    0700 and stat reports 666, every time. Measured on Windows 10 22H2. So nothing here
    sets a mode, and the daemon does not check one.

    A SCHEDULED TASK, NOT A SERVICE, and it is a considered choice rather than a shortcut.
    A real Windows service must answer the Service Control Manager within 30 seconds;
    node.exe does not, so `sc create` on it fails with error 1053. Every route to a real
    service goes through a third-party wrapper executable, and this product's trust story
    is that the installer is one readable file you can diff against the copy on GitHub at
    /verify#installer. Shipping a binary you cannot read to win a nicer service entry is
    the wrong trade. A real service, under a signed binary, is phase 9.

    ADMINISTRATORS AND SYSTEM ARE INSIDE THE WALL. They are outside every boundary on this
    operating system, exactly as root is on Linux, and the daemon's own check allows them
    deliberately. /limitations says so in the same words.
#>

[CmdletBinding()]
param(
    [string] $Account   = 'wundervault',
    [string] $TaskName  = 'wundervault-agent',
    [string] $NodePath  = '',
    [string] $AgentPath = '',
    [switch] $Uninstall
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$Base  = Join-Path $env:ProgramData 'wundervault'
$State = Join-Path $Base 'state'
$Run   = Join-Path $Base 'run'

# Well-known SIDs, because names are localised and these are not. An installer that grants
# "Administrators" by name does nothing at all on a German Windows.
$SID_SYSTEM  = 'S-1-5-18'
$SID_ADMINS  = 'S-1-5-32-544'
$SID_USERS   = 'S-1-5-32-545'

function Say    { param($m) Write-Host "  $m" }
function Step   { param($m) Write-Host "`n== $m" -ForegroundColor Cyan }
function Fail   { param($m) Write-Host "`nFAILED: $m" -ForegroundColor Red; exit 1 }

<#
    Run a console program without letting its chatter kill the script.

    `$ErrorActionPreference = 'Stop'` is right for cmdlets and WRONG for native commands:
    PowerShell turns anything a native program writes to stderr into a terminating error,
    so `schtasks /delete` on a task that does not exist -- an expected, harmless outcome
    that this script relies on for idempotence -- killed the installer four fifths of the
    way through, after it had already created the account and the directories. Observed on
    Windows 10.

    So native programs go through here: stderr is captured rather than thrown, and the EXIT
    CODE is what decides. `-AllowFail` is for the calls whose failure is the normal case.
#>
function Native {
    param([Parameter(Mandatory)][string] $Exe,
          [string[]] $Arguments = @(),
          [switch] $AllowFail,
          [string] $What = '')
    $old = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    try {
        $out = & $Exe @Arguments 2>&1
        $code = $LASTEXITCODE
    } finally { $ErrorActionPreference = $old }
    if (-not $AllowFail -and $code -ne 0) {
        $label = if ($What) { $What } else { "$Exe $($Arguments -join ' ')" }
        Fail "$label failed (exit $code):`n$(($out | Out-String).Trim())"
    }
    return $out
}

# -- 0. refuse without the rights this needs -----------------------------------
$me = [Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
if (-not $me.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Fail @"
This needs Administrator rights: it creates a local account, grants it a logon right, and
writes under $env:ProgramData.

Open an Administrator PowerShell (right-click > Run as administrator) and run:
  powershell -ExecutionPolicy Bypass -File packaging\install-daemon-windows.ps1
"@
}

# -- uninstall -----------------------------------------------------------------
if ($Uninstall) {
    Step "Removing the broker"
    Native schtasks @('/end', '/tn', $TaskName) -AllowFail | Out-Null
    Native schtasks @('/delete', '/tn', $TaskName, '/f') -AllowFail | Out-Null
    Say "task removed"
    Say "The account and $Base are LEFT IN PLACE on purpose: they hold your credentials."
    Say "Remove them deliberately when you have finished with them:"
    Say "  Remove-LocalUser $Account ; Remove-Item -Recurse -Force '$Base'"
    exit 0
}

# -- 1. find node and the agent ------------------------------------------------
Step "Locating node and the broker"
if (-not $NodePath) {
    $c = Get-Command node.exe -ErrorAction SilentlyContinue
    if ($c) { $NodePath = $c.Source }
}
if (-not $NodePath -or -not (Test-Path -LiteralPath $NodePath)) {
    Fail "Could not find node.exe. Pass -NodePath 'C:\path\to\node.exe'."
}
if (-not $AgentPath) {
    # THE INSTALLER SHIPS INSIDE THE PACKAGE, so the broker is next door. This is the only
    # lookup that is right by construction: `npm root -g` has to be run through the right
    # node, survives neither nvm-windows nor a custom prefix without care, and the first
    # version of this line tried to run npm.cmd as a JavaScript file.
    #
    # It also means the installer always installs THE COPY IT CAME WITH, rather than
    # whichever copy npm happens to point at -- which is what you want when you are about
    # to register something to run at boot.
    $AgentPath = Join-Path (Split-Path -Parent $PSScriptRoot) 'dist\agent.js'
}
if (-not (Test-Path -LiteralPath $AgentPath)) {
    Fail @"
Could not find the broker at:
  $AgentPath

Install it first:  npm install -g @wundervault/mcp-server
Or pass its path:  -AgentPath 'C:\...\dist\agent.js'
"@
}
# Node.js with the October 21, 2026 security fix. That release fixed a memory-corruption flaw in
# Node's Brotli decoder and two TLS hostname checks; the broker decompresses replies from services
# an agent chooses, so it refuses to start on an unpatched Node (src/node-floor.ts). Say so here,
# before anything is changed.
$NodeNeed = 'Node.js 22.23.4, 24.22.1 or 26.12.1 or newer (the October 21, 2026 security release)'
$NodeVersion = (& $NodePath -p 'process.version' 2>$null | Select-Object -First 1)
$nodeOk = $false
if ("$NodeVersion".Trim() -match '^v(\d+)\.(\d+)\.(\d+)(-\S*)?$') {
    $maj = [int]$Matches[1]; $min = [int]$Matches[2]; $pat = [int]$Matches[3]; $pre = [bool]$Matches[4]
    $floors = @{ 22 = @(23, 4); 24 = @(22, 1); 26 = @(12, 1) }
    if ($maj -gt 26) { $nodeOk = $true }
    elseif ($floors.ContainsKey($maj)) {
        $f = $floors[$maj]
        # A pre-release OF the floor version (22.23.4-rc.1) comes before it, and may predate the fix.
        $nodeOk = ($min -gt $f[0]) -or ($min -eq $f[0] -and ($pat -gt $f[1] -or ($pat -eq $f[1] -and -not $pre)))
    }
}
if (-not $nodeOk) {
    Fail "$NodePath is Node.js $NodeVersion, which lacks the October 21, 2026 security fix.`nInstall $NodeNeed from nodejs.org, then run this again. Nothing has been changed."
}
Say "node:   $NodePath"
Say "broker: $AgentPath"

# WHO CAN REPLACE THE THING WE ARE ABOUT TO RUN AS THE BROKER'S ACCOUNT?
#
# The task runs $NodePath against $AgentPath as an account that can open every credential
# on this machine. If either file sits somewhere a non-administrator can write -- and
# nvm-windows puts node under %APPDATA%, which is exactly that -- then anyone who can write
# there chooses what the broker executes. The account split still holds; it just stops
# meaning anything, because the code inside it is theirs.
#
# A WARNING RATHER THAN A REFUSAL, deliberately: refusing would lock out every nvm user,
# and the verifier turns this into a check that actually fails, so "verified" still means
# verified. Saying nothing was not an option.
function Writable-ByNonAdmins {
    param([string] $Path)
    $broad = @('S-1-5-32-545', 'S-1-1-0', 'S-1-5-11', 'S-1-5-4')
    $writes = @('Write', 'Modify', 'FullControl', 'WriteData', 'CreateFiles', 'TakeOwnership', 'ChangePermissions')
    foreach ($target in @($Path, (Split-Path -Parent $Path))) {
        try { $acl = Get-Acl -LiteralPath $target } catch { continue }
        foreach ($ace in $acl.Access) {
            if ($ace.AccessControlType -ne 'Allow') { continue }
            $sid = try { $ace.IdentityReference.Translate([Security.Principal.SecurityIdentifier]).Value }
                   catch { '' }
            if ($broad -notcontains $sid) { continue }
            foreach ($w in $writes) { if ("$($ace.FileSystemRights)" -match $w) { return $target } }
        }
    }
    return $null
}
foreach ($risky in @($NodePath, $AgentPath)) {
    $where = Writable-ByNonAdmins -Path $risky
    if ($where) {
        Write-Host ""
        Write-Host "  WARNING: $where can be written by ordinary users." -ForegroundColor Yellow
        Write-Host "  The broker runs $([IO.Path]::GetFileName($risky)) from there, as an account that holds every" -ForegroundColor Yellow
        Write-Host "  credential on this machine. Anyone who can replace that file chooses what the" -ForegroundColor Yellow
        Write-Host "  broker runs, and the separate account then protects their code instead of yours." -ForegroundColor Yellow
        Write-Host "  Install node and the package somewhere only administrators can write." -ForegroundColor Yellow
        Write-Host ""
    }
}

# -- 2. the account ------------------------------------------------------------
Step "The broker's own account"
$existing = Get-LocalUser -Name $Account -ErrorAction SilentlyContinue
# A random password, used to create the account and to register the task, and never
# written anywhere. Task Scheduler stores what it needs in the LSA; nothing else needs to
# know it again, and an installer that saved it would be handing out the account it just
# built a wall around.
$bytes = New-Object byte[] 48
[Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($bytes)
$plain = [Convert]::ToBase64String($bytes) + '!aA1'
$pw = ConvertTo-SecureString $plain -AsPlainText -Force

if ($existing) {
    Say "account '$Account' exists -- resetting its password so the task can be registered"
    Set-LocalUser -Name $Account -Password $pw
} else {
    New-LocalUser -Name $Account -Password $pw `
        -FullName 'Wundervault secret broker' `
        -Description 'Wundervault secret broker. No logon.' `
        -PasswordNeverExpires -UserMayNotChangePassword | Out-Null
    Say "created local account '$Account'"
}
# Deliberately a member of nothing. Windows puts new local users in Users; removing them
# would break the run directory's read grant, which is granted to Users on purpose.
$AccountSid = (Get-LocalUser -Name $Account).SID.Value
Say "sid: $AccountSid"

# -- 3. logon rights -----------------------------------------------------------
Step "Logon rights"
# SeBatchLogonRight is REQUIRED and schtasks does not grant it. Without it the task
# registers, reports success, and silently never runs -- observed, with the warning
# "Batch logon privilege needs to be enabled for the task principal" buried in the output
# of a command that still exits 0.
#
# The three deny rights are the other half: this account exists to run one process, and an
# account that can be logged into is a second way in.
$secDir = Join-Path $env:TEMP ("wv-sec-" + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $secDir -Force | Out-Null
try {
    $cur = Join-Path $secDir 'cur.inf'
    Native secedit @('/export', '/cfg', $cur, '/areas', 'USER_RIGHTS') -What 'reading the current logon rights' | Out-Null
    $lines = Get-Content $cur

    function RightWith {
        param($name, $sid, $lines)
        $line = $lines | Where-Object { $_ -match "^$name\s*=" }
        $vals = if ($line) { ($line -split '=', 2)[1].Trim() } else { '' }
        # TOKEN EQUALITY, NOT SUBSTRING. `-match` on the raw SID finds `...-1001` inside
        # `...-10010`, so an unrelated local account whose SID merely ENDS with ours as a
        # prefix made this conclude the right was already granted. It then omitted our SID
        # from all four rights, and the scheduled task silently never ran -- the exact
        # failure this function exists to prevent, produced by the check for it.
        $have = @($vals -split ',' | ForEach-Object { $_.Trim().TrimStart('*') })
        if ($have -contains $sid) { return $vals }
        if ($vals) { return "$vals,*$sid" } else { return "*$sid" }
    }

    $batch      = RightWith 'SeBatchLogonRight'                 $AccountSid $lines
    $denyInter  = RightWith 'SeDenyInteractiveLogonRight'       $AccountSid $lines
    $denyNet    = RightWith 'SeDenyNetworkLogonRight'           $AccountSid $lines
    $denyRemote = RightWith 'SeDenyRemoteInteractiveLogonRight' $AccountSid $lines

    $inf = Join-Path $secDir 'apply.inf'
    @"
[Unicode]
Unicode=yes
[Version]
signature="`$CHICAGO`$"
Revision=1
[Privilege Rights]
SeBatchLogonRight = $batch
SeDenyInteractiveLogonRight = $denyInter
SeDenyNetworkLogonRight = $denyNet
SeDenyRemoteInteractiveLogonRight = $denyRemote
"@ | Out-File -FilePath $inf -Encoding unicode

    Native secedit @('/configure', '/db', (Join-Path $secDir 'apply.sdb'), '/cfg', $inf,
                     '/areas', 'USER_RIGHTS') -What 'applying the logon rights' | Out-Null
    Say "granted: log on as a batch job"
    Say "denied:  interactive, network and remote-interactive logon"
} finally {
    Remove-Item -Recurse -Force $secDir -ErrorAction SilentlyContinue
}

# -- 4. the directories --------------------------------------------------------
Step "Directories and ACLs"

function Set-ExplicitAcl {
    param([string] $Path, [string[]] $Grants)
    # THE OWNER FIRST, and it is not cosmetic. On Windows an owner always holds
    # READ_CONTROL and WRITE_DAC implicitly, whatever the DACL says -- so a directory owned
    # by the account the agents run as is a directory those agents can unlock at will. The
    # installer runs elevated, so a directory it creates is owned by Administrators by
    # default on most systems and by the creating account on some; setting it explicitly
    # means the daemon's own boundary check has something it can rely on.
    Native icacls @($Path, '/setowner', "*${SID_ADMINS}") -What "setting the owner of $Path" | Out-Null
    # /reset FIRST, AND THAT IS THE WHOLE FIX. `/inheritance:r` removes only the INHERITED
    # entries; explicit ones survive it, and `/grant` adds without removing. So a directory
    # that someone had explicitly granted `Users:(RX)` kept that grant through a reinstall,
    # and the installer then printed "the boundary" over a directory every local account
    # could read. This is an allowlist or it is nothing, and building an allowlist by
    # adding to whatever was already there is not building an allowlist.
    #
    # /reset drops every explicit ACE and restores inheritance; /inheritance:r then strips
    # the inherited ones, leaving an empty DACL; the grants below are then the entire
    # contents. There is a moment in between where only the owner can open the directory,
    # which is this process, elevated.
    Native icacls @($Path, '/reset') -What "clearing the ACL on $Path" | Out-Null
    Native icacls @($Path, '/inheritance:r') -What "removing inherited permissions from $Path" | Out-Null
    foreach ($g in $Grants) {
        Native icacls @($Path, '/grant', $g) -What "granting $g on $Path" | Out-Null
    }
}

New-Item -ItemType Directory -Path $Base  -Force | Out-Null
New-Item -ItemType Directory -Path $State -Force | Out-Null
New-Item -ItemType Directory -Path $Run   -Force | Out-Null

# Traversable, and holds nothing readable.
Set-ExplicitAcl -Path $Base -Grants @(
    "*${SID_SYSTEM}:(OI)(CI)(F)", "*${SID_ADMINS}:(OI)(CI)(F)",
    "*${AccountSid}:(OI)(CI)(F)", "*${SID_USERS}:(RX)"
)
# THE BOUNDARY. Nobody but the account and the operating system.
Set-ExplicitAcl -Path $State -Grants @(
    "*${SID_SYSTEM}:(OI)(CI)(F)", "*${SID_ADMINS}:(OI)(CI)(F)", "*${AccountSid}:(OI)(CI)(F)"
)
# The agents must reach their discovery files, so Users read here -- and ONLY read. A run
# directory an agent could write is a run directory an agent could use to point another
# agent at a port of its choosing.
Set-ExplicitAcl -Path $Run -Grants @(
    "*${SID_SYSTEM}:(OI)(CI)(F)", "*${SID_ADMINS}:(OI)(CI)(F)",
    "*${AccountSid}:(OI)(CI)(F)", "*${SID_USERS}:(OI)(CI)(RX)"
)
Say "$Base   traversable"
Say "$State  the boundary -- $Account, SYSTEM, Administrators"
Say "$Run    readable by all, writable only by $Account"

# -- 5. the store key ----------------------------------------------------------
Step "Store key"
$KeyPath = Join-Path $State 'store.key'

function Assert-NoReparsePointOnPath {
    param([string] $Path)
    # EVERY COMPONENT, not just the leaf. Checking only `state\store.key` leaves `state`
    # itself: a compromised broker account owns that directory, so it can replace it with a
    # junction and this elevated script writes the key wherever the junction points --
    # creating or clobbering a file, and then handing it to the service account with the
    # chown that follows.
    #
    # It remains CHECK-THEN-USE and is documented as such: PowerShell cannot open a path
    # with FILE_FLAG_OPEN_REPARSE_POINT, so there is no atomic version of this available
    # here. What closes the gap rather than narrowing it is that the attacker must already
    # BE the broker account -- nobody else can write in that directory -- and a compromised
    # broker is out of scope for every phase so far. The signed standalone binary of phase
    # 9 is where this becomes closable.
    $parts = @()
    $cur = $Path
    while ($cur -and $cur -ne (Split-Path -Parent $cur)) {
        $parts += $cur
        $cur = Split-Path -Parent $cur
    }
    foreach ($p in $parts) {
        if (Test-Path -LiteralPath $p) {
            $item = Get-Item -LiteralPath $p -Force
            if ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) {
                Fail "$p is a reparse point (a symlink or junction), not a real directory or file.`n`nRefusing to write through it: this script runs as an administrator, and following a link placed by a less privileged account would write wherever that link points. Remove it by hand and look into how it got there."
            }
        }
    }
}

function Assert-NotReparsePoint {
    param([string] $Path)
    # A ROOT-WRITE THROUGH A SYMLINK THE SERVICE ACCOUNT PLANTED.
    #
    # This runs as Administrator and writes into a directory the service account owns.
    # That account could place a reparse point at store.key before a reinstall; this
    # script would follow it as an administrator, create or clobber whatever it pointed
    # at, and the ACL applied afterwards would hand that target to the service account.
    # Found on macOS in review round 22 and closed here at the same time.
    if (Test-Path -LiteralPath $Path) {
        $item = Get-Item -LiteralPath $Path -Force
        if ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) {
            Fail @"
$Path is a reparse point (a symlink or junction), not a file.

Refusing to write through it: this script runs as an administrator, and following a link
placed by a less privileged account would write wherever that link points. Remove it by
hand and look into how it got there.
"@
        }
    }
}

Assert-NoReparsePointOnPath -Path $KeyPath
Assert-NoReparsePointOnPath -Path (Join-Path $State 'broker-key.pem')
Assert-NoReparsePointOnPath -Path $Run

if (Test-Path -LiteralPath $KeyPath) {
    # NEVER ROTATED. The profile store is encrypted under this key; replacing it on a
    # reinstall would make every credential on the machine unreadable, and an installer
    # that destroys data when run twice is an installer nobody can run twice.
    Say "store key already present -- left alone (rotating it would orphan the store)"
} else {
    $kb = New-Object byte[] 32
    [Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($kb)
    # CreateNew, not WriteAllBytes: it fails if anything is already at that path, so the
    # window between the reparse-point check above and this write cannot be used to put a
    # link there. WriteAllBytes would happily follow one.
    $fs = [IO.File]::Open($KeyPath, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write)
    try { $fs.Write($kb, 0, 32) } finally { $fs.Dispose() }
    Say "wrote a random 32-byte store key"
}
Native icacls @($KeyPath, '/setowner', "*${SID_ADMINS}") -What 'setting the store key owner' | Out-Null
Native icacls @($KeyPath, '/inheritance:r') -What 'locking the store key' | Out-Null
Native icacls @($KeyPath, '/grant', "*${SID_SYSTEM}:(F)", "*${SID_ADMINS}:(F)",
                "*${AccountSid}:(F)") -What 'granting on the store key' | Out-Null

# What actually protects it, said honestly rather than claimed.
$bit = (Native 'manage-bde' @('-status', $env:SystemDrive) -AllowFail | Out-String)
if ($bit -match 'Protection\s+On') {
    Say "BitLocker: On for $env:SystemDrive -- a stolen disk does not open this key."
} else {
    Say "BitLocker: NOT on for $env:SystemDrive."
    Say "  The store key is a file on this disk. It is not sealed to hardware and there is"
    Say "  no TPM step here, so anyone who takes the disk and can read it as an"
    Say "  administrator can read the key. BitLocker is what covers that, and it is not"
    Say "  something this installer can claim on your behalf."
}

# -- 6. the task ---------------------------------------------------------------
Step "Scheduled task"
Native schtasks @('/end', '/tn', $TaskName) -AllowFail | Out-Null
Native schtasks @('/delete', '/tn', $TaskName, '/f') -AllowFail | Out-Null

$action  = New-ScheduledTaskAction -Execute $NodePath -Argument "`"$AgentPath`""
$trigger = New-ScheduledTaskTrigger -AtStartup
# NOT a New-ScheduledTaskPrincipal. Register-ScheduledTask's parameter sets put -Password
# with -User, and passing it alongside -Principal fails with "Parameter set cannot be
# resolved using the specified named parameters" -- a message that names nothing useful.
# RestartCount is the thing launchd could not offer. A daemon that refuses to start for a
# reason a restart cannot fix must not respawn for ever filling a log nobody watches; three
# attempts and then stop is a give-up count, which is what was missing on macOS.
$settings = New-ScheduledTaskSettingsSet `
    -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries `
    -StartWhenAvailable -RestartCount 3 -RestartInterval (New-TimeSpan -Minutes 1) `
    -ExecutionTimeLimit ([TimeSpan]::Zero) -MultipleInstances IgnoreNew

Register-ScheduledTask -TaskName $TaskName -Action $action -Trigger $trigger `
    -Settings $settings -User "$env:COMPUTERNAME\$Account" -Password $plain `
    -RunLevel Limited -Force | Out-Null
Say "registered '$TaskName', starts at boot as $Account"

# The password has done its two jobs. Overwrite the variables rather than leaving them for
# whatever reads this session's memory next.
$plain = $null; $pw = $null; $bytes = $null
[GC]::Collect()

Start-ScheduledTask -TaskName $TaskName
Start-Sleep -Seconds 8
$state = (Get-ScheduledTask -TaskName $TaskName).State
$info  = Get-ScheduledTask -TaskName $TaskName | Get-ScheduledTaskInfo
Say "state: $state, last result: $($info.LastTaskResult)"

# A TASK THAT IS NOT RUNNING IS A FAILED INSTALL, and printing its state is not the same
# as checking it. Hand this script a -NodePath that is not node, or an -AgentPath that is
# some other file, and registration succeeds, the process exits immediately, and the
# installer used to sail on to "Done" and exit 0 -- reporting a working broker that had
# already died. Every check below this point in the verifier depends on it being up.
$owned = @(Get-CimInstance Win32_Process -Filter "Name='node.exe'" | Where-Object {
    (Invoke-CimMethod -InputObject $_ -MethodName GetOwner).User -eq $Account
})
if ($state -ne 'Running' -or $owned.Count -eq 0) {
    Fail "The task registered but the broker is not running (state: $state, last result: $($info.LastTaskResult), processes owned by ${Account}: $($owned.Count)).`n`nThe usual causes:`n  - node or the broker path is wrong: $NodePath`n                                     $AgentPath`n  - the broker refused to start. Run it by hand to see why:`n      $NodePath `"$AgentPath`"`n  - the account lacks 'log on as a batch job' (this script grants it; a group policy can take it away)."
}

# -- 7. what to do next --------------------------------------------------------
Step "Done -- and not finished"
Write-Host @"
  Next, in this order:

  1. PROVE IT. Nothing above has been verified from a second account:
       powershell -ExecutionPolicy Bypass -File packaging\verify-windows.ps1

  2. Pair this machine, once, in a terminal no agent is driving:
       wundervault-agent --pair

  3. Hand your agents over, ONE AT A TIME, checking each before the next:
       wundervault-agent --migrate

  What this does NOT give you, stated plainly:
    - Administrators and SYSTEM can open the state directory. So can anyone who takes the
      disk if BitLocker is off. That is the same as root on Linux.
    - There is no sandboxing. The Linux unit restricts the daemon's filesystem, syscalls
      and capabilities; Task Scheduler has no equivalent, so the account split is very
      nearly the whole of the defence here.
    - Any agent you run can read any other agent's token, because they all run as you.
"@ -ForegroundColor Gray
