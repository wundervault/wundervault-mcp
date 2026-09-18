<#
    Prove the Windows install, from a second account.

        powershell -ExecutionPolicy Bypass -File packaging\verify-windows.ps1

    WHY THIS EXISTS AND WHAT IT REFUSES TO DO

    Reading the ACL back and finding it tidy proves that icacls did what icacls was asked.
    It does not prove that another account is shut out -- and the difference is not
    theoretical: the named-pipe transport this phase rejected passed every test written
    from an administrator account and failed for every unprivileged one. So this script
    CREATES A THROWAWAY NON-ADMINISTRATOR ACCOUNT, makes it try, and reads the answer.

    A CHECK THAT DOES NOT RUN IS NOT A CHECK THAT PASSED. `need` fails the script; `skip`
    means "not applicable here" and is reported as neither. Review round 22 found the macOS
    verifier exiting 0 with required checks SKIPped, and that shape is not repeated.
#>

[CmdletBinding()]
param(
    [string] $Account   = 'wundervault',
    [string] $TaskName  = 'wundervault-agent',
    [string] $ProbeUser = ''
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$Base  = Join-Path $env:ProgramData 'wundervault'
$State = Join-Path $Base 'state'
$Run   = Join-Path $Base 'run'

# A RANDOM NAME EVERY RUN, AND WE NEVER ADOPT ONE WE FIND.
#
# The probe account and task had fixed names. If anything on the machine already used
# `wv-verify-probe` -- a real account, a real scheduled task -- this script reset its
# password, took it over, and DELETED IT in its finally block. A verification script is not
# entitled to destroy things it did not create.
if (-not $ProbeUser) { $ProbeUser = 'wv-vfy-' + ([guid]::NewGuid().ToString('N').Substring(0, 8)) }
$ProbeTask = "$ProbeUser-task"

$script:Failures = 0
$script:Passes   = 0
$script:Skips    = 0
$script:NativeExit = 0

function need {
    param([string] $What, [scriptblock] $Test)
    try {
        $r = & $Test
        if ($r) { Write-Host "  PASS  $What" -ForegroundColor Green; $script:Passes++ }
        else    { Write-Host "  FAIL  $What" -ForegroundColor Red;   $script:Failures++ }
    } catch {
        Write-Host "  FAIL  $What" -ForegroundColor Red
        Write-Host "        $($_.Exception.Message)" -ForegroundColor DarkGray
        $script:Failures++
    }
}
function skip {
    param([string] $What, [string] $Why)
    Write-Host "  n/a   $What  ($Why)" -ForegroundColor DarkGray
    $script:Skips++
}
function section { param($m) Write-Host "`n== $m" -ForegroundColor Cyan }

<#
    Run a console program without letting its chatter kill the script.

    Same trap as the installer: with $ErrorActionPreference = 'Stop', anything a native
    program writes to stderr becomes a terminating error. `schtasks /delete` on a task that
    does not exist is the normal case here -- it is how the cleanup is made idempotent --
    and it killed the verifier in its finally block, after thirteen checks had passed and
    before the one that actually matters had run.
#>
function Native {
    param([Parameter(Mandatory)][string] $Exe, [string[]] $Arguments = @())
    $old = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    try { $out = & $Exe @Arguments 2>&1; $script:NativeExit = $LASTEXITCODE }
    finally { $ErrorActionPreference = $old }
    return $out
}

$me = [Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
if (-not $me.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Host "This needs Administrator rights: it creates and removes a probe account." -ForegroundColor Red
    exit 1
}

# -- the install itself --------------------------------------------------------
section "The install"

need "the account '$Account' exists" { [bool](Get-LocalUser -Name $Account -ErrorAction SilentlyContinue) }

need "'$Account' is not an administrator" {
    $members = @(Get-LocalGroupMember -Group (Get-LocalGroup -SID 'S-1-5-32-544') -ErrorAction SilentlyContinue)
    -not ($members | Where-Object { $_.Name -like "*\$Account" })
}

need "the state directory exists" { Test-Path -LiteralPath $State }
need "the run directory exists"   { Test-Path -LiteralPath $Run }

need "the state ACL has no inherited entries" {
    $acl = Get-Acl -LiteralPath $State
    -not ($acl.Access | Where-Object { $_.IsInherited })
}

need "inheritance is switched OFF, not merely unused" {
    # Not the same question. A directory can have inheritance enabled and show no
    # inherited entries today, because its parent has no inheritable ones yet -- and the
    # day the parent gains one, it flows in.
    (Get-Acl -LiteralPath $State).AreAccessRulesProtected -eq $true
}

need "the state directory is owned by Administrators or the broker's account" {
    # An owner holds WRITE_DAC implicitly, so a directory owned by the agents' account is
    # one those agents can unlock whenever they like.
    $sid = (Get-LocalUser -Name $Account).SID.Value
    $owner = (Get-Acl -LiteralPath $State).GetOwner([Security.Principal.SecurityIdentifier]).Value
    $owner -eq 'S-1-5-32-544' -or $owner -eq $sid -or $owner -eq 'S-1-5-18'
}

need "the state ACL names only the account, SYSTEM and Administrators" {
    $sid = (Get-LocalUser -Name $Account).SID.Value
    $allowed = @('S-1-5-18', 'S-1-5-32-544', $sid,
                 'S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464')
    $acl = Get-Acl -LiteralPath $State
    $bad = $acl.Access | Where-Object { $_.AccessControlType -eq 'Allow' } | ForEach-Object {
        $s = try { $_.IdentityReference.Translate([Security.Principal.SecurityIdentifier]).Value }
             catch { $_.IdentityReference.Value }
        if ($allowed -notcontains $s) { $s }
    }
    -not $bad
}

need "the account has SeBatchLogonRight" {
    $sid = (Get-LocalUser -Name $Account).SID.Value
    $tmp = Join-Path $env:TEMP ("wv-verify-" + [guid]::NewGuid().ToString('N') + ".inf")
    try {
        Native secedit @('/export', '/cfg', $tmp, '/areas', 'USER_RIGHTS') | Out-Null
        $line = Get-Content $tmp | Where-Object { $_ -match '^SeBatchLogonRight' }
        # secedit may render the account by NAME rather than SID on export, so both count.
        # Split on commas first: a substring test finds `...-1001` inside `...-10010`.
        $have = @(($line -split '=', 2)[1].Trim() -split ',' | ForEach-Object { $_.Trim().TrimStart('*') })
        ($have -contains $sid) -or ($have -contains $Account) -or
            ($have -contains "$env:COMPUTERNAME\$Account")
    } finally { Remove-Item -LiteralPath $tmp -ErrorAction SilentlyContinue }
}

need "the task exists and is registered to run as '$Account'" {
    $t = Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
    $t -and ($t.Principal.UserId -like "*$Account")
}

need "the task is running" {
    $t = Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
    $t -and $t.State -eq 'Running'
}

need "the broker is running AS '$Account', not as anyone else" {
    $procs = @(Get-CimInstance Win32_Process -Filter "Name='node.exe'" | Where-Object {
        $_.CommandLine -and $_.CommandLine -match 'agent\.js'
    })
    if ($procs.Count -eq 0) { throw "no broker process found" }
    $owners = $procs | ForEach-Object { (Invoke-CimMethod -InputObject $_ -MethodName GetOwner).User }
    [bool]($owners -contains $Account)
}

need "the broker published its management endpoint" {
    Test-Path -LiteralPath (Join-Path $Run 'mgmt\mgmt.port')
}

need "the broker published a public key for agents to verify against" {
    $p = Join-Path $Run 'broker.pub'
    (Test-Path -LiteralPath $p) -and ((Get-Item -LiteralPath $p).Length -gt 32)
}

need "nothing an ordinary user can rewrite is run as the broker's account" {
    # THE BOUNDARY PROTECTS WHATEVER IS INSIDE IT, including code someone else chose. The
    # task runs node against dist/agent.js as an account holding every credential on this
    # machine; if either file lives where a non-administrator can write, that person picks
    # what the broker executes and the separate account starts protecting their code.
    # nvm-windows installs node under %APPDATA%, which is exactly that.
    $t = Get-ScheduledTask -TaskName $TaskName
    $exe = $t.Actions[0].Execute.Trim('"')
    $arg = $t.Actions[0].Arguments.Trim('"')
    $broad = @('S-1-5-32-545', 'S-1-1-0', 'S-1-5-11', 'S-1-5-4')
    $writes = 'Write|Modify|FullControl|WriteData|CreateFiles|TakeOwnership|ChangePermissions'
    $bad = @()
    foreach ($f in @($exe, $arg)) {
        if (-not $f -or -not (Test-Path -LiteralPath $f)) { continue }
        foreach ($target in @($f, (Split-Path -Parent $f))) {
            try { $acl = Get-Acl -LiteralPath $target } catch { continue }
            foreach ($ace in $acl.Access) {
                if ($ace.AccessControlType -ne 'Allow') { continue }
                $sid = try { $ace.IdentityReference.Translate([Security.Principal.SecurityIdentifier]).Value } catch { '' }
                if ($broad -notcontains $sid) { continue }
                if ("$($ace.FileSystemRights)" -match $writes) { $bad += "$target ($sid)" }
            }
        }
    }
    if ($bad.Count -gt 0) {
        Write-Host "        writable by ordinary users: $($bad | Select-Object -Unique -First 3)" -ForegroundColor DarkGray
    }
    $bad.Count -eq 0
}

need "the store key is 32 bytes and is not a reparse point" {
    $p = Join-Path $State 'store.key'
    $i = Get-Item -LiteralPath $p -Force
    ($i.Length -eq 32) -and -not ($i.Attributes -band [IO.FileAttributes]::ReparsePoint)
}

# -- the boundary, proved from a second account --------------------------------
section "The boundary, from an account that is not yours and not the broker's"

$probeMade = $false
$probePw   = $null
$probeSid  = $null
try {
    $bytes = New-Object byte[] 36
    [Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($bytes)
    $probePw = [Convert]::ToBase64String($bytes) + '!aA1'
    $sec = ConvertTo-SecureString $probePw -AsPlainText -Force

    # If the random name somehow exists, stop rather than adopt it.
    if (Get-LocalUser -Name $ProbeUser -ErrorAction SilentlyContinue) {
        throw "a local account named $ProbeUser already exists; refusing to take it over"
    }
    New-LocalUser -Name $ProbeUser -Password $sec `
        -Description 'temporary: wundervault verification' `
        -PasswordNeverExpires -UserMayNotChangePassword | Out-Null
    $probeMade = $true
    $probeSid = (Get-LocalUser -Name $ProbeUser).SID.Value

    # The probe needs the batch logon right to run at all -- the same right the broker's
    # account needs, and the same trap: schtasks does not grant it and says so quietly.
    $secDir = Join-Path $env:TEMP ("wv-vprobe-" + [guid]::NewGuid().ToString('N'))
    New-Item -ItemType Directory -Path $secDir -Force | Out-Null
    try {
        $cur = Join-Path $secDir 'cur.inf'
        Native secedit @('/export', '/cfg', $cur, '/areas', 'USER_RIGHTS') | Out-Null
        $line = Get-Content $cur | Where-Object { $_ -match '^SeBatchLogonRight' }
        $vals = if ($line) { ($line -split '=', 2)[1].Trim() } else { '' }
        # Token equality, not substring -- the same trap as the installer: `...-1001`
        # matches inside `...-10010`.
        $have = @($vals -split ',' | ForEach-Object { $_.Trim().TrimStart('*') })
        if ($have -notcontains $probeSid) {
            $vals = if ($vals) { "$vals,*$probeSid" } else { "*$probeSid" }
        }
        $inf = Join-Path $secDir 'apply.inf'
        @"
[Unicode]
Unicode=yes
[Version]
signature="`$CHICAGO`$"
Revision=1
[Privilege Rights]
SeBatchLogonRight = $vals
"@ | Out-File -FilePath $inf -Encoding unicode
        Native secedit @('/configure', '/db', (Join-Path $secDir 'apply.sdb'), '/cfg', $inf,
                         '/areas', 'USER_RIGHTS') | Out-Null
    } finally { Remove-Item -Recurse -Force $secDir -ErrorAction SilentlyContinue }

    $work = Join-Path $env:TEMP ("wv-verify-work-" + [guid]::NewGuid().ToString('N'))
    New-Item -ItemType Directory -Path $work -Force | Out-Null
    Native icacls @($work, '/grant', "*${probeSid}:(OI)(CI)F") | Out-Null
    $out = Join-Path $work 'probe.txt'

    $probeScript = Join-Path $work 'probe.ps1'
    @"
`$ErrorActionPreference = 'Continue'
`$lines = @()
`$lines += "user=`$env:USERNAME"
try { Get-ChildItem -LiteralPath '$State' -ErrorAction Stop | Out-Null; `$lines += 'state_list=ALLOWED' }
catch { `$lines += 'state_list=DENIED' }
try { [IO.File]::ReadAllBytes((Join-Path '$State' 'store.key')) | Out-Null; `$lines += 'key_read=ALLOWED' }
catch { `$lines += 'key_read=DENIED' }
try { Get-ChildItem -LiteralPath '$Run' -ErrorAction Stop | Out-Null; `$lines += 'run_list=ALLOWED' }
catch { `$lines += 'run_list=DENIED' }
try {
  `$f = Join-Path '$Run' ('probe-' + [guid]::NewGuid().ToString('N') + '.port')
  [IO.File]::WriteAllText(`$f, 'x'); Remove-Item -LiteralPath `$f -Force
  `$lines += 'run_write=ALLOWED'
} catch { `$lines += 'run_write=DENIED' }
# AND THE HALF THAT MUST WORK. A boundary that also shuts out the agents is an outage,
# not a boundary -- and this is the exact shape of the failure that killed the named-pipe
# transport: reachable from an administrator, EPERM from everybody else.
try {
  `$rec = Get-Content -LiteralPath (Join-Path '$Run' 'mgmt\mgmt.port') -Raw | ConvertFrom-Json
  `$c = New-Object Net.Sockets.TcpClient
  `$c.Connect('127.0.0.1', [int]`$rec.port)
  `$st = `$c.GetStream()
  `$w = New-Object IO.StreamWriter(`$st); `$r = New-Object IO.StreamReader(`$st)
  `$w.NewLine = "``n"; `$w.AutoFlush = `$true
  `$w.WriteLine('{"hello":"wv-broker-hello-v1","nonce":"probe0123456789"}')
  `$banner = `$r.ReadLine()
  `$w.WriteLine('{"action":"ping"}')
  `$pong = `$r.ReadLine()
  `$c.Close()
  if (`$pong -match '"ok":true') { `$lines += 'broker_reach=ALLOWED' } else { `$lines += "broker_reach=ODD:`$pong" }
  if (`$banner -match '"sig"') { `$lines += 'broker_signed=YES' } else { `$lines += 'broker_signed=NO' }
} catch { `$lines += "broker_reach=FAILED:`$(`$_.Exception.Message)" }
`$lines | Set-Content -LiteralPath '$out'
"@ | Out-File -FilePath $probeScript -Encoding UTF8

    Native schtasks @('/delete', '/tn', $ProbeTask, '/f') | Out-Null
    Native schtasks @('/create', '/tn', $ProbeTask,
        '/tr', "powershell -NoProfile -ExecutionPolicy Bypass -File `"$probeScript`"",
        '/sc', 'once', '/st', '00:00', '/ru', $ProbeUser, '/rp', $probePw,
        '/rl', 'limited', '/f') | Out-Null
    if ($script:NativeExit -ne 0) { throw "could not register the probe task" }
    Native schtasks @('/run', '/tn', $ProbeTask) | Out-Null

    $deadline = (Get-Date).AddSeconds(45)
    while (-not (Test-Path -LiteralPath $out) -and (Get-Date) -lt $deadline) { Start-Sleep -Milliseconds 500 }

    if (-not (Test-Path -LiteralPath $out)) {
        need "the probe account ran at all" { throw "the probe task produced no output within 45s" }
    } else {
        $res = @{}
        foreach ($l in Get-Content -LiteralPath $out) {
            $kv = $l -split '=', 2
            if ($kv.Count -eq 2) { $res[$kv[0]] = $kv[1] }
        }
        Write-Host "  (probe ran as '$($res['user'])')" -ForegroundColor DarkGray

        need "a non-administrator CANNOT list the state directory" { $res['state_list'] -eq 'DENIED' }
        need "a non-administrator CANNOT read the store key"       { $res['key_read']   -eq 'DENIED' }
        need "a non-administrator CAN list the run directory"      { $res['run_list']   -eq 'ALLOWED' }
        need "a non-administrator CANNOT write to the run directory" { $res['run_write'] -eq 'DENIED' }
        # The other half. Everything above is the wall; this is the door.
        need "a non-administrator CAN reach the broker and get an answer" { $res['broker_reach'] -eq 'ALLOWED' }
        need "the broker proves itself to a non-administrator too"        { $res['broker_signed'] -eq 'YES' }
    }
} finally {
    Native schtasks @('/end', '/tn', $ProbeTask) | Out-Null
    Native schtasks @('/delete', '/tn', $ProbeTask, '/f') | Out-Null
    # THE LOGON RIGHT GOES BACK TOO. Deleting the account does not remove its SID from
    # SeBatchLogonRight -- local security policy keeps the raw SID, so every run of this
    # script left another dead entry behind in a list nobody reads but everybody inherits.
    if ($probeMade -and $probeSid) {
        $cleanDir = Join-Path $env:TEMP ("wv-vclean-" + [guid]::NewGuid().ToString('N'))
        New-Item -ItemType Directory -Path $cleanDir -Force | Out-Null
        try {
            $c = Join-Path $cleanDir 'cur.inf'
            Native secedit @('/export', '/cfg', $c, '/areas', 'USER_RIGHTS') | Out-Null
            $l = Get-Content $c | Where-Object { $_ -match '^SeBatchLogonRight' }
            if ($l) {
                $kept = @(($l -split '=', 2)[1].Trim() -split ',' |
                          Where-Object { $_.Trim().TrimStart('*') -ne $probeSid })
                $inf = Join-Path $cleanDir 'apply.inf'
                @"
[Unicode]
Unicode=yes
[Version]
signature="`$CHICAGO`$"
Revision=1
[Privilege Rights]
SeBatchLogonRight = $($kept -join ',')
"@ | Out-File -FilePath $inf -Encoding unicode
                Native secedit @('/configure', '/db', (Join-Path $cleanDir 'apply.sdb'),
                                 '/cfg', $inf, '/areas', 'USER_RIGHTS') | Out-Null
            }
        } catch { Write-Host "  (could not remove the probe's logon right: $($_.Exception.Message))" -ForegroundColor DarkGray }
        finally { Remove-Item -Recurse -Force $cleanDir -ErrorAction SilentlyContinue }
    }
    if ($probeMade) { Remove-LocalUser -Name $ProbeUser -ErrorAction SilentlyContinue }
    Get-ChildItem $env:TEMP -Filter 'wv-verify-work-*' -Directory -ErrorAction SilentlyContinue |
        Remove-Item -Recurse -Force -ErrorAction SilentlyContinue
    $probePw = $null
    Write-Host "  (probe account and task removed)" -ForegroundColor DarkGray
}

section "The boundary against YOUR OWN account, which is the case that matters"

# WHY THIS EXISTS, AND WHY THE SECTION ABOVE IS NOT ENOUGH.
#
# Everything above proves the boundary against an account that is not yours. That is the
# easy case. On Windows the common case is quite different: most people are administrators
# of their own machine, so their agents run as an account that IS in the state directory's
# ACL -- and whether it can actually open the directory comes down to whether the process
# is ELEVATED.
#
# A non-elevated process belonging to an administrator carries the Administrators SID as
# DENY-ONLY under UAC token filtering, and a deny-only SID cannot be used to grant access.
# So the boundary holds -- but that is a claim about Windows token semantics, and a claim
# is not a measurement. This measures it, with the account running the verifier.
#
# `runas /trustlevel:0x20000` (SAFER normal-user) is not byte-identical to a UAC-filtered
# token: it removes the Administrators SID rather than marking it deny-only. For an ALLOW
# ace the access check is the same either way, so the result transfers -- and it is the
# closest thing available without a second interactive logon.
$selfOut = Join-Path $env:TEMP ("wv-self-" + [guid]::NewGuid().ToString('N') + ".txt")
$selfScript = Join-Path $env:TEMP ("wv-self-" + [guid]::NewGuid().ToString('N') + ".ps1")
@"
`$lines = @()
`$id = [Security.Principal.WindowsIdentity]::GetCurrent()
`$p = New-Object Security.Principal.WindowsPrincipal(`$id)
`$lines += "user=`$(`$id.Name)"
`$lines += "elevated=`$(`$p.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator))"
try { Get-ChildItem -LiteralPath '$State' -ErrorAction Stop | Out-Null; `$lines += 'state_list=ALLOWED' }
catch { `$lines += 'state_list=DENIED' }
# THE EXCEPTION TYPE, not Test-Path. Test-Path on a file inside a directory you cannot
# traverse returns False, so an UNREACHABLE key reported as 'missing' -- the absent/denied
# conflation this was written to avoid, arriving from the other side. Only the exception
# knows which of the two actually happened.
`$k = Join-Path '$State' 'store.key'
try { [IO.File]::ReadAllBytes(`$k) | Out-Null; `$lines += 'key_read=ALLOWED' }
catch [UnauthorizedAccessException] { `$lines += 'key_read=DENIED' }
catch [IO.DirectoryNotFoundException] { `$lines += 'key_read=DENIED' }
catch [IO.FileNotFoundException] { `$lines += 'key_read=MISSING' }
catch { `$lines += "key_read=OTHER:`$(`$_.Exception.GetType().Name)" }
try { Get-ChildItem -LiteralPath '$Run' -ErrorAction Stop | Out-Null; `$lines += 'run_list=ALLOWED' }
catch { `$lines += 'run_list=DENIED' }
`$lines | Set-Content -LiteralPath '$selfOut'
"@ | Out-File -FilePath $selfScript -Encoding UTF8

try {
    Native 'runas' @('/trustlevel:0x20000',
        "powershell -NoProfile -ExecutionPolicy Bypass -File `"$selfScript`"") | Out-Null
    $deadline = (Get-Date).AddSeconds(40)
    while (-not (Test-Path -LiteralPath $selfOut) -and (Get-Date) -lt $deadline) { Start-Sleep -Milliseconds 500 }

    if (-not (Test-Path -LiteralPath $selfOut)) {
        # NOT a skip. A check that did not run is not a check that passed -- if this cannot
        # be measured here, the most important boundary claim on this machine is unproven.
        need "an unelevated process of YOUR account cannot open the broker's state" {
            throw "could not run the unelevated probe (runas produced no result within 40s)"
        }
    } else {
        $self = @{}
        foreach ($l in Get-Content -LiteralPath $selfOut) {
            $kv = $l -split '=', 2
            if ($kv.Count -eq 2) { $self[$kv[0]] = $kv[1] }
        }
        Write-Host "  (probe ran as '$($self['user'])', elevated=$($self['elevated']))" -ForegroundColor DarkGray

        need "the unelevated probe really was unelevated" { $self['elevated'] -eq 'False' }
        need "an unelevated process of YOUR account cannot list the broker's state" { $self['state_list'] -eq 'DENIED' }
        need "an unelevated process of YOUR account cannot read the store key"      { $self['key_read'] -eq 'DENIED' }
        need "your agents can still reach the run directory"                        { $self['run_list'] -eq 'ALLOWED' }
    }
} finally {
    Remove-Item -LiteralPath $selfScript, $selfOut -Force -ErrorAction SilentlyContinue
}

Write-Host ""
Write-Host "  Note: an ELEVATED process of an administrator account CAN open the state" -ForegroundColor DarkGray
Write-Host "  directory. That is by design and is the same as root on Linux -- but on Windows" -ForegroundColor DarkGray
Write-Host "  it includes anything launched from an SSH session, which gets a full token." -ForegroundColor DarkGray

section "What the broker says about itself"------------------------------------------------


# TALKS TO THE BROKER DIRECTLY, rather than through the CLI.
#
# The first version of this ran `wundervault-agent --ping`. That flag does not exist, and
# an unrecognised flag fell through to "start a broker in the foreground" -- so the
# verifier started a SECOND broker, as the verifying user, and hung for ever. The daemon
# now refuses unknown options, and this asks the management endpoint the question directly:
# one TCP connect to the port the broker published, one JSON line, one answer.
#
# It also proves something the ACL checks cannot: that the OWNER'S account can reach the
# endpoint. A boundary that also shuts out the people who are supposed to get through is
# not a boundary, it is an outage.
$mgmtFile = Join-Path $Run 'mgmt\mgmt.port'
if (-not (Test-Path -LiteralPath $mgmtFile)) {
    need "the broker answers on its management endpoint" { throw "no mgmt.port at $mgmtFile" }
} else {
    $rec = Get-Content -LiteralPath $mgmtFile -Raw | ConvertFrom-Json

    # ASK TWICE, WITH DIFFERENT NONCES, AND WITH DEADLINES.
    #
    # Deadlines because a listener that accepts TCP and then says nothing made ReadLine()
    # block for ever -- a required check that hangs is worse than one that fails, because
    # it never reaches the exit code at all.
    #
    # Twice because the signature check here has to be one that CAN FAIL. Checking that the
    # `sig` field is a long string proves the far end can type; a squatter returns the
    # recorded server_id and forty characters of anything and passes. PowerShell 5.1 runs on
    # .NET Framework, which has no ImportSubjectPublicKeyInfo, so verifying P-256 properly
    # here is not available -- but asking twice is: a broker SIGNS THE NONCE IT WAS GIVEN,
    # so two different nonces must produce two different signatures. A replayed banner
    # cannot. (The full signature verification lives in the unit tests, against the key.)
    function Ask-Broker {
        param([int] $Port, [string] $Nonce)
        $client = New-Object Net.Sockets.TcpClient
        try {
            $conn = $client.BeginConnect('127.0.0.1', $Port, $null, $null)
            if (-not $conn.AsyncWaitHandle.WaitOne(5000)) { throw "connect timed out" }
            $client.EndConnect($conn)
            $client.ReceiveTimeout = 10000
            $client.SendTimeout = 10000
            $stream = $client.GetStream()
            $stream.ReadTimeout = 10000
            $writer = New-Object IO.StreamWriter($stream)
            $reader = New-Object IO.StreamReader($stream)
            $writer.NewLine = "`n"; $writer.AutoFlush = $true
            $writer.WriteLine((@{ hello = 'wv-broker-hello-v1'; nonce = $Nonce } | ConvertTo-Json -Compress))
            $bannerLine = $reader.ReadLine()
            $writer.WriteLine((@{ action = 'ping' } | ConvertTo-Json -Compress))
            $pingLine = $reader.ReadLine()
            return @{ banner = $bannerLine; ping = $pingLine }
        } finally { $client.Close() }
    }

    $first = $null; $second = $null
    try { $first  = Ask-Broker -Port ([int]$rec.port) -Nonce ('a' * 8 + [guid]::NewGuid().ToString('N')) } catch { $first = $null }
    try { $second = Ask-Broker -Port ([int]$rec.port) -Nonce ('b' * 8 + [guid]::NewGuid().ToString('N')) } catch { $second = $null }
    $banner = if ($first) { $first.banner } else { $null }
    $reply  = if ($first) { $first.ping } else { $null }

    need "the broker answers on the port it published" { [bool]$reply }

    if ($reply) {
        $p = $reply | ConvertFrom-Json
        need "the broker signs the nonce it was given, not a replay" {
            $b1 = $banner | ConvertFrom-Json
            if ($b1.server_id -ne $rec.server_id) { return $false }
            if (-not $b1.sig) { return $false }
            # A real DER-encoded P-256 signature is about 70-72 bytes.
            $raw = [Convert]::FromBase64String($b1.sig)
            if ($raw.Length -lt 64 -or $raw.Length -gt 80) { return $false }
            if (-not $second) { return $false }
            $b2 = $second.banner | ConvertFrom-Json
            # Different nonce, different signature. A replayed banner cannot do this.
            ($b2.sig -ne $b1.sig) -and ($b2.server_id -eq $rec.server_id)
        }
        need "the broker reports a REAL boundary" { $p.boundary -eq $true }
        need "the broker reports running as '$Account'" { $p.account -eq $Account }
        need "the store key is a real key, not a derived one" {
            $p.key_mode -eq 'local-file' -or $p.key_mode -eq 'sealed-tpm' -or $p.key_mode -eq 'sealed-host'
        }
        Write-Host "  (broker $($p.version), key_mode=$($p.key_mode), boundary=$($p.boundary))" -ForegroundColor DarkGray
    }
}

# -- verdict -------------------------------------------------------------------
Write-Host ""
Write-Host "  $($script:Passes) passed, $($script:Failures) failed, $($script:Skips) not applicable"
if ($script:Failures -gt 0) {
    Write-Host "`nThe boundary is NOT verified on this machine." -ForegroundColor Red
    Write-Host "Do not describe Windows as supported until this exits clean." -ForegroundColor Red
    exit 1
}
Write-Host "`nVerified: the broker runs as its own account and yours cannot open its state." -ForegroundColor Green
exit 0
