[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidateSet('install', 'uninstall')]
    [string]$Action,
    [string]$Account,
    [string]$NodePath,
    [string]$PackageRoot,
    [string]$Version,
    [switch]$RemoveData
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$Identity = [System.Security.Principal.WindowsIdentity]::GetCurrent()
$Principal = New-Object System.Security.Principal.WindowsPrincipal($Identity)
if (-not $Principal.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'Run this script as Administrator.'
}
if (-not $env:ProgramFiles -or -not $env:ProgramData -or -not $env:SystemRoot) {
    throw 'The Windows installation paths are not available.'
}

$Root = Join-Path $env:ProgramFiles 'Wundervault'
$Spool = Join-Path $env:ProgramData 'wundervault-update'
$ManifestPath = Join-Path $Root 'state\manifest.json'
$Icacls = Join-Path $env:SystemRoot 'System32\icacls.exe'
$Cmd = Join-Path $env:SystemRoot 'System32\cmd.exe'
$SystemSid = New-Object System.Security.Principal.SecurityIdentifier('S-1-5-18')
$AdminsSid = New-Object System.Security.Principal.SecurityIdentifier('S-1-5-32-544')
$UsersSid = New-Object System.Security.Principal.SecurityIdentifier('S-1-5-32-545')
$Utf8 = New-Object System.Text.UTF8Encoding($false)
$Ascii = [System.Text.Encoding]::ASCII

function Assert-RealPath {
    param([string]$Path)
    $Item = Get-Item -LiteralPath $Path -Force
    if (($Item.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
        throw "Refusing a reparse point: $Path"
    }
}

function Assert-CmdPath {
    param([string]$Path)
    if (-not [System.IO.Path]::IsPathRooted($Path) -or
        $Path -notmatch '^[A-Za-z]:\\' -or $Path -match '["%!\r\n]') {
        throw "Path cannot be represented safely in a command wrapper: $Path"
    }
}

Assert-CmdPath $Root
Assert-CmdPath $Spool
Assert-CmdPath $Cmd
Assert-CmdPath $Icacls

function Set-LayoutAcl {
    param(
        [string]$Path,
        [bool]$Directory,
        [bool]$Public,
        [System.Security.Principal.SecurityIdentifier]$Owner,
        [System.Security.Principal.SecurityIdentifier]$Broker = $null,
        [bool]$Request = $false,
        [bool]$DenyBrokerDirectory = $false
    )
    Assert-RealPath $Path
    if ($Directory) {
        $Acl = New-Object System.Security.AccessControl.DirectorySecurity
        $Inheritance = [System.Security.AccessControl.InheritanceFlags]'ContainerInherit, ObjectInherit'
    } else {
        $Acl = New-Object System.Security.AccessControl.FileSecurity
        $Inheritance = [System.Security.AccessControl.InheritanceFlags]::None
    }
    $Acl.SetAccessRuleProtection($true, $false)
    $Propagation = [System.Security.AccessControl.PropagationFlags]::None
    $Allow = [System.Security.AccessControl.AccessControlType]::Allow
    foreach ($Sid in @($SystemSid, $AdminsSid)) {
        $Rule = New-Object System.Security.AccessControl.FileSystemAccessRule(
            $Sid, [System.Security.AccessControl.FileSystemRights]::FullControl,
            $Inheritance, $Propagation, $Allow
        )
        [void]$Acl.AddAccessRule($Rule)
    }
    if ($Public) {
        $Rights = [System.Security.AccessControl.FileSystemRights]::Read
        if ($Directory -and -not $DenyBrokerDirectory) {
            $Rights = [System.Security.AccessControl.FileSystemRights]::ReadAndExecute
        }
        # The spool's Users rule is this-folder-only, never inherited by request.json.
        $PublicInheritance = $Inheritance
        if ($DenyBrokerDirectory) {
            $PublicInheritance = [System.Security.AccessControl.InheritanceFlags]::None
        }
        $Rule = New-Object System.Security.AccessControl.FileSystemAccessRule(
            $UsersSid, $Rights, $PublicInheritance, $Propagation, $Allow
        )
        [void]$Acl.AddAccessRule($Rule)
    }
    if ($Request) {
        # Node opens O_WRONLY with GENERIC_WRITE, which needs the complete Write set.
        # No Delete, DeleteSubdirectoriesAndFiles, ChangePermissions, or TakeOwnership.
        $RequestRights = [System.Security.AccessControl.FileSystemRights]'Read, Write, Synchronize'
        $Rule = New-Object System.Security.AccessControl.FileSystemAccessRule(
            $Broker, $RequestRights,
            [System.Security.AccessControl.InheritanceFlags]::None, $Propagation, $Allow
        )
        [void]$Acl.AddAccessRule($Rule)
    }
    if ($DenyBrokerDirectory) {
        # A broker might also be in Users. Deny directory access, not access to its file.
        $Rule = New-Object System.Security.AccessControl.FileSystemAccessRule(
            $Broker, [System.Security.AccessControl.FileSystemRights]::FullControl,
            [System.Security.AccessControl.InheritanceFlags]::None, $Propagation,
            [System.Security.AccessControl.AccessControlType]::Deny
        )
        [void]$Acl.AddAccessRule($Rule)
    }
    Set-Acl -LiteralPath $Path -AclObject $Acl
    # icacls enables the privilege needed to assign SYSTEM as owner.
    & $Icacls $Path /setowner ("*" + $Owner.Value) /Q | Out-Null
    if ($LASTEXITCODE -ne 0) {
        throw "Could not set owner on $Path"
    }
    $Actual = Get-Acl -LiteralPath $Path
    if ($Actual.GetOwner([System.Security.Principal.SecurityIdentifier]).Value -ne $Owner.Value -or
        -not $Actual.AreAccessRulesProtected) {
        throw "Owner or inheritance verification failed: $Path"
    }
}

function Test-VersionGreater {
    param([string]$Left, [string]$Right)
    $L = $Left.Split('.')
    $R = $Right.Split('.')
    for ($I = 0; $I -lt 3; $I++) {
        if ($L[$I].Length -ne $R[$I].Length) {
            return $L[$I].Length -gt $R[$I].Length
        }
        $Comparison = [string]::CompareOrdinal($L[$I], $R[$I])
        if ($Comparison -ne 0) {
            return $Comparison -gt 0
        }
    }
    return $false
}

function Assert-Version {
    param([string]$Value)
    if ($Value -notmatch '^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$') {
        throw 'Expected a canonical X.Y.Z version.'
    }
}

$ResumeUpdater = $false
# One layout run at a time on this machine, installs and uninstalls alike (review round 3, B blind
# spot): a named system-wide mutex, released in the finally below. An abandoned one (a run that
# died) is granted to us with AbandonedMutexException, which counts as acquired.
$LayoutMutex = New-Object System.Threading.Mutex($false, 'Global\WundervaultLayout')
$HoldsMutex = $false
try {
    try { $HoldsMutex = $LayoutMutex.WaitOne([TimeSpan]::FromSeconds(120)) }
    catch [System.Threading.AbandonedMutexException] { $HoldsMutex = $true }
    if (-not $HoldsMutex) { throw 'Another Wundervault install or uninstall is still running after 120 seconds.' }
    # Disabling prevents a new tick; let an in-flight update finish rather than killing its switch.
    $Task = Get-ScheduledTask -TaskName 'wundervault-update' -ErrorAction SilentlyContinue
    if ($null -ne $Task) {
        # Resumed whatever happens (install, or an uninstall that failed); a successful uninstall
        # has removed the task, so there is nothing left to resume (review round 3, B-F3).
        $ResumeUpdater = $true
        Disable-ScheduledTask -TaskName 'wundervault-update' | Out-Null
        # The state read BEFORE disabling can be stale: a tick may have started in between, and
        # disabling does not stop a running instance (review round 3, B-F2).
        $Task = Get-ScheduledTask -TaskName 'wundervault-update' -ErrorAction SilentlyContinue
        $Wait = [System.Diagnostics.Stopwatch]::StartNew()
        while ($null -ne $Task -and $Task.State -eq 'Running') {
            if ($Wait.Elapsed.TotalSeconds -ge 120) {
                throw 'The wundervault-update task is still Running after 120 seconds; layout was not changed.'
            }
            Start-Sleep -Milliseconds 250
            $Task = Get-ScheduledTask -TaskName 'wundervault-update' -ErrorAction SilentlyContinue
        }
        $Wait.Stop()
    }

$script:Manifest = $null
if (Test-Path -LiteralPath $Root) {
    Assert-RealPath $Root
    if (-not (Test-Path -LiteralPath $ManifestPath -PathType Leaf)) {
        # Only the exact, empty skeleton of our first run may be adopted.
        if ($Action -ne 'install' -or
            -not (Test-Path -LiteralPath $Root -PathType Container)) {
            throw "Won't adopt a folder it didn't make: $Root"
        }
        $Children = @(Get-ChildItem -LiteralPath $Root -Force)
        if ($Children.Count -ne 3) {
            throw "Won't adopt a folder it didn't make: $Root"
        }
        foreach ($Name in @('versions', 'bin', 'state')) {
            $Path = Join-Path $Root $Name
            if (-not (Test-Path -LiteralPath $Path -PathType Container)) {
                throw "Won't adopt a folder it didn't make: $Root"
            }
            Assert-RealPath $Path
            if (@(Get-ChildItem -LiteralPath $Path -Force).Count -ne 0) {
                throw "Won't adopt a folder it didn't make: $Root"
            }
        }
        foreach ($Path in @($Root) + @($Children | ForEach-Object { $_.FullName })) {
            $Owner = (Get-Acl -LiteralPath $Path).GetOwner(
                [System.Security.Principal.SecurityIdentifier]
            ).Value
            if ($Owner -notin @($SystemSid.Value, $AdminsSid.Value)) {
                throw "Won't adopt a folder it didn't make: $Root"
            }
        }
    } else {
        Assert-RealPath (Join-Path $Root 'state')
        Assert-RealPath $ManifestPath
        $script:Manifest = Get-Content -LiteralPath $ManifestPath -Raw | ConvertFrom-Json
        if ($script:Manifest.format -ne 'wundervault-layout-1' -or
            $script:Manifest.root -ne $Root -or $script:Manifest.platform -ne 'win') {
            throw 'Not our manifest.'
        }
    }
}

function Save-Manifest {
    $Temp = $ManifestPath + '.tmp.' + $PID
    $Data = $Utf8.GetBytes(($script:Manifest | ConvertTo-Json -Depth 8) + "`n")
    $Stream = New-Object System.IO.FileStream(
        $Temp, [System.IO.FileMode]::CreateNew, [System.IO.FileAccess]::Write,
        [System.IO.FileShare]::None
    )
    try {
        $Stream.Write($Data, 0, $Data.Length)
        $Stream.Flush($true)
    } finally {
        $Stream.Dispose()
    }
    if ([System.IO.File]::Exists($ManifestPath)) {
        [System.IO.File]::Replace($Temp, $ManifestPath, [NullString]::Value)   # $null becomes "" in PowerShell 5.1: "path is not of a legal form"
    } else {
        [System.IO.File]::Move($Temp, $ManifestPath)
    }
}

function Test-Owned {
    param([string]$Path)
    return @($script:Manifest.paths | Where-Object { $_.path -eq $Path }).Count -ne 0
}

function Add-ManifestPath {
    param([string]$Path, [string]$Kind)
    if (-not (Test-Owned $Path)) {
        $script:Manifest.paths = @($script:Manifest.paths) + @(
            [pscustomobject]@{ path = $Path; kind = $Kind }
        )
        Save-Manifest
    }
}

function Claim-Path {
    param([string]$Path, [string]$Kind)
    if (-not (Test-Owned $Path)) {
        if (Test-Path -LiteralPath $Path) {
            throw "Won't replace an unmanaged path: $Path"
        }
        Add-ManifestPath $Path $Kind
    }
}

function Write-LayoutFile {
    param([string]$Path, [string]$Text, [bool]$CommandFile = $false)
    Claim-Path $Path 'file'
    if (Test-Path -LiteralPath $Path) {
        Assert-RealPath $Path
    }
    $Temp = $Path + '.tmp.' + $PID
    $Encoding = $Utf8
    if ($CommandFile) {
        # cmd.exe uses the Windows ANSI code page for batch files.
        $Encoding = [System.Text.Encoding]::Default
        if ($Encoding.GetString($Encoding.GetBytes($Text)) -cne $Text) {
            throw "A command path cannot be represented in the Windows code page: $Path"
        }
    }
    $Bytes = $Encoding.GetBytes($Text)
    $Stream = New-Object System.IO.FileStream(
        $Temp, [System.IO.FileMode]::CreateNew, [System.IO.FileAccess]::Write,
        [System.IO.FileShare]::None
    )
    try {
        $Stream.Write($Bytes, 0, $Bytes.Length)
        $Stream.Flush($true)
    } finally {
        $Stream.Dispose()
    }
    if ([System.IO.File]::Exists($Path)) {
        [System.IO.File]::Replace($Temp, $Path, [NullString]::Value)
    } else {
        [System.IO.File]::Move($Temp, $Path)
    }
}

if ($Action -eq 'uninstall') {
    if ($null -eq $script:Manifest) {
        throw 'No managed manifest.'
    }
    if (@($script:Manifest.tasks) -contains 'wundervault-update') {
        $Task = Get-ScheduledTask -TaskName 'wundervault-update' -ErrorAction SilentlyContinue
        if ($null -ne $Task) {
            Unregister-ScheduledTask -TaskName 'wundervault-update' -Confirm:$false
        }
    }
    if ((Test-Owned $Spool) -and (Test-Path -LiteralPath $Spool)) {
        Assert-RealPath $Spool
        # Check descendants too: Remove-Item must not traverse a substituted junction.
        foreach ($Item in @(Get-ChildItem -LiteralPath $Spool -Force -Recurse)) {
            Assert-RealPath $Item.FullName
        }
        Remove-Item -LiteralPath $Spool -Recurse -Force
    }
    $Expected = Join-Path $env:ProgramFiles 'Wundervault'
    if ($Root -cne $Expected) {
        throw 'Unsafe removal root.'
    }
    Assert-RealPath $Root
    foreach ($Item in @(Get-ChildItem -LiteralPath $Root -Force -Recurse)) {
        Assert-RealPath $Item.FullName
    }
    Remove-Item -LiteralPath $Root -Recurse -Force
    if ($RemoveData) {
        Write-Output 'layout: -RemoveData is handled by the caller; broker data was not touched here'
    }
    # return, not exit: the finally below must release the mutex (and resume the updater if needed).
    return
}

Assert-Version $Version
Assert-CmdPath $NodePath
Assert-CmdPath $PackageRoot
if (-not (Test-Path -LiteralPath $NodePath -PathType Leaf) -or
    -not (Test-Path -LiteralPath $PackageRoot -PathType Container) -or -not $Account) {
    throw 'Validated Node, package root, and broker account are required.'
}
Assert-RealPath $NodePath
Assert-RealPath $PackageRoot
$BrokerSid = (New-Object System.Security.Principal.NTAccount($Account)).Translate(
    [System.Security.Principal.SecurityIdentifier]
)
if ($BrokerSid.Value -in @($SystemSid.Value, $AdminsSid.Value, $UsersSid.Value)) {
    throw 'Expected a dedicated unprivileged broker account.'
}

if ($null -eq $script:Manifest) {
    if (-not (Test-Path -LiteralPath $Root)) {
        [void](New-Item -ItemType Directory -Path $Root)
    }
    Set-LayoutAcl $Root $true $true $AdminsSid
    foreach ($Name in @('versions', 'bin', 'state')) {
        $Path = Join-Path $Root $Name
        if (-not (Test-Path -LiteralPath $Path)) {
            [void](New-Item -ItemType Directory -Path $Path)
        }
        Set-LayoutAcl $Path $true ($Name -ne 'state') $AdminsSid
    }
    $script:Manifest = [pscustomobject]@{
        format = 'wundervault-layout-1'
        root = $Root
        platform = 'win'
        paths = @(
            [pscustomobject]@{ path = $Root; kind = 'dir' }
            [pscustomobject]@{ path = (Join-Path $Root 'versions'); kind = 'dir' }
            [pscustomobject]@{ path = (Join-Path $Root 'bin'); kind = 'dir' }
            [pscustomobject]@{ path = (Join-Path $Root 'state'); kind = 'dir' }
            [pscustomobject]@{ path = $ManifestPath; kind = 'file' }
        )
        launchers = @()
        tasks = @()
    }
    Save-Manifest
}
Set-LayoutAcl $Root $true $true $AdminsSid
foreach ($Name in @('versions', 'bin', 'state')) {
    $Path = Join-Path $Root $Name
    Assert-RealPath $Path
    Set-LayoutAcl $Path $true ($Name -ne 'state') $AdminsSid
}

$HighestPath = Join-Path $Root 'state\highest.json'
$Highest = $null
if (Test-Path -LiteralPath $HighestPath) {
    Assert-RealPath $HighestPath
    $Value = Get-Content -LiteralPath $HighestPath -Raw | ConvertFrom-Json
    if (@($Value.PSObject.Properties).Count -ne 1) {
        throw 'Invalid high-water file.'
    }
    Assert-Version $Value.version
    $Highest = $Value.version
    if (Test-VersionGreater $Highest $Version) {
        throw 'Refusing an installer version below the high-water mark.'
    }
}

$V = Join-Path $Root ("versions\" + $Version)
$App = Join-Path $V 'app'
$Active = Join-Path $Root 'bin\active.cmd'
$ActiveNode = $NodePath
$IsCurrent = $false
if (Test-Path -LiteralPath $V) {
    Assert-RealPath $V
    if ((Test-Path -LiteralPath $App) -and (Test-Path -LiteralPath $Active)) {
        Assert-RealPath $App
        Assert-RealPath $Active
        $Lines = [System.IO.File]::ReadAllLines($Active)
        if ($Lines.Count -eq 2 -and $Lines[0] -match '^set "WV_NODE=(.+)"$' -and
            $Lines[1] -ceq ('set "WV_APP=' + $App + '"')) {
            $ActiveNode = $Matches[1]
            Assert-CmdPath $ActiveNode
            Assert-RealPath $ActiveNode
            $IsCurrent = $true
        }
    }
    if (-not $IsCurrent) {
        # Left by a run that stopped part-way (a crash, a power cut). Ours and not running, so it
        # is removed and copied again; refusing it would block every later run for good.
        if (-not (Test-Owned $V)) { throw 'Version directory exists and was not made by this layout.' }
        foreach ($Item in @(Get-ChildItem -LiteralPath $V -Force -Recurse)) { Assert-RealPath $Item.FullName }
        Remove-Item -LiteralPath $V -Recurse -Force
    }
}
if (-not $IsCurrent) {
    # Inspect before copying as well: never let Copy-Item follow an untrusted junction.
    $Reparse = @(Get-ChildItem -LiteralPath $PackageRoot -Recurse -Force -Attributes ReparsePoint)
    if ($Reparse.Count -ne 0) {
        throw 'Package contains a reparse point.'
    }
    Add-ManifestPath $V 'dir'
    if (-not (Test-Path -LiteralPath $V)) { [void](New-Item -ItemType Directory -Path $V) }
    Set-LayoutAcl $V $true $true $AdminsSid
    $Staging = Join-Path $V 'app.staging'
    Copy-Item -LiteralPath $PackageRoot -Destination $Staging -Recurse
    $DotBin = Join-Path $Staging 'node_modules\.bin'
    if (Test-Path -LiteralPath $DotBin) {
        Assert-RealPath $DotBin
        Remove-Item -LiteralPath $DotBin -Recurse -Force
    }
    $Reparse = @(Get-ChildItem -LiteralPath $Staging -Recurse -Force -Attributes ReparsePoint)
    if ($Reparse.Count -ne 0) {
        throw 'Copied package contains a reparse point.'
    }
    Set-LayoutAcl $Staging $true $true $AdminsSid
    # Everything below inherits the folder's rules (SYSTEM and Administrators full, Users read and
    # run) — two icacls runs for the whole tree instead of one per file (~3,000 for this package).
    & $Icacls $Staging /reset /T /C /Q | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "Could not reset permissions under $Staging" }
    & $Icacls $Staging /setowner ('*' + $AdminsSid.Value) /T /C /Q | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "Could not set owner under $Staging" }
    Set-LayoutAcl $Staging $true $true $AdminsSid
    Move-Item -LiteralPath $Staging -Destination $App
    Add-ManifestPath $App 'dir'
    foreach ($Item in @(Get-ChildItem -LiteralPath $App -Recurse -Force)) {
        $Kind = 'file'
        if ($Item.PSIsContainer) { $Kind = 'dir' }
        Add-ManifestPath $Item.FullName $Kind
    }
}

$BundledNode = Join-Path $V 'node.exe'
$VersionNodePath = Join-Path $V 'node.path'
if (Test-Path -LiteralPath $BundledNode) {
    Assert-RealPath $BundledNode
    if (-not (Test-Path -LiteralPath $BundledNode -PathType Leaf)) {
        throw 'no node for version'
    }
    $ActiveNode = $BundledNode
} else {
    if (-not (Test-Path -LiteralPath $VersionNodePath)) {
        # A first install uses the validated system Node. Preserve an existing current version's
        # system Node when migrating a layout made before node.path was introduced.
        Assert-CmdPath $ActiveNode
        if ($ActiveNode -notmatch '\\node\.exe$' -or $ActiveNode.Length -gt 1024 -or
            $Ascii.GetString($Ascii.GetBytes($ActiveNode)) -cne $ActiveNode) {
            throw 'System Node path must be ASCII, at most 1 KiB, and end with \node.exe.'
        }
        Write-LayoutFile $VersionNodePath $ActiveNode
    }
    Assert-RealPath $VersionNodePath
    $NodePathItem = Get-Item -LiteralPath $VersionNodePath -Force
    if ($NodePathItem.PSIsContainer -or $NodePathItem.Length -gt 1024) {
        throw 'no node for version'
    }
    $NodePathBytes = [System.IO.File]::ReadAllBytes($VersionNodePath)
    if (@($NodePathBytes | Where-Object { $_ -gt 127 }).Count -ne 0) {
        throw 'no node for version'
    }
    $ActiveNode = $Ascii.GetString($NodePathBytes)
    Assert-CmdPath $ActiveNode
    if ($ActiveNode -notmatch '\\node\.exe$' -or
        -not (Test-Path -LiteralPath $ActiveNode -PathType Leaf)) {
        throw 'no node for version'
    }
    Assert-RealPath $ActiveNode
    Add-ManifestPath $VersionNodePath 'file'
    Set-LayoutAcl $VersionNodePath $false $true $AdminsSid
}

Write-LayoutFile $Active (
    'set "WV_NODE=' + $ActiveNode + '"' + "`r`n" +
    'set "WV_APP=' + $App + '"' + "`r`n"
) $true
foreach ($Name in @('broker', 'updater', 'wundervault-mcp', 'wundervault-agent')) {
    $Entry = 'bin\wundervault-agent'
    if ($Name -eq 'updater') { $Entry = 'dist\updater.js' }
    if ($Name -eq 'wundervault-mcp') { $Entry = 'bin\wundervault-mcp' }
    $Text = '@echo off' + "`r`n" +
        'call "%~dp0active.cmd"' + "`r`n" +
        '"%WV_NODE%" "%WV_APP%\' + $Entry + '" %*' + "`r`n"
    $Path = Join-Path $Root ('bin\' + $Name + '.cmd')
    Write-LayoutFile $Path $Text $true
    Set-LayoutAcl $Path $false $true $AdminsSid
}
Set-LayoutAcl $Active $false $true $AdminsSid
if ($null -eq $Highest -or (Test-VersionGreater $Version $Highest)) {
    Write-LayoutFile $HighestPath ('{"version":"' + $Version + '"}' + "`n")
    Set-LayoutAcl $HighestPath $false $false $AdminsSid
}

Claim-Path $Spool 'dir'
if (-not (Test-Path -LiteralPath $Spool)) {
    [void](New-Item -ItemType Directory -Path $Spool)
}
Assert-RealPath $Spool
Set-LayoutAcl -Path $Spool -Directory $true -Public $true -Owner $SystemSid `
    -Broker $BrokerSid -DenyBrokerDirectory $true

$RequestPath = Join-Path $Spool 'request.json'
$StatusPath = Join-Path $Spool 'status.json'
foreach ($Path in @($RequestPath, $StatusPath)) {
    Claim-Path $Path 'file'
    if (-not (Test-Path -LiteralPath $Path)) {
        $Initial = ''
        if ($Path -eq $StatusPath) { $Initial = '{}' }
        [System.IO.File]::WriteAllText($Path, $Initial, $Utf8)
    }
    Assert-RealPath $Path
}
Set-LayoutAcl -Path $RequestPath -Directory $false -Public $false -Owner $SystemSid `
    -Broker $BrokerSid -Request $true
Set-LayoutAcl $StatusPath $false $true $SystemSid

# Read the ACLs back. Do not trust a successful Set-Acl alone.
$Allowed = [System.Security.AccessControl.FileSystemRights]'Read, Write, Synchronize'
$Forbidden = [System.Security.AccessControl.FileSystemRights]'Delete, DeleteSubdirectoriesAndFiles, ChangePermissions, TakeOwnership'
$RequestAcl = Get-Acl -LiteralPath $RequestPath
$BrokerRules = @($RequestAcl.GetAccessRules(
    $true, $true, [System.Security.Principal.SecurityIdentifier]
) | Where-Object { $_.IdentityReference.Value -eq $BrokerSid.Value })
if ($BrokerRules.Count -ne 1 -or
    $BrokerRules[0].AccessControlType -ne [System.Security.AccessControl.AccessControlType]::Allow -or
    [int64]$BrokerRules[0].FileSystemRights -ne [int64]$Allowed -or
    ([int64]$BrokerRules[0].FileSystemRights -band [int64]$Forbidden) -ne 0 -or
    $BrokerRules[0].IsInherited) {
    throw 'Broker request permissions are not exactly Read, Write, Synchronize.'
}
$DirectoryAcl = Get-Acl -LiteralPath $Spool
$DirectoryRules = @($DirectoryAcl.GetAccessRules(
    $true, $true, [System.Security.Principal.SecurityIdentifier]
) | Where-Object { $_.IdentityReference.Value -eq $BrokerSid.Value })
if ($DirectoryRules.Count -ne 1 -or
    $DirectoryRules[0].AccessControlType -ne [System.Security.AccessControl.AccessControlType]::Deny -or
    $DirectoryRules[0].FileSystemRights -ne [System.Security.AccessControl.FileSystemRights]::FullControl -or
    $DirectoryRules[0].InheritanceFlags -ne [System.Security.AccessControl.InheritanceFlags]::None) {
    throw 'Broker must have no rights on the spool directory.'
}

$ExistingTask = Get-ScheduledTask -TaskName 'wundervault-update' -ErrorAction SilentlyContinue
if ($null -ne $ExistingTask -and
    -not (@($script:Manifest.tasks) -contains 'wundervault-update')) {
    throw 'Refusing to replace an unmanaged updater task.'
}
if (-not (@($script:Manifest.tasks) -contains 'wundervault-update')) {
    $script:Manifest.tasks = @($script:Manifest.tasks) + @('wundervault-update')
    Save-Manifest
}
$TaskPrincipal = New-ScheduledTaskPrincipal -UserId 'S-1-5-18' `
    -LogonType ServiceAccount -RunLevel Highest
$TaskAction = New-ScheduledTaskAction -Execute $Cmd `
    -Argument ('/d /s /c ""{0}""' -f (Join-Path $Root 'bin\updater.cmd'))
$Startup = New-ScheduledTaskTrigger -AtStartup
$Daily = New-ScheduledTaskTrigger -Daily -At ([datetime]::Today)
$Repeating = New-ScheduledTaskTrigger -Once -At ([datetime]::Today) `
    -RepetitionInterval (New-TimeSpan -Minutes 1)
$Daily.Repetition = $Repeating.Repetition
$Settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries `
    -DontStopIfGoingOnBatteries -ExecutionTimeLimit (New-TimeSpan -Minutes 15) `
    -MultipleInstances IgnoreNew -StartWhenAvailable -Disable
Register-ScheduledTask -TaskName 'wundervault-update' -Action $TaskAction `
    -Trigger @($Startup, $Daily) -Principal $TaskPrincipal -Settings $Settings -Force | Out-Null
$ResumeUpdater = $true

# The task object is another root-code boundary, not merely the files it runs.
$Scheduler = New-Object -ComObject 'Schedule.Service'
$Scheduler.Connect()
$RegisteredTask = $Scheduler.GetFolder('\').GetTask('wundervault-update')
$RegisteredTask.SetSecurityDescriptor('O:BAG:BAD:P(A;;FA;;;SY)(A;;FA;;;BA)', 0)
$TaskAcl = New-Object System.Security.AccessControl.RawSecurityDescriptor(
    $RegisteredTask.GetSecurityDescriptor(7)
)
foreach ($Ace in $TaskAcl.DiscretionaryAcl) {
    if ($Ace.SecurityIdentifier.Value -notin @($SystemSid.Value, $AdminsSid.Value)) {
        throw 'Updater task has an unexpected access rule.'
    }
}

Save-Manifest
Set-LayoutAcl $ManifestPath $false $false $AdminsSid
Write-Output ('BROKER_CMD=' + (Join-Path $Root 'bin\broker.cmd'))
} finally {
    if ($ResumeUpdater) {
        $Task = Get-ScheduledTask -TaskName 'wundervault-update' -ErrorAction SilentlyContinue
        if ($null -ne $Task) {
            Enable-ScheduledTask -TaskName 'wundervault-update' | Out-Null
        }
    }
    if ($HoldsMutex) { $LayoutMutex.ReleaseMutex() }
    $LayoutMutex.Dispose()
}
