# SPDX-License-Identifier: MIT
# Standard-user controls. STOP is cooperative; this script never kills processes.
[CmdletBinding()]
param(
    [ValidateSet('Init','Once','Sync','Verify','Start','Stop','Status')][string]$Action = 'Status',
    [Parameter(Mandatory=$true)][string]$PythonPath,
    [Parameter(Mandatory=$true)][string]$ConfigPath,
    [string]$ControlRoot, [string]$ArchiveRoot, [string]$ProtonRoot, [string]$GoogleRoot
)
$ErrorActionPreference = 'Stop'
$enginePath = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot 'feed_engine.py'))
$pythonFull = [IO.Path]::GetFullPath($PythonPath)
$configFull = [IO.Path]::GetFullPath($ConfigPath)
if (-not (Test-Path -LiteralPath $pythonFull -PathType Leaf)) { throw 'Explicit Python executable is missing.' }

function FileHash([string]$Path) {
    $stream = [IO.File]::OpenRead($Path)
    try { $algo = [Security.Cryptography.SHA256]::Create(); try {
        return ([BitConverter]::ToString($algo.ComputeHash($stream))).Replace('-','').ToLowerInvariant()
    } finally { $algo.Dispose() } } finally { $stream.Dispose() }
}
function QuotePath([string]$Path) {
    if ($Path.Contains('"') -or $Path -match '[\x00-\x1f]' -or $Path.EndsWith('\')) { throw 'Process argument path refused.' }
    return '"' + $Path + '"'
}
function GetOwned($Config) {
    $ownerPath = Join-Path $Config.control_root 'owner.json'
    if (-not (Test-Path -LiteralPath $ownerPath -PathType Leaf)) { return @{alive=$false;owned=$false;owner=$null} }
    $owner = Get-Content -LiteralPath $ownerPath -Raw | ConvertFrom-Json
    $process = Get-Process -Id ([int]$owner.pid) -ErrorAction SilentlyContinue
    if ($null -eq $process) { return @{alive=$false;owned=$false;owner=$owner} }
    $start = $process.StartTime.ToUniversalTime()
    $expectedStart = [DateTimeOffset]::Parse($owner.process_start_utc).UtcDateTime
    $owned = $owner.status -eq 'running' -and [Math]::Abs(($start-$expectedStart).TotalMilliseconds) -lt 10 -and
        [IO.Path]::GetFullPath($process.Path) -eq $pythonFull -and $owner.python_executable -eq $pythonFull -and
        $owner.python_sha256 -eq (FileHash $pythonFull) -and $owner.script -eq $enginePath -and
        $owner.script_sha256 -eq (FileHash $enginePath) -and $owner.config_sha256 -eq $snapshot.config_sha256
    foreach ($name in @('feed_engine.py','feed_control.ps1','schedule_feed.ps1')) {
        $owned = $owned -and $owner.source_pins.$name -eq (FileHash (Join-Path $PSScriptRoot $name))
    }
    return @{alive=$true;owned=[bool]$owned;owner=$owner;pid=$process.Id;start_utc=$start.ToString('o')}
}
function InvokeEngine([string]$Operation) {
    $engineArgs = @('-B','-u',$enginePath,$Operation,'--config',$configFull)
    $answer = & $pythonFull @engineArgs
    if ($LASTEXITCODE -ne 0) { throw "Feed $Operation failed. No automatic retry or global stop was attempted." }
    return ($answer | ConvertFrom-Json)
}

if ($Action -eq 'Init') {
    if (-not $ControlRoot -or -not $ArchiveRoot) {
        throw 'Init requires explicit ControlRoot and ArchiveRoot; cloud mirrors are optional.'
    }
    $engineArgs = @('-B','-u',$enginePath,'init','--config',$configFull,'--control',[IO.Path]::GetFullPath($ControlRoot),
        '--archive',[IO.Path]::GetFullPath($ArchiveRoot))
    if ($ProtonRoot) { $engineArgs += @('--proton',[IO.Path]::GetFullPath($ProtonRoot)) }
    if ($GoogleRoot) { $engineArgs += @('--google',[IO.Path]::GetFullPath($GoogleRoot)) }
    & $pythonFull @engineArgs
    if ($LASTEXITCODE -ne 0) { throw 'Feed initialization failed.' }
    exit 0
}
$config = Get-Content -LiteralPath $configFull -Raw | ConvertFrom-Json
# Validate current source pins through the engine before any lifecycle mutation.
$snapshot = InvokeEngine 'status'
$owned = GetOwned $config
if ($Action -eq 'Status') {
    @{schema='xnet.public-code-feed.lifecycle-status.v1';process=$owned;feed=$snapshot} | ConvertTo-Json -Depth 12
    exit 0
}
if ($Action -eq 'Start') {
    if ($owned.alive -and -not $owned.owned) { throw 'Recorded PID is alive but does not match the feed owner pins; inspect it.' }
    if ($owned.owned) { @{status='already-running';pid=$owned.pid;generation=$owned.owner.generation} | ConvertTo-Json; exit 0 }
    $pause = Join-Path $config.control_root 'paused.json'
    if (Test-Path -LiteralPath $pause -PathType Leaf) {
        # A deliberate Start revokes pause; stale STOP is generation-specific.
        [IO.File]::WriteAllText($pause,'{"paused":false}',(New-Object Text.UTF8Encoding($false)))
    }
    $logRoot = Join-Path $config.control_root 'logs'
    New-Item -ItemType Directory -Path $logRoot -Force | Out-Null
    $launch = [Guid]::NewGuid().ToString('N')
    $processArgs = @('-B','-u',(QuotePath $enginePath),'run','--config',(QuotePath $configFull))
    $startArgs = @{FilePath=$pythonFull;ArgumentList=$processArgs;WindowStyle='Hidden';PassThru=$true;
        RedirectStandardOutput=(Join-Path $logRoot "$launch.stdout.log");
        RedirectStandardError=(Join-Path $logRoot "$launch.stderr.log")}
    $process = Start-Process @startArgs
    $deadline = [Diagnostics.Stopwatch]::StartNew()
    while ($deadline.Elapsed.TotalSeconds -lt 20) {
        Start-Sleep -Milliseconds 200
        $check = GetOwned $config
        if ($check.owned -and $check.pid -eq $process.Id) {
            @{status='started';pid=$check.pid;generation=$check.owner.generation;launch=$launch} | ConvertTo-Json
            exit 0
        }
        if ($process.HasExited) { throw "Owned feed exited before publishing its owner receipt. Inspect $launch logs." }
    }
    throw 'Feed owner handshake not confirmed in 20 seconds; inspect without relaunching or killing.'
}
if ($Action -eq 'Stop') {
    if ($owned.alive -and -not $owned.owned) { throw 'Recorded process ownership differs; no signal or kill sent.' }
    $answer = InvokeEngine 'stop'
    $watch = [Diagnostics.Stopwatch]::StartNew()
    while ($watch.Elapsed.TotalSeconds -lt 20 -and (GetOwned $config).owned) { Start-Sleep -Milliseconds 250 }
    @{request=$answer;process=(GetOwned $config);force_termination=$false} | ConvertTo-Json -Depth 8
    exit 0
}
$operation = @{Once='once';Sync='sync';Verify='verify'}[$Action]
InvokeEngine $operation | ConvertTo-Json -Depth 12
