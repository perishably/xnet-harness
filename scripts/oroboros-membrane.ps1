# Both membranes call the same fixed, source-pinned packet controller.
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$Config,
    [Parameter(Mandatory = $true)][ValidateSet('plan', 'cycle', 'verify')][string]$Action,
    [string]$Packet,
    [Parameter(Mandatory = $true)][string]$PythonExecutable,
    [Parameter(Mandatory = $true)][ValidatePattern('^[0-9a-fA-F]{64}$')][string]$ScriptSha256,
    [Parameter(Mandatory = $true)][ValidatePattern('^[0-9a-fA-F]{64}$')][string]$CoreSha256
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Get-MembraneRegularFile([string]$PathValue) {
    if ([string]::IsNullOrWhiteSpace($PathValue)) {
        throw 'A required local file path is missing.'
    }
    # Refuse network syntax before Get-Item can touch a remote share.
    if ($PathValue -match '^[\\/]{2}') {
        throw 'Network file paths are outside the local membrane contract.'
    }
    $item = Get-Item -LiteralPath $PathValue -Force
    if ($item.PSIsContainer -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint)) {
        throw 'Membrane input must be a regular local file, not a directory or reparse point.'
    }
    if ($item.FullName.StartsWith('\\')) {
        throw 'Network file paths are outside the local membrane contract.'
    }
    return $item.FullName
}

if ($Action -eq 'cycle') {
    if ([string]::IsNullOrWhiteSpace($Packet)) { throw 'cycle requires -Packet.' }
} elseif (-not [string]::IsNullOrWhiteSpace($Packet)) {
    throw '-Packet is only accepted for cycle.'
}

$repoRoot = Split-Path -Parent $PSScriptRoot
$scriptPath = Get-MembraneRegularFile (Join-Path $PSScriptRoot 'oroboros-sphere.py')
$corePath = Get-MembraneRegularFile (Join-Path $repoRoot 'xnet\oroboros_sphere.py')
$configPath = Get-MembraneRegularFile $Config
$pythonPath = Get-MembraneRegularFile $PythonExecutable
if ([IO.Path]::GetExtension($pythonPath) -ine '.exe') {
    throw '-PythonExecutable must identify a local Python .exe.'
}
if ((Get-FileHash -LiteralPath $scriptPath -Algorithm SHA256).Hash -ine $ScriptSha256) {
    throw 'Pinned sphere CLI source hash mismatch.'
}
if ((Get-FileHash -LiteralPath $corePath -Algorithm SHA256).Hash -ine $CoreSha256) {
    throw 'Pinned sphere core source hash mismatch.'
}

$controllerArguments = @('-I', '-B', $scriptPath, '--config', $configPath,
    '--lane', 'powershell', '--action', $Action)
if ($Action -eq 'cycle') {
    $packetPath = Get-MembraneRegularFile $Packet
    $controllerArguments += @('--packet', $packetPath)
}

# Array arguments keep packet text and file names out of shell evaluation.
& $pythonPath @controllerArguments
$controllerExit = $LASTEXITCODE
exit $controllerExit
