# SPDX-License-Identifier: MIT
# Prepare has no triggers. Enable requires a successful manually observed cycle.
[CmdletBinding()]
param(
    [ValidateSet('Prepare','Enable','Disable','Status')][string]$Action='Status',
    [Parameter(Mandatory=$true)][string]$PythonPath,
    [Parameter(Mandatory=$true)][string]$ConfigPath
)
$ErrorActionPreference='Stop'
$taskName='XNET Halo Code Feed r01'
$engine=[IO.Path]::GetFullPath((Join-Path $PSScriptRoot 'feed_engine.py'))
$python=[IO.Path]::GetFullPath($PythonPath)
$configFull=[IO.Path]::GetFullPath($ConfigPath)
$shellFull=Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
$helper=[IO.Path]::GetFullPath((Join-Path $PSScriptRoot 'feed_control.ps1'))
$userSid=[Security.Principal.WindowsIdentity]::GetCurrent().User.Value
function QuotePath([string]$Path) {
    if ($Path.Contains('"') -or $Path -match '[\x00-\x1f]' -or $Path.EndsWith('\')) { throw 'Scheduler argument path refused.' }
    return '"'+$Path+'"'
}
function OwnedTask {
    $task=Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue
    if ($null -eq $task) { return $null }
    $expected='-NoProfile -WindowStyle Hidden -ExecutionPolicy RemoteSigned -File '+(QuotePath $helper)+
        ' -Action Once -PythonPath '+(QuotePath $python)+' -ConfigPath '+(QuotePath $configFull)
    $principalSid=$task.Principal.UserId
    if ($principalSid -notmatch '^S-1-') {
        $principalSid=(New-Object Security.Principal.NTAccount($principalSid)).Translate([Security.Principal.SecurityIdentifier]).Value
    }
    if ($task.Actions.Count -ne 1 -or $task.Actions[0].Execute -ne $shellFull -or $task.Actions[0].Arguments -ne $expected -or
        $task.Principal.RunLevel -ne 'Limited' -or $principalSid -ne $userSid) {
        throw 'Existing task identity differs; refusing to modify it.'
    }
    return $task
}
$snapshot=& $python -B -u $engine status --config $configFull
if ($LASTEXITCODE -ne 0) { throw 'Config/source validation failed before scheduler mutation.' }
$config=Get-Content -LiteralPath $configFull -Raw | ConvertFrom-Json
if ($Action -eq 'Status') {
    $task=OwnedTask
    @{task_name=$taskName;present=($null-ne$task);state=if($task){[string]$task.State}else{'absent'};
        feed=($snapshot|ConvertFrom-Json)} | ConvertTo-Json -Depth 10
    exit 0
}
if ($Action -eq 'Prepare') {
    if ($null -ne (Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue)) { throw 'Task already exists; inspect before replacement.' }
    $args='-NoProfile -WindowStyle Hidden -ExecutionPolicy RemoteSigned -File '+(QuotePath $helper)+
        ' -Action Once -PythonPath '+(QuotePath $python)+' -ConfigPath '+(QuotePath $configFull)
    $actionDef=New-ScheduledTaskAction -Execute $shellFull -Argument $args -WorkingDirectory $PSScriptRoot
    $principal=New-ScheduledTaskPrincipal -UserId $userSid -LogonType Interactive -RunLevel Limited
    $settings=New-ScheduledTaskSettingsSet -MultipleInstances IgnoreNew -Hidden -ExecutionTimeLimit (New-TimeSpan -Minutes 8) -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries
    $definition=New-ScheduledTask -Action $actionDef -Principal $principal -Settings $settings -Description 'XNET owned public practice feed, one hourly bounded cycle. No models. Cloud mount readback only.'
    Register-ScheduledTask -TaskName $taskName -InputObject $definition | Out-Null
    @{status='manual-first';task_name=$taskName;automatic_triggers=0;run_level='Limited';credentials='none'} | ConvertTo-Json
    exit 0
}
$task=OwnedTask
if ($null-eq$task) { throw 'Prepare the owned task first.' }
if ($Action-eq'Disable') { Disable-ScheduledTask -TaskName $taskName | Out-Null; @{status='disabled';task_name=$taskName}|ConvertTo-Json; exit 0 }
$cyclePath=Join-Path $config.control_root 'last-cycle.json'
if (-not (Test-Path -LiteralPath $cyclePath -PathType Leaf)) { throw 'Run and inspect one manual cycle before enabling.' }
$cycle=Get-Content -LiteralPath $cyclePath -Raw | ConvertFrom-Json
if ($cycle.status-ne'ready' -or $cycle.model_calls-ne0 -or $cycle.evaluation_inputs-ne0 -or
    $cycle.integrity.events-lt1 -or @($cycle.mirrors).Count-ne@($config.mirrors.PSObject.Properties).Count -or
    @($cycle.mirrors|Where-Object {$_.status-ne'local-readback-passed'}).Count-ne0) {
    throw 'Manual cycle has not passed all explicitly configured local mirror readback checks; task remains manual-only.'
}
# Repetition runs the same bounded once operation. The writer lease prevents two
# processes from acquiring data together; STOP's pause also governs this task.
$trigger=New-ScheduledTaskTrigger -Once -At (Get-Date).AddMinutes(60) -RepetitionInterval (New-TimeSpan -Hours 1)
Set-ScheduledTask -TaskName $taskName -Trigger $trigger | Out-Null
Enable-ScheduledTask -TaskName $taskName | Out-Null
@{status='hourly-enabled';task_name=$taskName;run_level='Limited';remote_upload_verified=$false;model_calls=0}|ConvertTo-Json
