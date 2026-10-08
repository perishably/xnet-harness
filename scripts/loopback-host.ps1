# Copyright 2026 Felix Xavier Lopez. SPDX-License-Identifier: MIT
# One current-user hourly task. Each native run writes an observable receipt.
[CmdletBinding()]
param(
    [ValidateSet('Prepare','Tick','Start','Stop','Status')][string]$Action='Status',
    [Parameter(Mandatory=$true)][string]$PythonPath,
    [Parameter(Mandatory=$true)][string]$ConfigPath,
    [Parameter(Mandatory=$true)][string]$SourceRoot,
    [string]$TaskName='XNET Loopback Hourly r01'
)
$ErrorActionPreference='Stop'
if ($TaskName -notmatch '^XNET Loopback Hourly [a-zA-Z0-9-]{1,32}$') { throw 'Owned task name required.' }
$taskPython=[IO.Path]::GetFullPath($PythonPath)
$taskConfigPath=[IO.Path]::GetFullPath($ConfigPath)
$taskSource=[IO.Path]::GetFullPath($SourceRoot)
$taskEngine=Join-Path $taskSource 'feed_engine.py'
$taskSelf=[IO.Path]::GetFullPath($PSCommandPath)
$taskShell=Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
$taskConfig=Get-Content -LiteralPath $taskConfigPath -Raw|ConvertFrom-Json
$taskControl=[IO.Path]::GetFullPath($taskConfig.control_root)
$taskOwnerPath=Join-Path $taskControl 'hourly-task-owner.json'
$taskReceiptPath=Join-Path $taskControl 'hourly-task-result.json'
$taskSid=[Security.Principal.WindowsIdentity]::GetCurrent().User.Value
function QuotePath([string]$Value) {
    if ($Value.Contains('"') -or $Value -match '[\x00-\x1f]' -or $Value.EndsWith('\')) { throw 'Argument path refused.' }
    return '"'+$Value+'"'
}
function FileSha([string]$Path) {
    $taskFile=[IO.File]::OpenRead($Path)
    try { $taskAlgo=[Security.Cryptography.SHA256]::Create(); try {
        return ([BitConverter]::ToString($taskAlgo.ComputeHash($taskFile))).Replace('-','').ToLowerInvariant()
    } finally { $taskAlgo.Dispose() } } finally { $taskFile.Dispose() }
}
function WriteReceipt($Value) {
    [IO.File]::WriteAllText($taskReceiptPath,($Value|ConvertTo-Json -Depth 12),[Text.UTF8Encoding]::new($false))
}
$taskArguments='-NoProfile -WindowStyle Hidden -ExecutionPolicy RemoteSigned -File '+(QuotePath $taskSelf)+
    ' -Action Tick -PythonPath '+(QuotePath $taskPython)+' -ConfigPath '+(QuotePath $taskConfigPath)+
    ' -SourceRoot '+(QuotePath $taskSource)+' -TaskName '+(QuotePath $TaskName)
function OwnedTask {
    $taskFound=Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
    if (-not $taskFound) { return $null }
    if (-not (Test-Path -LiteralPath $taskOwnerPath)) { throw 'Existing task has no owned receipt.' }
    $taskOwner=Get-Content -LiteralPath $taskOwnerPath -Raw|ConvertFrom-Json
    $taskPrincipal=$taskFound.Principal.UserId
    if ($taskPrincipal -notmatch '^S-1-') {
        $taskPrincipal=([Security.Principal.NTAccount]::new($taskPrincipal)).Translate([Security.Principal.SecurityIdentifier]).Value
    }
    if ($taskFound.Actions.Count-ne1 -or $taskFound.Actions[0].Execute-ne$taskShell -or
        $taskFound.Actions[0].Arguments-ne$taskArguments -or $taskFound.Actions[0].WorkingDirectory-ne$taskSource -or $taskPrincipal-ne$taskSid -or
        $taskFound.Principal.RunLevel-ne'Limited' -or $taskFound.Principal.LogonType-ne'Interactive' -or $taskOwner.sid-ne$taskSid -or $taskOwner.script_sha256-ne(FileSha $taskSelf) -or
        $taskOwner.config_sha256-ne(FileSha $taskConfigPath) -or $taskOwner.python_sha256-ne(FileSha $taskPython)) {
        throw 'Task identity/source/configuration changed; inspect before mutation.'
    }
    return $taskFound
}
if ($Action-eq'Tick') {
    $taskStart=[DateTime]::UtcNow.ToString('o');$taskWatch=[Diagnostics.Stopwatch]::StartNew()
    try {
        $taskText=@(& $taskPython -B -u $taskEngine once --config $taskConfigPath 2>&1)
        $taskExit=$LASTEXITCODE
        if ($taskExit-ne0) { throw ('Engine exit '+$taskExit+': '+($taskText -join "`n")) }
        $taskResult=($taskText -join "`n")|ConvertFrom-Json
        if ($taskResult.status-notin@('ready','paused')) { throw 'Cycle is not ready or deliberately paused.' }
        WriteReceipt ([ordered]@{schema='xnet.loopback-hourly-task-result.v1';status=$taskResult.status;
            utc_started=$taskStart;utc_finished=[DateTime]::UtcNow.ToString('o');elapsed_seconds=$taskWatch.Elapsed.TotalSeconds;
            exit_code=0;source_sha256=(FileSha $taskEngine);script_sha256=(FileSha $taskSelf);
            cycle=$taskResult;remote_upload_verified=$false})
        exit 0
    } catch {
        WriteReceipt ([ordered]@{schema='xnet.loopback-hourly-task-result.v1';status='failed';utc_started=$taskStart;
            utc_finished=[DateTime]::UtcNow.ToString('o');elapsed_seconds=$taskWatch.Elapsed.TotalSeconds;
            exit_code=1;error=$_.Exception.Message.Substring(0,[Math]::Min(4000,$_.Exception.Message.Length));
            automatic_retry=$false})
        exit 1
    }
}
$taskValidation=& $taskPython -B $taskEngine status --config $taskConfigPath
if ($LASTEXITCODE-ne0) { throw 'Engine/source/configuration validation failed.' }
if ($Action-eq'Prepare') {
    if (Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue) { throw 'Task already exists.' }
    $taskDefinition=New-ScheduledTask -Action (New-ScheduledTaskAction -Execute $taskShell -Argument $taskArguments -WorkingDirectory $taskSource) `
        -Principal (New-ScheduledTaskPrincipal -UserId $taskSid -LogonType Interactive -RunLevel Limited) `
        -Settings (New-ScheduledTaskSettingsSet -Hidden -MultipleInstances IgnoreNew -ExecutionTimeLimit (New-TimeSpan -Minutes 8) -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries)
    Register-ScheduledTask -TaskName $TaskName -InputObject $taskDefinition|Out-Null
    $taskOwner=@{schema='xnet.loopback-hourly-task-owner.v1';script_sha256=(FileSha $taskSelf);
        config_sha256=(FileSha $taskConfigPath);python_sha256=(FileSha $taskPython);sid=$taskSid;automatic_triggers=0}
    [IO.File]::WriteAllText($taskOwnerPath,($taskOwner|ConvertTo-Json -Compress),[Text.UTF8Encoding]::new($false))
    @{status='manual-first';task=$TaskName;run_level='Limited'}|ConvertTo-Json -Compress;exit 0
}
$taskOwned=OwnedTask
if (-not $taskOwned) { throw 'Prepare this owned task first.' }
if ($Action-eq'Start') {
    if (-not (Test-Path -LiteralPath $taskReceiptPath)) { throw 'A manual native task cycle is required first.' }
    $taskPrior=Get-Content -LiteralPath $taskReceiptPath -Raw|ConvertFrom-Json
    $taskNativeInfo=Get-ScheduledTaskInfo -TaskName $TaskName
    $taskNativeStart=$taskNativeInfo.LastRunTime.ToUniversalTime()
    $taskReceiptStart=[DateTime]::Parse($taskPrior.utc_started).ToUniversalTime()
    if ($taskPrior.status-ne'ready' -or $taskPrior.exit_code-ne0 -or $taskPrior.script_sha256-ne(FileSha $taskSelf)) {
        throw 'Manual native task proof is missing or failed.'
    }
    if ($taskOwned.State-eq'Running' -or $taskNativeInfo.LastTaskResult-ne0 -or
        $taskReceiptStart-lt$taskNativeStart -or ($taskReceiptStart-$taskNativeStart).TotalSeconds-gt30) {
        throw 'Successful native task history must match this receipt before enabling hourly runs.'
    }
    [IO.File]::WriteAllText((Join-Path $taskControl 'paused.json'),'{"paused":false}',[Text.UTF8Encoding]::new($false))
    $taskTrigger=New-ScheduledTaskTrigger -Once -At (Get-Date).AddHours(1) -RepetitionInterval (New-TimeSpan -Hours 1)
    Set-ScheduledTask -TaskName $TaskName -Trigger $taskTrigger|Out-Null
    Enable-ScheduledTask -TaskName $TaskName|Out-Null
    Start-ScheduledTask -TaskName $TaskName
    @{status='hourly-enabled';task=$TaskName;model_calls=0}|ConvertTo-Json -Compress;exit 0
}
if ($Action-eq'Stop') {
    Disable-ScheduledTask -TaskName $TaskName|Out-Null
    & $taskPython -B $taskEngine stop --config $taskConfigPath
    if ($LASTEXITCODE-ne0) { throw 'Cooperative pause failed.' }
    @{status='paused';task=$TaskName;force_termination=$false}|ConvertTo-Json -Compress;exit 0
}
$taskInfo=Get-ScheduledTaskInfo -TaskName $TaskName
@{schema='xnet.loopback-hourly-host-status.v1';task=$TaskName;state=[string]$taskOwned.State;
    last_exit=$taskInfo.LastTaskResult;last_run=$taskInfo.LastRunTime.ToString('o');next_run=$taskInfo.NextRunTime.ToString('o');
    feed=($taskValidation|ConvertFrom-Json);task_receipt=if(Test-Path -LiteralPath $taskReceiptPath){Get-Content -LiteralPath $taskReceiptPath -Raw|ConvertFrom-Json}else{$null}}|ConvertTo-Json -Depth 14
