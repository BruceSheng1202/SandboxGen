# Trusted per-task runner, uploaded from the read-only analysis container.
# The golden's HTTP agent is transport only; its legacy /execute is not used.
# No sample-controlled text is evaluated as PowerShell or cmd.exe source.
$ErrorActionPreference = 'Stop'
$TaskDir = 'C:\task'
$tn = 'SandboxGENSample'
$started = Get-Date
$launchError = $null; $exportError = $null; $waitError = $null
$taskResult = $null; $timedOut = $false; $rootExited = $null
$killed = @(); $timeout = 0; $waited = 0; $registered = $null
$executable = $null; $arguments = ''; $samplePath = $null
New-Item -ItemType File -Force -Path "$TaskDir\.running" | Out-Null
Remove-Item "$TaskDir\run.json" -Force -ErrorAction SilentlyContinue
try {
  $request = Get-Content -Raw -LiteralPath "$TaskDir\launch-request.json" | ConvertFrom-Json
  if ($request.launch.version -ne 1) { throw 'unsupported launch protocol' }
  $samplePath = [IO.Path]::GetFullPath([string]$request.path)
  if ([IO.Path]::GetDirectoryName($samplePath) -ine $TaskDir) { throw 'sample must be directly inside C:\task' }
  if (-not (Test-Path -LiteralPath $samplePath -PathType Leaf)) { throw 'sample file missing' }
  $timeout = [int]$request.timeout
  if ($timeout -lt 1 -or $timeout -gt 1800) { throw 'invalid analysis timeout' }
  $package = [string]$request.launch.package
  if ($package -eq 'exe') {
    if ([IO.Path]::GetExtension($samplePath) -ine '.exe') { throw 'EXE transport must end in .exe' }
    $executable = $samplePath
  } elseif ($package -eq 'dll') {
    $entry = [string]$request.launch.function
    if ($entry -notmatch '^(?:[A-Za-z_?@$][A-Za-z0-9_?@$]*|#[1-9][0-9]{0,4})$' -or $entry -ieq 'DllMain') {
      throw 'DLL requires an explicit exported entry point'
    }
    if ($request.launch.architecture -eq 'x86') { $executable = "$env:SystemRoot\SysWOW64\rundll32.exe" }
    elseif ($request.launch.architecture -eq 'x64') { $executable = "$env:SystemRoot\System32\rundll32.exe" }
    else { throw 'unsupported DLL architecture' }
    $arguments = '"' + $samplePath + '",' + $entry
  } else { throw 'unsupported launch package' }

  # Include just this DLL's ImageLoad event, so a rundll32 process alone does
  # not count as proof that the submitted DLL loaded.
  [xml]$config = Get-Content -Raw 'C:\sandboxgen\sysmonconfig.xml'
  if ($package -eq 'dll') {
    $group = $config.CreateElement('RuleGroup'); $group.SetAttribute('groupRelation', 'or')
    $load = $config.CreateElement('ImageLoad'); $load.SetAttribute('onmatch', 'include')
    $target = $config.CreateElement('ImageLoaded'); $target.SetAttribute('condition', 'is')
    $target.InnerText = $samplePath
    $null = $load.AppendChild($target); $null = $group.AppendChild($load)
    $null = $config.Sysmon.EventFiltering.AppendChild($group)
  }
  $config.Save("$TaskDir\sysmon-task.xml")
  & 'C:\sandboxgen\Sysmon64.exe' -accepteula -c "$TaskDir\sysmon-task.xml" | Out-Null
  if ($LASTEXITCODE -ne 0) { throw 'Sysmon configuration failed' }
  wevtutil cl 'Microsoft-Windows-Sysmon/Operational'
  if ($LASTEXITCODE -ne 0) { throw 'Sysmon clear failed' }

  # ExecAction has separate executable/arguments/working-directory fields;
  # no file associations, /tr quoting ambiguity, or session-0 fallback.
  $scheduler = New-Object -ComObject 'Schedule.Service'; $scheduler.Connect()
  $folder = $scheduler.GetFolder('\')
  try { $folder.DeleteTask($tn, 0) } catch {}
  $definition = $scheduler.NewTask(0)
  $definition.Principal.UserId = 'analyst'
  $definition.Principal.LogonType = 3  # TASK_LOGON_INTERACTIVE_TOKEN
  $definition.Principal.RunLevel = 1
  $definition.Settings.Enabled = $true
  $definition.Settings.DisallowStartIfOnBatteries = $false
  $definition.Settings.StopIfGoingOnBatteries = $false
  $definition.Settings.ExecutionTimeLimit = 'PT1H'
  $action = $definition.Actions.Create(0)
  $action.Path = $executable; $action.Arguments = $arguments; $action.WorkingDirectory = $TaskDir
  $registered = $folder.RegisterTaskDefinition($tn, $definition, 6, 'analyst', $null, 3)
  $started = Get-Date
  $null = $registered.Run($null)
  # Observe the full budget even when an EXE exits immediately after spawning
  # a child. Sysmon supplies launch evidence, including short-lived processes.
  while (((Get-Date) - $started).TotalSeconds -lt $timeout) {
    Start-Sleep -Milliseconds 500
    if ($null -eq $rootExited -and $registered.State -eq 3 -and $registered.LastRunTime -ge $started.AddSeconds(-2)) {
      $rootExited = [Math]::Round(((Get-Date) - $started).TotalSeconds, 1)
    }
  }
  $waited = ((Get-Date) - $started).TotalSeconds
  $taskResult = $registered.LastTaskResult
  $timedOut = $registered.State -eq 4
} catch {
  $launchError = "$_"
} finally {
  # Stop only the selected executable/loader and its still-live descendants.
  # Completed roots/children remain in Sysmon for attribution after shutdown.
  try {
    $all = @(Get-CimInstance Win32_Process)
    $roots = @($all | Where-Object {
      $_.ExecutablePath -ieq $executable -and
      ($package -ne 'dll' -or ($_.CommandLine -and $_.CommandLine.Contains($arguments)))
    })
    $tree = @($roots | ForEach-Object { [int]$_.ProcessId })
    $grew = $true
    while ($grew) {
      $grew = $false
      foreach ($process in $all) {
        if ($tree -contains [int]$process.ParentProcessId -and $tree -notcontains [int]$process.ProcessId) {
          $tree += [int]$process.ProcessId; $grew = $true
        }
      }
    }
    if ($registered -and $registered.State -eq 4) { $registered.Stop(0) }
    foreach ($processId in $tree) {
      if ($processId -ne $PID) { Stop-Process -Id $processId -Force -ErrorAction SilentlyContinue; $killed += $processId }
    }
    if ($folder) { $folder.DeleteTask($tn, 0) }
  } catch { $waitError = "cleanup: $_" }
  Start-Sleep -Seconds 2
  try {
    wevtutil epl 'Microsoft-Windows-Sysmon/Operational' "$TaskDir\sysmon.evtx" /ow:true
    if ($LASTEXITCODE -ne 0) { throw 'Sysmon EVTX export failed' }
    # Fixed command only: XML output is read by the host-side collector.
    cmd /c 'wevtutil qe Microsoft-Windows-Sysmon/Operational /f:xml /rd:false /c:200000 > C:\task\sysmon.xml'
    if ($LASTEXITCODE -ne 0) { throw 'Sysmon XML export failed' }
  } catch { $exportError = "$_" }
  @{
    launcher_version=1; launch_executable=$executable; launch_arguments=$arguments
    exit_code=$(if (-not $timedOut) { $taskResult } else { $null })
    task_result=$taskResult; timed_out=$timedOut; killed=$killed
    launch_error=$launchError; wait_error=$waitError; export_error=$exportError
    timeout_s=$timeout; waited_s=$waited; root_exited_s=$rootExited
    duration_s=((Get-Date)-$started).TotalSeconds
  } | ConvertTo-Json -Depth 6 | Set-Content -Encoding UTF8 "$TaskDir\run.json"
  Remove-Item "$TaskDir\.running" -Force -ErrorAction SilentlyContinue
}
