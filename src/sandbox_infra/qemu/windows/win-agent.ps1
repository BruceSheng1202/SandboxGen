# SandboxGEN in-guest agent (Windows). PowerShell 5.1, runs as SYSTEM.
# Mirrors the Linux agent HTTP protocol on 0.0.0.0:8000, reached by the task
# driver through qemu hostfwd. Behaviour is captured with Sysmon (ETW).
$ErrorActionPreference = 'SilentlyContinue'
$TaskDir = 'C:\task'
$Sysmon  = 'C:\sandboxgen\Sysmon64.exe'
New-Item -ItemType Directory -Force -Path $TaskDir | Out-Null
Remove-Item "$TaskDir\.running" -Force   # a stale marker from an aborted job would make /execute answer 409 forever
function Get-State {
  if (Test-Path "$TaskDir\run.json") { return @{ state='done' } }
  if (Test-Path "$TaskDir\.running") { return @{ state='running' } }
  return @{ state='idle' }
}

function Send($ctx, $code, $obj, [byte[]]$bytes, $ctype) {
  $resp = $ctx.Response; $resp.StatusCode = $code
  if ($bytes) { $resp.ContentType = $ctype; $resp.ContentLength64 = $bytes.Length; $resp.OutputStream.Write($bytes,0,$bytes.Length) }
  else { $json=[Text.Encoding]::UTF8.GetBytes(($obj|ConvertTo-Json -Compress -Depth 6)); $resp.ContentType='application/json'; $resp.ContentLength64=$json.Length; $resp.OutputStream.Write($json,0,$json.Length) }
  $resp.OutputStream.Close()
}

function Run-Sample($path, $timeout, $interp) {
  $TaskDir='C:\task'; $Sysmon='C:\sandboxgen\Sysmon64.exe'
  New-Item -ItemType File -Force -Path "$TaskDir\.running" | Out-Null
  $started=(Get-Date)
  Remove-Item "$TaskDir\sysmon.evtx","$TaskDir\sysmon.xml","$TaskDir\run.json" -Force
  # clear + start capture
  & $Sysmon -accepteula -c C:\sandboxgen\sysmonconfig.xml | Out-Null
  wevtutil cl "Microsoft-Windows-Sysmon/Operational"
  # Launch the sample in the INTERACTIVE analyst session (session 1, admin
  # token), not here in session 0 as SYSTEM: GUI installers/dialogs need a
  # desktop, and HKCU / %APPDATA% must be a real user's. Task Scheduler does
  # the session + token plumbing; the agent itself stays SYSTEM so the sample
  # cannot kill it. (analyst/analyst is the autologon account from autounattend.)
  $tn = 'SandboxGENSample'
  schtasks /delete /tn $tn /f 2>$null | Out-Null
  $tr = if ($interp) { "$interp `"$path`"" } else { "`"$path`"" }
  $marker = Get-Date
  schtasks /create /tn $tn /tr $tr /sc once /st 00:00 /ru analyst /rp analyst /rl HIGHEST /it /f 2>&1 | Out-Null
  schtasks /run /tn $tn 2>&1 | Out-Null
  # find the launched process (up to 90 s: task scheduler + TCG are slow)
  $p = $null; $launch_deadline = (Get-Date).AddSeconds(90)
  while (-not $p -and (Get-Date) -lt $launch_deadline) {
    Start-Sleep -Seconds 2
    $cand = Get-CimInstance Win32_Process | Where-Object { $_.CommandLine -and $_.CommandLine.IndexOf($path, [StringComparison]::OrdinalIgnoreCase) -ge 0 } | Select-Object -First 1
    if ($cand) { $p = Get-Process -Id $cand.ProcessId -ErrorAction SilentlyContinue }
  }
  $launch_error = $null
  if (-not $p) {
    # fallback: run it here (session 0) so the analysis still yields something
    $launch_error = 'scheduled-task launch not observed within 90 s; ran in session 0 instead'
    if ($interp) { $p = Start-Process -FilePath $interp -ArgumentList $path -PassThru -WorkingDirectory $TaskDir }
    else         { $p = Start-Process -FilePath $path   -PassThru -WorkingDirectory $TaskDir }
  }
  $timeout = [int]$timeout; if ($timeout -le 0) { $timeout = 60 }
  # Run the FULL analysis window, not just until the launched process exits: a
  # bootstrapper/dropper (ScreenConnect, most installers) exits in seconds after
  # spawning msiexec / a service / a child that carries the real behaviour. If
  # we stopped at root exit we would freeze and kill those children immediately.
  # So wait for root exit OR timeout, then keep observing for the remainder.
  $wait_error = $null
  try { $rootDone = $p.WaitForExit([int]($timeout*1000)) } catch { $rootDone = $false; $wait_error = "$_" }
  $root_exit = $null; $root_exited_s = $null
  if ($rootDone) { try { $root_exit = $p.ExitCode } catch {}; $root_exited_s = [Math]::Round(((Get-Date)-$started).TotalSeconds,1) }
  $remain = $timeout - ((Get-Date)-$started).TotalSeconds
  if ($remain -gt 1) { Start-Sleep -Seconds ([Math]::Ceiling($remain)) }
  $exit_code = $root_exit
  $timed_out = -not $rootDone          # root still alive at the window end
  $waited_s = ((Get-Date)-$started).TotalSeconds
  $session = $p.SessionId
  Start-Sleep -Seconds 3
  # Freeze what the sample left behind: (a) its whole process tree, and (b) any
  # process started after the marker whose image is NOT under the Windows dir.
  # Never sweep System32 images by start time alone: nslookup/powershell make
  # Windows spawn on-demand svchost hosts (DNS, WMI, ...) and killing those cut
  # the network (agent connection reset) and hung the event-log export forever.
  $killed = @()
  try {
    $all = Get-CimInstance Win32_Process | Select-Object ProcessId, ParentProcessId, Name
    $tree = @(); if ($p) { $tree = @([int]$p.Id) }
    $grew = $true
    while ($grew) { $grew = $false
      foreach ($w in $all) { if (($tree -contains [int]$w.ParentProcessId) -and -not ($tree -contains [int]$w.ProcessId)) { $tree += [int]$w.ProcessId; $grew = $true } } }
    foreach ($id in $tree) { if ($id -ne $PID) { Stop-Process -Id $id -Force; $killed += $id } }
    $winroot = $env:SystemRoot
    Get-Process | Where-Object { $_.StartTime -gt $marker -and $_.Id -ne $PID -and -not ($tree -contains $_.Id) -and
                                 $_.Path -and -not $_.Path.StartsWith($winroot, 'OrdinalIgnoreCase') } |
      ForEach-Object { Stop-Process -Id $_.Id -Force; $killed += $_.Id }
  } catch {}
  Start-Sleep -Seconds 1
  # collect; every step guarded so run.json (=> state 'done') is always written
  $export_error = $null
  try {
    wevtutil epl "Microsoft-Windows-Sysmon/Operational" "$TaskDir\sysmon.evtx"
    # native XML dump (EventData fields, no Message formatting): Get-WinEvent
    # message rendering took >15 min under TCG and never finished a run
    cmd /c "wevtutil qe Microsoft-Windows-Sysmon/Operational /f:xml /rd:false /c:200000 > `"$TaskDir\sysmon.xml`" 2>&1"
  } catch { $export_error = "$_" }
  try { cmd /c "cscript //nologo C:\Windows\System32\slmgr.vbs /dlv > `"$TaskDir\license.txt`" 2>&1" } catch {}
  try { Get-Process | Select-Object Id,ProcessName,Path,StartTime | ConvertTo-Csv -NoTypeInformation | Set-Content "$TaskDir\ps.csv" } catch {}
  # $p.ExitCode is unreadable for a process in another session; recover the
  # sample's exit code from the scheduled task's Last Result before deleting it.
  $task_result = $null
  try {
    $q = schtasks /query /tn $tn /fo LIST /v 2>$null | Select-String 'Last Result'
    if ($q) { $task_result = ($q -split ':',2)[1].Trim() }
  } catch {}
  if ($null -eq $exit_code -and -not $timed_out -and $task_result) { $exit_code = $task_result }
  schtasks /delete /tn $tn /f 2>$null | Out-Null
  @{ exit_code=$exit_code; timed_out=$timed_out; killed=$killed; export_error=$export_error; task_result=$task_result;
     session_id=$session; launch_error=$launch_error; timeout_s=$timeout; waited_s=$waited_s; wait_error=$wait_error; root_exited_s=$root_exited_s;
     duration_s=((Get-Date)-$started).TotalSeconds } | ConvertTo-Json | Set-Content "$TaskDir\run.json"
  Remove-Item "$TaskDir\.running" -Force
}

$listener = New-Object Net.HttpListener
$listener.Prefixes.Add('http://+:8000/')
$listener.Start()
while ($listener.IsListening) {
  $ctx = $listener.GetContext()
  $req = $ctx.Request; $p = $req.Url.AbsolutePath
  try {
    if ($p -eq '/status') { Send $ctx 200 @{ status='ready'; hostname=$env:COMPUTERNAME; os=[Environment]::OSVersion.VersionString; state=(Get-State).state } }
    elseif ($p -eq '/poll') { Send $ctx 200 (Get-State) }
    elseif ($p -eq '/store' -and $req.HttpMethod -eq 'POST') {
      $name = [IO.Path]::GetFileName($req.QueryString['name']); if (-not $name) { $name='sample.exe' }
      $dest = Join-Path $TaskDir $name
      $ms = New-Object IO.MemoryStream; $req.InputStream.CopyTo($ms); [IO.File]::WriteAllBytes($dest,$ms.ToArray())
      $sha = (Get-FileHash $dest -Algorithm SHA256).Hash.ToLower()
      Send $ctx 200 @{ path=$dest; sha256=$sha; size=$ms.Length }
    }
    elseif ($p -eq '/execute' -and $req.HttpMethod -eq 'POST') {
      if ((Get-State).state -eq 'running') { Send $ctx 409 @{ error='busy' } }
      else {
        $body = (New-Object IO.StreamReader($req.InputStream)).ReadToEnd() | ConvertFrom-Json
        # NB: in command-argument mode "[int]$body.timeout" is NOT a cast, it is
        # the literal string "[int]120"; the job then did "[int]120"*1000 (string
        # repetition), WaitForExit threw, and every sample was killed within
        # seconds while run.json claimed timed_out. Build the list in expression mode.
        $to = 60; try { $to = [int]$body.timeout } catch {}
        if ($to -le 0) { $to = 60 }
        Start-Job -ScriptBlock ${function:Run-Sample} -ArgumentList @($body.path, $to, $body.interpreter) | Out-Null
        Send $ctx 200 @{ ok=$true }
      }
    }
    elseif ($p -eq '/result') {
      if ((Get-State).state -ne 'done') { Send $ctx 409 @{ error='no finished task' } }
      else {
        $zip="C:\result.zip"; Remove-Item $zip -Force
        Add-Type -AssemblyName System.IO.Compression.FileSystem
        [IO.Compression.ZipFile]::CreateFromDirectory($TaskDir,$zip)
        Send $ctx 200 $null ([IO.File]::ReadAllBytes($zip)) 'application/zip'
      }
    }
    elseif ($p -eq '/run' -and $req.HttpMethod -eq 'POST') {
      # synchronous cmd.exe /c <cmd>; used by the golden build (activation, link
      # checks) and for diagnostics. Only reachable via the qemu hostfwd port.
      $body = (New-Object IO.StreamReader($req.InputStream)).ReadToEnd() | ConvertFrom-Json
      $t = if ($body.timeout) { [int]$body.timeout } else { 120 }
      $out = "$TaskDir\run_out.txt"; Remove-Item $out -Force
      $rp = Start-Process -FilePath 'cmd.exe' -ArgumentList "/c $($body.cmd) > `"$out`" 2>&1" -PassThru -WindowStyle Hidden
      $fin = $rp.WaitForExit($t*1000)
      if (-not $fin) { Stop-Process -Id $rp.Id -Force }
      $txt = ''; if (Test-Path $out) { $txt = [IO.File]::ReadAllText($out) }
      Send $ctx 200 @{ exit_code=$(if ($fin) { $rp.ExitCode } else { $null }); timed_out=(-not $fin); output=$txt }
    }
    elseif ($p -eq '/shutdown') { Send $ctx 200 @{ ok=$true }; Start-Sleep 1; Stop-Computer -Force }
    else { Send $ctx 404 @{ error='unknown' } }
  } catch { Send $ctx 500 @{ error="$_" } }
}
