# SandboxGEN auto-clicker (UI Automation) — runs in the analyst interactive
# session. Samples (installers, SmartScreen, "renamed file" prompts, UAC-in-
# session dialogs) stall on modal windows waiting for a human; a sandbox must
# drive them. Walks the UIA tree for Button elements whose name ADVANCES the
# flow (Yes/OK/Run/Next/...) and invokes them, never Cancel/No/Close. Logs each
# invoke to C:\task\autoclick.log as behavioural evidence.
$ErrorActionPreference = 'SilentlyContinue'
$log = 'C:\task\autoclick.log'
function Log($m){ try { "{0}  {1}" -f (Get-Date).ToString('o'), $m | Add-Content $log } catch {} }
Log ("autoclick starting; user=" + $env:USERNAME + " ps=" + $PSVersionTable.PSVersion)
try { Add-Type -AssemblyName UIAutomationClient; Add-Type -AssemblyName UIAutomationTypes; Log "UIA loaded" }
catch { Log ("UIA load FAILED: " + $_) }
# advance-only, ordered so two-step flows (More info -> Run anyway) resolve
$ADVANCE = @('Run anyway','More info','I Agree','I accept','Agree','Accept','Allow','Install',
             'Continue','Finish','Next','Run','Open','Yes','OK','Start','Unzip','Extract')
$AUTO = [System.Windows.Automation.AutomationElement]
$root = $AUTO::RootElement
$condBtn = New-Object System.Windows.Automation.PropertyCondition(
  [System.Windows.Automation.AutomationElement]::ControlTypeProperty,
  [System.Windows.Automation.ControlType]::Button)
$seen = @{}
while ($true) {
  try {
    # every top-level window on this desktop
    $wins = $root.FindAll([System.Windows.Automation.TreeScope]::Children,
      (New-Object System.Windows.Automation.PropertyCondition(
        [System.Windows.Automation.AutomationElement]::ControlTypeProperty,
        [System.Windows.Automation.ControlType]::Window)))
    foreach ($w in $wins) {
      $title = $w.Current.Name
      if (-not $title) { continue }
      $btns = $w.FindAll([System.Windows.Automation.TreeScope]::Descendants, $condBtn)
      # collect button names present
      $names = @{}
      foreach ($b in $btns) { $n = ($b.Current.Name -replace '_','').Trim(); if ($n) { $names[$n.ToLower()] = $b } }
      foreach ($want in $ADVANCE) {
        $b = $names[$want.ToLower()]
        if ($b) {
          $key = "$title|$want"
          if (-not $seen.ContainsKey($key) -or ((Get-Date)-$seen[$key]).TotalSeconds -gt 6) {
            $ip = $b.GetCurrentPattern([System.Windows.Automation.InvokePattern]::Pattern)
            if ($ip) { $ip.Invoke(); $seen[$key] = Get-Date; Log ("window='{0}' clicked='{1}'" -f $title,$want) }
          }
          break
        }
      }
    }
  } catch { }
  Start-Sleep -Milliseconds 1200
}
