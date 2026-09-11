@echo off
rem SandboxGEN Windows golden setup — runs once at first logon (from the media
rem drive found by autounattend). Prepares the analysis guest, then the agent
rem service starts on this and every boot. This VM is a disposable, network-
rem isolated analysis sandbox, so Defender/updates/firewall are turned OFF (they
rem would quarantine the sample or add nondeterministic network noise).
set SRC=%~d0\sandboxgen
mkdir C:\sandboxgen 2>nul
xcopy /Y /E "%SRC%\*" C:\sandboxgen\ >nul

rem --- disable Defender (real-time + tamper via policy) ---
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender" /v DisableAntiSpyware /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" /v DisableRealtimeMonitoring /t REG_DWORD /d 1 /f
powershell -Command "Set-MpPreference -DisableRealtimeMonitoring $true -DisableBehaviorMonitoring $true -DisableIOAVProtection $true" 2>nul

rem --- disable Windows Update + firewall (isolated VM) ---
sc config wuauserv start= disabled
netsh advfirewall set allprofiles state off

rem --- SmartScreen / OOBE noise off ---
rem no "allow your PC to be discoverable" flyout on first desktop (it sat open in the savestate)
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Network\NewNetworkWindowOff" /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\System" /v EnableSmartScreen /t REG_DWORD /d 0 /f

rem --- first-logon background noise off: OneDrive setup, ngen, appraiser, WER, search ---
rem (they were still running when the golden state was saved and showed up as
rem  "files written" in every analysis)
taskkill /f /im OneDrive.exe >nul 2>&1
taskkill /f /im OneDriveSetup.exe >nul 2>&1
if exist %SystemRoot%\SysWOW64\OneDriveSetup.exe start /wait %SystemRoot%\SysWOW64\OneDriveSetup.exe /uninstall
if exist %SystemRoot%\System32\OneDriveSetup.exe start /wait %SystemRoot%\System32\OneDriveSetup.exe /uninstall
reg delete "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" /v OneDriveSetup /f >nul 2>&1
for %%t in ("\Microsoft\Windows\.NET Framework\.NET Framework NGEN v4.0.30319" "\Microsoft\Windows\.NET Framework\.NET Framework NGEN v4.0.30319 64" "\Microsoft\Windows\Application Experience\Microsoft Compatibility Appraiser" "\Microsoft\Windows\Application Experience\StartupAppTask" "\Microsoft\Windows\Customer Experience Improvement Program\Consolidator" "\Microsoft\Windows\Windows Error Reporting\QueueReporting" "\Microsoft\Windows\WindowsUpdate\Scheduled Start" "\Microsoft\Windows\Maintenance\WinSAT" "\Microsoft\Windows\Shell\FamilySafetyMonitor" "\Microsoft\Windows\Feedback\Siuf\DmClient") do schtasks /change /tn %%t /disable >nul 2>&1
sc config WSearch start= disabled >nul & sc stop WSearch >nul 2>&1
sc config DiagTrack start= disabled >nul & sc stop DiagTrack >nul 2>&1
sc config SysMain start= disabled >nul & sc stop SysMain >nul 2>&1

rem --- Sysmon behaviour capture ---
C:\sandboxgen\Sysmon64.exe -accepteula -i C:\sandboxgen\sysmonconfig.xml

rem --- agent as a SYSTEM scheduled task, at every startup, and now ---
schtasks /create /tn SandboxGENAgent /ru SYSTEM /rl HIGHEST /sc onstart ^
  /tr "powershell -NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File C:\sandboxgen\win-agent.ps1" /f
schtasks /run /tn SandboxGENAgent

rem --- auto-clicker in the analyst interactive session: advances modal dialogs
rem     (SmartScreen, installers, "renamed file" prompts) that would otherwise
rem     stall a sample forever. Runs as analyst so it can touch the desktop. ---
rem in-guest auto-clicker retired: host-side qemu key driver (win_detonate.py)
rem advances dialogs from outside; the in-guest UIA approach was unreliable under TCG.
rem (autoclick.ps1 stays in the media but is not started.)

rem --- licence state at build time (compared against the analysis-time capture) ---
cscript //nologo %SystemRoot%\System32\slmgr.vbs /dlv > C:\sandboxgen\license-at-build.txt 2>&1

rem --- marker for the build driver ---
echo ready > C:\sandboxgen\ready.txt
