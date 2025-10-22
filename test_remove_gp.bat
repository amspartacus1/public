@echo off
setlocal EnableExtensions EnableDelayedExpansion

rem ===== Create timestamped log file in the script directory =====
set "SCRIPT_DIR=%~dp0"
for /f %%I in ('powershell -NoProfile -Command "(Get-Date).ToString(\"yyyyMMdd_HHmmss\")"') do set "STAMP=%%I"
set "LOG=%SCRIPT_DIR%remove-globalprotect_%STAMP%.log"

rem ===== small helper to log status lines to console + file =====
set "TSFMT=powershell -NoProfile -Command \"$d=(Get-Date).ToString('yyyy-MM-dd HH:mm:ss'); Write-Output $d\""
for /f %%I in ('%TSFMT%') do set "NOW=%%I"
echo [%NOW%] Log file: "%LOG%"
>>"%LOG%" echo [%NOW%] ==== start run ====

:log
for /f %%I in ('%TSFMT%') do set "NOW=%%I"
echo [%NOW%] %~1
>>"%LOG%" echo [%NOW%] %~1
exit /b 0

call :log "Uninstall GP ONLY when user is in the office. Press Enter to continue if the user is in the office..."
pause

call :log "Stopping GlobalProtect processes"
echo taskkill /im pangpa.exe /f /t >>"%LOG%" & taskkill /im pangpa.exe /f /t >>"%LOG%" 2>&1
echo taskkill /im pangps.exe /f /t >>"%LOG%" & taskkill /im pangps.exe /f /t >>"%LOG%" 2>&1

call :log "Uninstalling GlobalProtect (trying Name then Description via WMIC)"
echo wmic product where "Name='GlobalProtect'" call uninstall /nointeractive >>"%LOG%"
wmic product where "Name='GlobalProtect'" call uninstall /nointeractive >>"%LOG%" 2>&1
if errorlevel 1 (
    echo wmic product where "Description='GlobalProtect'" call uninstall /nointeractive >>"%LOG%"
    wmic product where "Description='GlobalProtect'" call uninstall /nointeractive >>"%LOG%" 2>&1
)

call :log "Waiting for uninstall to settle (press Enter to continue)"
pause

call :log "Stopping and deleting service PanGPS"
echo sc stop PanGPS >>"%LOG%" & sc stop PanGPS >>"%LOG%" 2>&1
echo sc delete PanGPS >>"%LOG%" & sc delete PanGPS >>"%LOG%" 2>&1

call :log "Removing folders"
if exist "C:\Program Files\Palo Alto Networks" (
    echo rd /s /q "C:\Program Files\Palo Alto Networks" >>"%LOG%"
    rd /s /q "C:\Program Files\Palo Alto Networks" >>"%LOG%" 2>&1
)

if defined LOCALAPPDATA (
    if exist "%LOCALAPPDATA%\Palo Alto Networks" (
        echo rd /s /q "%LOCALAPPDATA%\Palo Alto Networks" >>"%LOG%"
        rd /s /q "%LOCALAPPDATA%\Palo Alto Networks" >>"%LOG%" 2>&1
    )
) else (
    if exist "C:\Users\%USERNAME%\AppData\Local\Palo Alto Networks" (
        echo rd /s /q "C:\Users\%USERNAME%\AppData\Local\Palo Alto Networks" >>"%LOG%"
        rd /s /q "C:\Users\%USERNAME%\AppData\Local\Palo Alto Networks" >>"%LOG%" 2>&1
    )
)

call :log "Ensuring processes are terminated"
echo taskkill /im pangpa.exe /f /t >>"%LOG%" & taskkill /im pangpa.exe /f /t >>"%LOG%" 2>&1
echo taskkill /im pangps.exe /f /t >>"%LOG%" & taskkill /im pangps.exe /f /t >>"%LOG%" 2>&1

call :log "Deleting registry keys (errors are expected if keys are absent)"

rem --- Product/driver related keys
echo reg delete "HKLM\SOFTWARE\Palo Alto Networks\GlobalProtect\PanGPS" /f >>"%LOG%"
reg delete "HKLM\SOFTWARE\Palo Alto Networks\GlobalProtect\PanGPS" /f >>"%LOG%" 2>&1

echo reg delete "HKLM\DRIVERS\DriverDatabase\DeviceIds\PanGpd" /f >>"%LOG%"
reg delete "HKLM\DRIVERS\DriverDatabase\DeviceIds\PanGpd" /f >>"%LOG%" 2>&1

echo reg delete "HKLM\DRIVERS\DriverDatabase\DriverInfFiles\oem71.inf" /f >>"%LOG%"
reg delete "HKLM\DRIVERS\DriverDatabase\DriverInfFiles\oem71.inf" /f >>"%LOG%" 2>&1

echo reg delete "HKLM\DRIVERS\DriverDatabase\DriverPackages\pangpd.inf_amd64_5c5d20b3e9562905" /f >>"%LOG%"
reg delete "HKLM\DRIVERS\DriverDatabase\DriverPackages\pangpd.inf_amd64_5c5d20b3e9562905" /f >>"%LOG%" 2>&1

rem --- PnP lockdown files
echo reg delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Setup\PnpLockdownFiles\%SystemRoot%\System32\DRIVERS\pangpd.sys" /f >>"%LOG%"
reg delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Setup\PnpLockdownFiles\%SystemRoot%\System32\DRIVERS\pangpd.sys" /f >>"%LOG%" 2>&1

echo reg delete "HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Setup\PnpLockdownFiles\%SystemRoot%\System32\DRIVERS\pangpd.sys" /f >>"%LOG%"
reg delete "HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Setup\PnpLockdownFiles\%SystemRoot%\System32\DRIVERS\pangpd.sys" /f >>"%LOG%" 2>&1

rem --- Class/Enum keys (ControlSet001)
for %%K in (
"HKLM\SYSTEM\ControlSet001\Control\Class\{4d36e972-e325-11ce-bfc1-08002be10318}\0015"
"HKLM\SYSTEM\ControlSet001\Control\DeviceClasses\{ad498944-762f-11d0-8dcb-00c04fc3358c}\##?#ROOT#NET#0000#{ad498944-762f-11d0-8dcb-00c04fc3358c}"
"HKLM\SYSTEM\ControlSet001\Control\DeviceClasses\{ad498944-762f-11d0-8dcb-00c04fc3358c}\##?#ROOT#NET#0000#{ad498944-762f-11d0-8dcb-00c04fc3358c}\#{9ED715EC-5A4A-4B7B-B63C-22B8B256B72F}"
"HKLM\SYSTEM\ControlSet001\Control\DeviceClasses\{ad498944-762f-11d0-8dcb-00c04fc3358c}\##?#ROOT#NET#0000#{ad498944-762f-11d0-8dcb-00c04fc3358c}\#{B897A75E-CA02-4D47-9DC9-E0F42D720B1D}"
"HKLM\SYSTEM\ControlSet001\Control\DeviceClasses\{cac88484-7515-4c03-82e6-71a87abac361}\##?#ROOT#NET#0000#{cac88484-7515-4c03-82e6-71a87abac361}"
"HKLM\SYSTEM\ControlSet001\Control\DeviceClasses\{cac88484-7515-4c03-82e6-71a87abac361}\##?#ROOT#NET#0000#{cac88484-7515-4c03-82e6-71a87abac361}\#"
"HKLM\SYSTEM\ControlSet001\Enum\ROOT\NET\0000"
"HKLM\SYSTEM\ControlSet001\Enum\ROOT\NET"
"HKLM\SYSTEM\ControlSet001\Services\PanGpd\Enum"
"HKLM\SYSTEM\ControlSet001\Services\PanGpd"
) do (
  echo reg delete %%~K /f >>"%LOG%"
  reg delete %%~K /f >>"%LOG%" 2>&1
)

rem --- Class/Enum keys (CurrentControlSet)
for %%K in (
"HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e972-e325-11ce-bfc1-08002be10318}\0015"
"HKLM\SYSTEM\CurrentControlSet\Control\DeviceClasses\{ad498944-762f-11d0-8dcb-00c04fc3358c}\##?#ROOT#NET#0000#{ad498944-762f-11d0-8dcb-00c04fc3358c}"
"HKLM\SYSTEM\CurrentControlSet\Control\DeviceClasses\{ad498944-762f-11d0-8dcb-00c04fc3358c}\##?#ROOT#NET#0000#{ad498944-762f-11d0-8dcb-00c04fc3358c}\#{9ED715EC-5A4A-4B7B-B63C-22B8B256B72F}"
"HKLM\SYSTEM\CurrentControlSet\Control\DeviceClasses\{ad498944-762f-11d0-8dcb-00c04fc3358c}\##?#ROOT#NET#0000#{ad498944-762f-11d0-8dcb-00c04fc3358c}\#{B897A75E-CA02-4D47-9DC9-E0F42D720B1D}"
"HKLM\SYSTEM\CurrentControlSet\Control\DeviceClasses\{cac88484-7515-4c03-82e6-71a87abac361}\##?#ROOT#NET#0000#{cac88484-7515-4c03-82e6-71a87abac361}"
"HKLM\SYSTEM\CurrentControlSet\Control\DeviceClasses\{cac88484-7515-4c03-82e6-71a87abac361}\##?#ROOT#NET#0000#{cac88484-7515-4c03-82e6-71a87abac361}\#"
"HKLM\SYSTEM\CurrentControlSet\Enum\ROOT\NET\0000"
"HKLM\SYSTEM\CurrentControlSet\Enum\ROOT\NET"
"HKLM\SYSTEM\CurrentControlSet\Services\PanGpd\Enum"
"HKLM\SYSTEM\CurrentControlSet\Services\PanGpd"
) do (
  echo reg delete %%~K /f >>"%LOG%"
  reg delete %%~K /f >>"%LOG%" 2>&1
)

rem --- Device Parameters subkeys (need quotes)
for %%K in (
"HKLM\SYSTEM\ControlSet001\Enum\ROOT\NET\0000\Device Parameters"
"HKLM\SYSTEM\CurrentControlSet\Enum\ROOT\NET\0000\Device Parameters"
) do (
  echo reg delete %%~K /f >>"%LOG%"
  reg delete %%~K /f >>"%LOG%" 2>&1
)

call :log "All cleanup steps attempted."

echo.
call :log "Press any key to restart the machine now (close this window to skip)."
pause >nul

call :log "Issuing restart: shutdown /r /t 0"
echo shutdown /r /t 0 >>"%LOG%"
shutdown /r /t 0

endlocal
