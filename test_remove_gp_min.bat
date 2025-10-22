@echo off
setlocal EnableExtensions EnableDelayedExpansion
set "D=%~dp0"
for /f %%I in ('powershell -NoP -C "(Get-Date).ToString(\"yyyyMMdd_HHmmss\")"') do set "S=%%I"
set "L=%D%remove-globalprotect_%S%.log"
set "TS=powershell -NoP -C \"$((Get-Date).ToString('yyyy-MM-dd HH:mm:ss'))\""
goto :main
:log
for /f %%I in ('%TS%') do set "N=%%I"
>>"%L%" echo [%N%] %~1
exit /b

:main
call :log "START"
echo Uninstall GP only when in office. Press Enter... & pause

call :log "KILL PROCESSES"
taskkill /im pangpa.exe /f /t >>"%L%" 2>&1
taskkill /im pangps.exe /f /t >>"%L%" 2>&1

call :log "UNINSTALL (WMIC)"
wmic product where "Name='GlobalProtect'" call uninstall /nointeractive >>"%L%" 2>&1
if errorlevel 1 wmic product where "Description='GlobalProtect'" call uninstall /nointeractive >>"%L%" 2>&1

call :log "PAUSE AFTER UNINSTALL" & pause

call :log "SERVICE REMOVE"
sc stop PanGPS >>"%L%" 2>&1
sc delete PanGPS >>"%L%" 2>&1

call :log "REMOVE FOLDERS"
if exist "C:\Program Files\Palo Alto Networks" rd /s /q "C:\Program Files\Palo Alto Networks" >>"%L%" 2>&1
if defined LOCALAPPDATA (
  if exist "%LOCALAPPDATA%\Palo Alto Networks" rd /s /q "%LOCALAPPDATA%\Palo Alto Networks" >>"%L%" 2>&1
) else (
  if exist "C:\Users\%USERNAME%\AppData\Local\Palo Alto Networks" rd /s /q "C:\Users\%USERNAME%\AppData\Local\Palo Alto Networks" >>"%L%" 2>&1
)

call :log "ENSURE PROCESSES DEAD"
taskkill /im pangpa.exe /f /t >>"%L%" 2>&1
taskkill /im pangps.exe /f /t >>"%L%" 2>&1

call :log "REG DELETE: PRODUCT/DRIVER"
reg delete "HKLM\SOFTWARE\Palo Alto Networks\GlobalProtect\PanGPS" /f >>"%L%" 2>&1
reg delete "HKLM\DRIVERS\DriverDatabase\DeviceIds\PanGpd" /f >>"%L%" 2>&1
reg delete "HKLM\DRIVERS\DriverDatabase\DriverInfFiles\oem71.inf" /f >>"%L%" 2>&1
reg delete "HKLM\DRIVERS\DriverDatabase\DriverPackages\pangpd.inf_amd64_5c5d20b3e9562905" /f >>"%L%" 2>&1
reg delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Setup\PnpLockdownFiles\%SystemRoot%\System32\DRIVERS\pangpd.sys" /f >>"%L%" 2>&1
reg delete "HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Setup\PnpLockdownFiles\%SystemRoot%\System32\DRIVERS\pangpd.sys" /f >>"%L%" 2>&1

call :log "REG DELETE: CONTROLSET001"
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
) do reg delete %%~K /f >>"%L%" 2>&1

call :log "REG DELETE: CURRENTCONTROLSET"
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
) do reg delete %%~K /f >>"%L%" 2>&1

call :log "REG DELETE: DEVICE PARAMETERS"
for %%K in (
"HKLM\SYSTEM\ControlSet001\Enum\ROOT\NET\0000\Device Parameters"
"HKLM\SYSTEM\CurrentControlSet\Enum\ROOT\NET\0000\Device Parameters"
) do reg delete %%~K /f >>"%L%" 2>&1

call :log "DONE"
echo Press any key to restart (close to skip). & pause >nul
call :log "RESTART"
shutdown /r /t 0
endlocal
