@echo off
setlocal enabledelayedexpansion

echo =====================================================
echo Uninstall GP ONLY when user is in the office.
echo Press Enter to continue if the user is in the office...
echo =====================================================
pause

echo.
echo ===== Stopping GlobalProtect processes =====
taskkill /im pangpa.exe /f /t >nul 2>&1
taskkill /im pangps.exe /f /t >nul 2>&1

echo.
echo ===== Uninstalling GlobalProtect (WMIC) =====
REM Note: WMIC is deprecated on newer Windows, but this still works on many builds.
REM If your product name differs, try Name='GlobalProtect' or Description='GlobalProtect'
wmic product where "Name='GlobalProtect'" call uninstall /nointeractive >nul 2>&1
if errorlevel 1 (
    wmic product where "Description='GlobalProtect'" call uninstall /nointeractive >nul 2>&1
)

echo.
echo ===== Waiting for uninstall to settle - press Enter to continue =====
pause

echo.
echo ===== Removing service PanGPS =====
sc stop PanGPS >nul 2>&1
sc delete PanGPS >nul 2>&1

echo.
echo ===== Removing folders =====
REM Program Files
if exist "C:\Program Files\Palo Alto Networks" rd /s /q "C:\Program Files\Palo Alto Networks"

REM Per-user LocalAppData
if defined LOCALAPPDATA (
    if exist "%LOCALAPPDATA%\Palo Alto Networks" rd /s /q "%LOCALAPPDATA%\Palo Alto Networks"
) else (
    if exist "C:\Users\%USERNAME%\AppData\Local\Palo Alto Networks" rd /s /q "C:\Users\%USERNAME%\AppData\Local\Palo Alto Networks"
)

REM Try once more to ensure processes are gone
taskkill /im pangpa.exe /f /t >nul 2>&1
taskkill /im pangps.exe /f /t >nul 2>&1

echo.
echo ===== Deleting registry keys (ignoring errors) =====

REM Use quoted roots and paths; /f = force; errors are ignored so the script continues.

REM Product/driver related keys
reg delete "HKLM\SOFTWARE\Palo Alto Networks\GlobalProtect\PanGPS" /f >nul 2>&1
reg delete "HKLM\DRIVERS\DriverDatabase\DeviceIds\PanGpd" /f >nul 2>&1
reg delete "HKLM\DRIVERS\DriverDatabase\DriverInfFiles\oem71.inf" /f >nul 2>&1
reg delete "HKLM\DRIVERS\DriverDatabase\DriverPackages\pangpd.inf_amd64_5c5d20b3e9562905" /f >nul 2>&1

REM PnP lockdown files (use backslashes, not slashes)
reg delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Setup\PnpLockdownFiles\%SystemRoot%\System32\DRIVERS\pangpd.sys" /f >nul 2>&1
reg delete "HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Setup\PnpLockdownFiles\%SystemRoot%\System32\DRIVERS\pangpd.sys" /f >nul 2>&1

REM Class/Enum keys (ControlSet001)
reg delete "HKLM\SYSTEM\ControlSet001\Control\Class\{4d36e972-e325-11ce-bfc1-08002be10318}\0015" /f >nul 2>&1
reg delete "HKLM\SYSTEM\ControlSet001\Control\DeviceClasses\{ad498944-762f-11d0-8dcb-00c04fc3358c}\##?#ROOT#NET#0000#{ad498944-762f-11d0-8dcb-00c04fc3358c}" /f >nul 2>&1
reg delete "HKLM\SYSTEM\ControlSet001\Control\DeviceClasses\{ad498944-762f-11d0-8dcb-00c04fc3358c}\##?#ROOT#NET#0000#{ad498944-762f-11d0-8dcb-00c04fc3358c}\#{9ED715EC-5A4A-4B7B-B63C-22B8B256B72F}" /f >nul 2>&1
reg delete "HKLM\SYSTEM\ControlSet001\Control\DeviceClasses\{ad498944-762f-11d0-8dcb-00c04fc3358c}\##?#ROOT#NET#0000#{ad498944-762f-11d0-8dcb-00c04fc3358c}\#{B897A75E-CA02-4D47-9DC9-E0F42D720B1D}" /f >nul 2>&1
reg delete "HKLM\SYSTEM\ControlSet001\Control\DeviceClasses\{cac88484-7515-4c03-82e6-71a87abac361}\##?#ROOT#NET#0000#{cac88484-7515-4c03-82e6-71a87abac361}" /f >nul 2>&1
reg delete "HKLM\SYSTEM\ControlSet001\Control\DeviceClasses\{cac88484-7515-4c03-82e6-71a87abac361}\##?#ROOT#NET#0000#{cac88484-7515-4c03-82e6-71a87abac361}\#" /f >nul 2>&1
reg delete "HKLM\SYSTEM\ControlSet001\Enum\ROOT\NET\0000" /f >nul 2>&1
reg delete "HKLM\SYSTEM\ControlSet001\Enum\ROOT\NET" /f >nul 2>&1
reg delete "HKLM\SYSTEM\ControlSet001\Services\PanGpd\Enum" /f >nul 2>&1
reg delete "HKLM\SYSTEM\ControlSet001\Services\PanGpd" /f >nul 2>&1

REM Class/Enum keys (CurrentControlSet)
reg delete "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e972-e325-11ce-bfc1-08002be10318}\0015" /f >nul 2>&1
reg delete "HKLM\SYSTEM\CurrentControlSet\Control\DeviceClasses\{ad498944-762f-11d0-8dcb-00c04fc3358c}\##?#ROOT#NET#0000#{ad498944-762f-11d0-8dcb-00c04fc3358c}" /f >nul 2>&1
reg delete "HKLM\SYSTEM\CurrentControlSet\Control\DeviceClasses\{ad498944-762f-11d0-8dcb-00c04fc3358c}\##?#ROOT#NET#0000#{ad498944-762f-11d0-8dcb-00c04fc3358c}\#{9ED715EC-5A4A-4B7B-B63C-22B8B256B72F}" /f >nul 2>&1
reg delete "HKLM\SYSTEM\CurrentControlSet\Control\DeviceClasses\{ad498944-762f-11d0-8dcb-00c04fc3358c}\##?#ROOT#NET#0000#{ad498944-762f-11d0-8dcb-00c04fc3358c}\#{B897A75E-CA02-4D47-9DC9-E0F42D720B1D}" /f >nul 2>&1
reg delete "HKLM\SYSTEM\CurrentControlSet\Control\DeviceClasses\{cac88484-7515-4c03-82e6-71a87abac361}\##?#ROOT#NET#0000#{cac88484-7515-4c03-82e6-71a87abac361}" /f >nul 2>&1
reg delete "HKLM\SYSTEM\CurrentControlSet\Control\DeviceClasses\{cac88484-7515-4c03-82e6-71a87abac361}\##?#ROOT#NET#0000#{cac88484-7515-4c03-82e6-71a87abac361}\#" /f >nul 2>&1
reg delete "HKLM\SYSTEM\CurrentControlSet\Enum\ROOT\NET\0000" /f >nul 2>&1
reg delete "HKLM\SYSTEM\CurrentControlSet\Enum\ROOT\NET" /f >nul 2>&1
reg delete "HKLM\SYSTEM\CurrentControlSet\Services\PanGpd\Enum" /f >nul 2>&1
reg delete "HKLM\SYSTEM\CurrentControlSet\Services\PanGpd" /f >nul 2>&1

REM Device Parameters subkey needs quotes due to the space
reg delete "HKLM\SYSTEM\ControlSet001\Enum\ROOT\NET\0000\Device Parameters" /f >nul 2>&1
reg delete "HKLM\SYSTEM\CurrentControlSet\Enum\ROOT\NET\0000\Device Parameters" /f >nul 2>&1

echo.
echo =====================================================
echo Press any key to restart the machine now.
echo (You can close this window to skip the restart.)
echo =====================================================
pause >nul

shutdown /r /t 0
endlocal
