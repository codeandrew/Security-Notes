@echo off
setlocal enabledelayedexpansion

:PrintHeader
echo.
echo ===================================================
echo %1
echo ===================================================
goto :eof

:ListHotFixes
call :PrintHeader "List of HotFixes"
wmic qfe get Caption,Description,HotFixID,InstalledOn | more

:: Check for possible exploits
set expl=no
for /f "tokens=3-9" %%a in ('systeminfo') do (
    ECHO."%%a %%b %%c %%d %%e %%f %%g" | findstr /i "2000 XP 2003 2008 vista" && set expl=yes
) & (
    ECHO."%%a %%b %%c %%d %%e %%f %%g" | findstr /i /C:"windows 7" && set expl=yes
)

:: Check for missing patches
if "%expl%" == "yes" (
    echo.
    echo Possible exploits (https://github.com/codingo/OSCP-2/blob/master/Windows/WinPrivCheck.bat)
    call :CheckPatch "KB2592799" "MS11-080"
    call :CheckPatch "KB3143141" "MS16-032"
    call :CheckPatch "KB2393802" "MS11-011"
    call :CheckPatch "KB982799" "MS10-059"
    ...
    call :CheckPatch "KB2870008" "MS13-081"
)

echo.

:DateAndTime
call :PrintHeader "Date and Time"
echo You may need to adjust your local date/time to exploit some vulnerability
date /T
time /T
echo.

:AuditSettings
call :PrintHeader "Audit Settings"
echo Check what is being logged
REG QUERY HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\Audit 2>nul
echo.

:WEFSettings
call :PrintHeader "WEF Settings"
echo Check where are being sent the logs
REG QUERY HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\EventLog\EventForwarding\SubscriptionManager 2>nul
echo.

goto :eof

:CheckPatch
wmic qfe get Caption,Description,HotFixID,InstalledOn | findstr /C:"%1" >nul
if errorlevel 1 echo %2 patch is NOT installed! (Vulns: ...)
goto :eof

######## 2nd batch

:FilePermissions
CALL :ColorLine " %E%33m[+]%E%97m FILE PERMISSIONS OF RUNNING PROCESSES"
ECHO.   [i] Checking file permissions of running processes (File backdooring - maybe the same files start automatically when Administrator logs in)
for /f "tokens=2 delims='='" %%x in ('wmic process list full^|find /i "executablepath"^|find /i /v "system32"^|find ":"') do (
    for /f eol^=^"^ delims^=^" %%z in ('ECHO.%%x') do (
        icacls "%%z" 2>nul | findstr /i "(F) (M) (W) :\\" | findstr /i ":\\ everyone authenticated users todos %username%" && ECHO.
    )
)
ECHO.

:DirPermissions
CALL :ColorLine " %E%33m[+]%E%97m DIRECTORY PERMISSIONS OF RUNNING PROCESSES"
ECHO.   [i] Checking directory permissions of running processes (DLL injection)
for /f "tokens=2 delims='='" %%x in ('wmic process list full^|find /i "executablepath"^|find /i /v "system32"^|find ":"') do for /f eol^=^"^ delims^=^" %%y in ('ECHO.%%x') do (
    icacls "%%~dpy\" 2>nul | findstr /i "(F) (M) (W) :\\" | findstr /i ":\\ everyone authenticated users todos %username%" && ECHO.
)
ECHO.
CALL :T_Progress 3

:ColorLine
echo %* | findstr /v /a:%1 /r "^$" | findstr /a:%1 /r "^.*$" > "%temp%\colorline.tmp"
findstr /f:"%temp%\colorline.tmp" /a:%1 /r "^$" "%temp%\colorline.tmp" > nul
type "%temp%\colorline.tmp" && ECHO. && ECHO.
del "%temp%\colorline.tmp"
exit /b

:T_Progress
set /a "dots=%1"
for /l %%i in (1,1,%dots%) do echo. & set /p "=."
echo.
exit /b

###### 3rd batch 

@echo off
SETLOCAL ENABLEDELAYEDEXPANSION

:: ColorLine function definition
:ColorLine
echo %* | findstr /v /a:%1 /r "^"
echo.
GOTO :EOF

:: Progress function definition
:T_Progress
ping localhost -n %1 >nul
GOTO :EOF

:: AlwaysInstallElevated check
:AlwaysInstallElevated
CALL :ColorLine " %E%33m[+]%E%97m AlwaysInstallElevated?"
ECHO.   [i] If '1' then you can install a .msi file with admin privileges ;)
ECHO.   [?] https://book.hacktricks.xyz/windows-hardening/windows-local-privilege-escalation#alwaysinstallelevated
reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated 2> nul
reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated 2> nul
ECHO.
CALL :T_Progress 2

:: Network Shares
:NetworkShares
CALL :ColorLine "%E%32m[*]%E%97m NETWORK"
CALL :ColorLine " %E%33m[+]%E%97m CURRENT SHARES"
net share
ECHO.
CALL :T_Progress 1

:: Network Interfaces
:NetworkInterfaces
CALL :ColorLine " %E%33m[+]%E%97m INTERFACES"
ipconfig /all
ECHO.
CALL :T_Progress 1

:: Network Used Ports
:NetworkUsedPorts
CALL :ColorLine " %E%33m[+]%E%97m USED PORTS"
ECHO.   [i] Check for services restricted from the outside
netstat -ano | findstr /i listen
ECHO.
CALL :T_Progress 1

:: Network Firewall
:NetworkFirewall
CALL :ColorLine " %E%33m[+]%E%97m FIREWALL"
netsh firewall show state
netsh firewall show config
ECHO.
CALL :T_Progress 2

:: ARP
:ARP
CALL :ColorLine " %E%33m[+]%E%97m ARP"
arp -A
ECHO.
CALL :T_Progress 1

:: Network Routes
:NetworkRoutes
CALL :ColorLine " %E%33m[+]%E%97m ROUTES"
route print
ECHO.
CALL :T_Progress 1

:: Windows Hosts File
:WindowsHostsFile
CALL :ColorLine " %E%33m[+]%E%97m Hosts file"
type C:\WINDOWS\System32\drivers\etc\hosts | findstr /v "^#"
CALL :T_Progress 1

:: DNS Cache
:DNSCache
CALL :ColorLine " %E%33m[+]%E%97m DNS CACHE"
ipconfig /displaydns | findstr "Record" | findstr "Name Host"
ECHO.
CALL :T_Progress 1

:: Wifi Creds
:WifiCreds
CALL :ColorLine " %E%33m[+]%E%97m WIFI"
for /f "tokens=4 delims=: " %%a in ('netsh wlan show profiles ^| find "Profile "') do (netsh wlan show profiles name=%%a key=clear | findstr "SSID Cipher Content" | find /v "Number" & ECHO.)
CALL :T_Progress 1

:end

#### 4th batch 