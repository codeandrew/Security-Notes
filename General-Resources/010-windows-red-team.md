# Windows Red Team


| Command    | Description                                                                                                                                                                       |
|------------|-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| ipconfig   | Display the IP configuration for all network interfaces. Example: ipconfig /all                                                                                                               |
| net        | A suite of commands for network settings and shares. Example: net user to list users.                                                                                                         |
| netstat    | Network statistics. Example: netstat -ano to display active TCP connections and process PID.                                                                                                  |
| nslookup   | Query the DNS server for domain name or IP address mapping. Example: nslookup example.com                                                                                                     |
| whoami     | Display the username and domain of the current user. Example: whoami                                                                                                                          |
| systeminfo | Display detailed configuration information about a computer and its operating system. Example: systeminfo                                                                                     |
| schtasks   | Schedule tasks to run periodically or at a specific time. Example: schtasks /create /tn TaskName /tr TaskRun /sc daily                                                                        |
| wmic       | Windows Management Instrumentation Command-line. Example: wmic process list brief lists details about all processes.                                                                          |
| gpresult   | Display the Resultant Set of Policy (RSoP) information for a remote user and computer. Example: gpresult /r                                                                                   |
| powershell | Starts a new PowerShell session. Example: powershell -exec bypass to start PowerShell with script execution policy bypassed.                                                                  |
| sc         | Service Control - manage Windows services. Example: sc query to display the status of services.                                                                                               |
| tasklist   | Lists all running tasks/processes. Example: tasklist                                                                                                                                          |
| taskkill   | Kill a running task/process. Example: taskkill /PID pid_number                                                                                                                                |
| reg        | Registry command that allows you to read from and write to the registry. Example: reg query HKLM\Software\Microsoft\Windows\CurrentVersion\Run to check all the programs that run at startup. |
| icacls     | Display or modify Access Control Lists (ACLs) for files and directories. Example: icacls C:\path\to\folder to display the ACLs.                                                               |
| netsh      | Network command to view or modify network configurations. Example: netsh wlan show profile to show saved WiFi profiles.                                                                       |

