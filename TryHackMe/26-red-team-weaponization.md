# Red Team Weaponization
> https://tryhackme.com/room/weaponization

![weapon](media/26-red-team-weapon.png)

Weaponization is the second stage of the Cyber Kill Chain model. In this stage, the attacker generates and develops their own malicious code using deliverable payloads such as word documents, PDFs, etc

The weaponization stage aims to use the malicious weapon to exploit the target machine and gain initial access.

Most organizations have Windows OS running, which is going to be a likely target. An organization's environment policy often blocks downloading and executing .exe files to avoid security violations. Therefore, red teamers rely upon building custom payloads sent via various channels such as phishing campaigns, social engineering, browser or software exploitation, USB, or web methods.

Most organizations block or monitor the execution of **.exe** files within their controlled environment. For that reason, red teamers rely on executing payloads using other techniques, such as built-in windows scripting technologies. Therefore, this task focuses on various popular and effective scripting techniques, including:

- The Windows Script Host (WSH)
- An HTML Application (HTA)
- Visual Basic Applications (VBA)
- PowerShell (PSH)

**CyberKill Chain**
https://www.lockheedmartin.com/en-us/capabilities/cyber/cyber-kill-chain.html

**Red Team Toolkit**:
https://github.com/infosecn1nja/Red-Teaming-Toolkit#Payload%20Development


Now let's try hacking that windows
```bash
# first access the Windows Machine
xfreerdp /v:10.10.17.249 /u:thm /p:TryHackM3 +clipboard
```
## Windows Scripting Host ( WSH )

Windows scripting host is a built-in Windows administration tool that runs batch files to automate and manage tasks within the operating system.

It is a Windows native engine, cscript.exe (for command-line scripts) and wscript.exe (for UI scripts), which are responsible for executing various Microsoft Visual Basic Scripts (VBScript), including vbs and vbe. For more information about VBScript, please visit here. It is important to note that the VBScript engine on a Windows operating system runs and executes applications with the same level of access and permission as a regular user; therefore, it is useful for the red teamers.

Now let's write a simple VBScript code to create a windows message box that shows the Welcome to THM message. Make sure to save the following code into a file, for example, hello.vbs.



hello.vbs
```vb
Dim message 
message = "Welcome to THM"
MsgBox message
```

Now let's use the VBScript to run executable files. The following vbs code is to invoke the Windows calculator, proof that we can execute .exe files using the Windows native engine (WSH).

calculator.vbs
```vb
Set shell = WScript.CreateObject("Wscript.Shell")
shell.Run("C:\Windows\System32\calc.exe " & WScript.ScriptFullName),0,True
' Ways to execute
' wscript calculator.vbs
' cscript calculator.vbs
```

Another trick. If the VBS files are blacklisted, then we can rename the file to .txt file and run it using wscript as follows,

```cmd
c:\Windows\System32>wscript /e:VBScript c:\Users\thm\Desktop\payload.txt
```