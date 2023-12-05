# Hacking With PowerShell
> https://tryhackme.com/room/powershell

Powershell is the Windows Scripting Language and shell environment built using the .NET framework.

This also allows Powershell to execute .NET functions directly from its shell. Most Powershell commands, called cmdlets, are written in .NET. Unlike other scripting languages and shell environments, the output of these cmdlets are objects - making Powershell somewhat object-oriented.

This also means that running cmdlets allows you to perform actions on the output object (which makes it convenient to pass output from one cmdlet to another). The normal format of a cmdlet is represented using Verb-Noun; for example, the cmdlet to list commands is called Get-Command

Common verbs to use include:
- Get
- Start
- Stop 
- Read
- Write
- New
- Out

References:
- https://docs.microsoft.com/en-us/powershell/scripting/developer/cmdlet/approved-verbs-for-windows-powershell-commands?view=powershell-7

```
New vs. Add
Use the New verb to create a new resource. Use the Add to add something to an existing container or resource. For example, Add-Content adds output to an existing file.

New vs. Set
Use the New verb to create a new resource. Use the Set verb to modify an existing resource, optionally creating it if it does not exist, such as the Set-Variable cmdlet.

Find vs. Search
Use the Find verb to look for an object. Use the Search verb to create a reference to a resource in a container.

Get vs. Read
Use the Get verb to obtain information about a resource (such as a file) or to obtain an object with which you can access the resource in future. Use the Read verb to open a resource and extract information contained within.

Invoke vs. Start
Use the Invoke verb to perform synchronous operations, such as running a command and waiting for it to end. Use the Start verb to begin asynchronous operations, such as starting an autonomous process.

Ping vs. Test
Use the Test verb.
```


## Basic PowerShell Commands

**Using Get-Help**

Get-Help displays information about a cmdlet. To get help with a particular command, run the following:

Get-Help Command-Name

You can also understand how exactly to use the command by passing in the -examples flag. This would return output like the following: 

```powershell
PS C:\Users\Administrator> Get-Help Get-Command -Examples

NAME
    Get-Command

SYNOPSIS
Gets all commands.

Example 1: Get cmdlets, functions, and aliases

PS C:\>Get-Command

```

**Using Get-Command**  

Get-Command gets all the cmdlets installed on the current Computer. The great thing about this cmdlet is that it allows for pattern matching like the following

Get-Command Verb-* or Get-Command *-Noun

Running Get-Command New-* to view all the cmdlets for the verb new displays the following: 


**Object Manipulation**  

In the previous task, we saw how the output of every cmdlet is an object. If we want to manipulate the output, we need to figure out a few things:

passing the output to other cmdlets
using specific object cmdlets to extract information
The Pipeline(|) is used to pass output from one cmdlet to another. A major difference compared to other shells is that Powershell passes an object to the next cmdlet instead of passing text or string to the command after the pipe. Like every object in object-oriented frameworks, an object will contain methods and properties.

You can think of methods as functions that can be applied to output from the cmdlet, and you can think of properties as variables in the output from a cmdlet. To view these details, pass the output of a cmdlet to the Get-Member cmdlet:

Verb-Noun | Get-Member 

An example of running this to view the members for Get-Command is:

Get-Command | Get-Member -MemberType Method

> Using pipe (|) to pass output from one cmdlet to another  

```ps1
PS C:\Users\Administrator> Get-Command | Get-Member -MemberType Method


   TypeName: System.Management.Automation.AliasInfo

Name             MemberType Definition
----             ---------- ----------
Equals           Method     bool Equals(System.Object obj)
GetHashCode      Method     int GetHashCode()
GetType          Method     type GetType()
ResolveParameter Method     System.Management.Automation.ParameterMetadata ResolveParameter(string name)
ToString         Method     string ToString()


   TypeName: System.Management.Automation.FunctionInfo

Name             MemberType Definition
----             ---------- ----------
Equals           Method     bool Equals(System.Object obj)
GetHashCode      Method     int GetHashCode()
GetType          Method     type GetType()
ResolveParameter Method     System.Management.Automation.ParameterMetadata ResolveParameter(string name)
ToString         Method     string ToString()


   TypeName: System.Management.Automation.CmdletInfo

Name             MemberType Definition
----             ---------- ----------
Equals           Method     bool Equals(System.Object obj)
GetHashCode      Method     int GetHashCode()
GetType          Method     type GetType()
ResolveParameter Method     System.Management.Automation.ParameterMetadata ResolveParameter(string name)
ToString         Method     string ToString()


PS C:\Users\Administrator>
```

**Creating Objects From Previous cmdlets**

One way of manipulating objects is pulling out the properties from the output of a cmdlet and creating a new object. This is done using the Select-Object cmdlet. 

Here's an example of listing the directories and just selecting the mode and the name:

```
PS C:\Users\Administrator> Get-ChildItem | Select-Object -Property Mode, Name
Mode   Name
----   ----
d-r--- Contacts
d-r--- Desktop
d-r--- Documents
d-r--- Downloads
d-r--- Favorites
d-r--- Links
d-r--- Music
d-r--- Pictures
d-r--- Saved Games
d-r--- Searches
d-r--- Videos

PS C:\Users\Administrator>
```

You can also use the following flags to select particular information:

- first - gets the first x object
- last - gets the last x object
- unique - shows the unique objects
- skip - skips x objects

**Filtering Objects**

When retrieving output objects, you may want to select objects that match a very specific value. You can do this using the Where-Object to filter based on the value of properties. 



**EXERCISE**
```powershell
# Find Item
Get-ChildItem -Path C:\ -Include *interesting-file.txt* -File -Recurse -ErrorAction SilentlyContinue

# Get Contents
Get-Content "C:\Program Files\interesting-file.txt.txt"

# Get how many cmdlets are installed on the system(only cmdlets, not functions and aliases)
Get-Command | Where-Object -Property CommandType -eq Cmdlet | Measure-Object
Count    : 6638
Average  :
Sum      :
Maximum  :
Minimum  :
Property :

## NOTES
# In PowerShell, cmdlets are the built-in commands provided by PowerShell itself and by modules that have been loaded into the session. They are native PowerShell commands that are compiled into .NET classes and are designed to perform an action and return .NET objects. Cmdlets are one of the fundamental elements in PowerShell, enabling the bulk of the functional scripting capabilities.

# Using Get-Command with a Where-Object filter to select only objects of the type Cmdlet and then using Measure-Object to count them is a valid method to get the number of cmdlets installed on the system.


# Get the MD5 hash of interesting-file.txt
Get-FileHash -Path "C:\Program Files\interesting-file.txt.txt" -Algorithm MD5
Algorithm       Hash                                                                   Path
---------       ----                                                                   ----
MD5             49A586A2A9456226F8A1B4CEC6FAB329                                       C:\Program Files\interesting-file.txt.txt

# Does the path “C:\Users\Administrator\Documents\Passwords” Exist(Y/N)?
Get-Location -Path "C:\Users\Administrator\Documents\Passwords"

# What command would you use to make a request to a web server?
Invoke-WebRequest

# Base64 decode the file b64.txt on Windows.
Get-ChildItem -Path C:/ -Include b64.txt -Recurse -File
$base64Content = Get-Content -Path "b64.txt"
$decodedBytes = [System.Convert]::FromBase64String($base64Content)
$decodedString = [Text.Encoding]::UTF8.GetString($decodedBytes)
$decodedString | Out-File -FilePath "decodedOutput.txt"
type .\decodedOutput.txt

this is the flag - ihopeyoudidthisonwindows
the rest is garbage
the rest is garbage
the rest is garbage
the rest is garbage
the rest is garbage
the rest is garbage
the rest is garbage
the rest is garbage
the rest is garbage
the rest is garbage
the rest is garbage
the rest is garbage
the rest is garbage
the rest is garbage
```

## Enumeration
```ps1
#1 How many users are there on the machine?
Get-LocalUser

#2 Which local user does this SID(S-1–5–21–1394777289–3961777894–1791813945–501) belong to?
Get-LocalUser -SID "S-1-5-21-1394777289-3961777894-1791813945-501"

#3 How many users have their password required values set to False?
Get-LocalUser | Where-Object -Property PasswordRequired -Match false

#4 How many local groups exist?
Get-LocalGroup | measure

#5 What command did you use to get the IP address info?
Get-NetIPAddress

#6 How many ports are listed as listening?
Get-NetTCPConnection | Where-Object -Property State -Match Listen | measure

#7 What is the remote address of the local port listening on port 445?
Get-NetTCPConnection | Where-Object -Property State -Match Listen

#8 How many patches have been applied?
Get-Hotfix | measure

#9 When was the patch with ID KB4023834 installed?
Get-Hotfix -Id KB4023834

#10 Find the contents of a backup file.
Get-ChildItem -Path C:\ -Include *.bak* -File -Recurse -ErrorAction SilentlyContinue
Get-Content "C:\Program Files (x86)\Internet Explorer\passwords.bak.txt"

#11 Search for all files containing API_KEY
Get-ChildItem C:\* -Recurse | Select-String -pattern API_KEY

#12 What command do you do to list all the running processes?
Get-Process

#13 What is the path of the scheduled task called new-sched-task?
Get-ScheduledTask -TaskName "new-sched-task" 
Get-ScheduledTask -TaskName "new-sched-task" | Select-Object -Property TaskPath, TaskName

#14 Who is the owner of the C:\
Get-Acl c:/

```

## Basic Scripting
```ps1
# This is an example script that checks the active ports if its inside the port.txt
$system_ports = Get-NetTCPConnection -State Listen

$text_port = Get-Content -Path C:\Users\Administrator\Desktop\ports.txt

foreach($port in $text_port){

    if($port -in $system_ports.LocalPort){
        echo $port
     }

}
```

The exercise is to find string that looks for the pattern "password"
```ps1
$path = "C:\Users\Administrator\Desktop\emails\*"
$string_pattern = "password"
$command = Get-ChildItem -Path $path -Recurse | Select-String -Pattern $string_pattern
echo $command
```

next excercise is to look for strings with `https://`
```ps1

$path = "C:\Users\Administrator\Desktop\emails\*"
$string_pattern = "https://"
$command = Get-ChildItem -Path $path -Recurse | Select-String -Pattern $string_pattern
echo $command

```
## Intermediate Scripting

Now that you've learnt a little bit about how scripting works - let's try something a bit more interesting. Sometimes we may not have utilities like Nmap and Python available, and we are forced to write scripts to do very rudimentary tasks.

Why don't you try writing a simple port scanner using Powershell? Here's the general approach to use: 

Determine IP ranges to scan(in this case it will be localhost) and you can provide the input in any way you want
Determine the port ranges to scan
Determine the type of scan to run(in this case it will be a simple TCP Connect Scan)

```ps1
# simplest sweep
for($i=130; $i -le 140; $i++){
    Test-NetConnection localhost -Port $i
}
```
or 

```ps1
function Test-Port {
    param (
        [Parameter(Mandatory = $true)]
        [string]
        $IPAddress,

        [Parameter(Mandatory = $true)]
        [int]
        $Port,

        [int]
        $Timeout = 1000
    )

    $connection = New-Object System.Net.Sockets.TcpClient
    try {
        $asyncResult = $connection.BeginConnect($IPAddress, $Port, $null, $null)
        $waitHandle = $asyncResult.AsyncWaitHandle
        $result = $waitHandle.WaitOne($Timeout)
        $connection.Close()

        if ($result) { return $true } else { return $false }
    } catch {
        return $false
    }
}

# Define IP range and port range
$IPAddress = "127.0.0.1"  # localhost
$StartPort = 130
$EndPort = 140

# Scanning
$StartPort..$EndPort | ForEach-Object {
    $port = $_
    $result = Test-Port -IPAddress $IPAddress -Port $port
    if ($result) {
        "Port $port is open"
    } else {
        "Port $port is closed"
    }
}
```

## References
- https://learnxinyminutes.com/docs/powershell/