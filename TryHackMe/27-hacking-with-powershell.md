# Hacking With PowerShell

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




