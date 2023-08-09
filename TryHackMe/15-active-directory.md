# Active Directory

Windows Active Directory environments by and large dominate the corporate and governmental world's organizational networking structure. Active Directory allows user and service interaction from machines within the domain, rather than individual workstations. A Domain Controller manages user accounts, services, networking shares, and more. In this section, users will learn about:

- Active Directory Basics
- Attacking Kerberos
- Exploiting a Domain Controller
- Post exploitation tasks

## Active Directory Basics
> https://tryhackme.com/room/winadbasics
 
In this room, we will learn about Active Directory and will become familiar with the following topics

What Active Directory is
What an Active Directory Domain is
What components go into an Active Directory Domain
Forests and Domain Trust
And much more!
### Windows Domain

Windows domain is a group of users and computers under the administration of a given business. The main idea behind a domain is to centralise the administration of common components of a Windows computer network in a single repository called Active Directory (AD). The server that runs the Active Directory services is known as a Domain Controller (DC).

![active_directotry](./media/15-ad.png)

The main advantages of having a configured Windows domain are:

Centralised identity management: All users across the network can be configured from Active Directory with minimum effort.
Managing security policies: You can configure security policies directly from Active Directory and apply them to users and computers across the network as needed.

**Take Aways:**
Credentials are stored in a centralised repository called Active Directory




Active Directory (AD) is a catalog of network "objects". It includes:
1. **Users**: Represents individuals or services. They're "security principals" - objects that can be authenticated and assigned network privileges. 
   Example: "JohnDoe" represents an employee; "MSSQLSvc" represents the SQL Server service.

2. **Machines**: Each computer in the AD domain is a "machine". It's also a security principal and has an account with local administrative rights. 
   Example: If a computer is named "DC01", its machine account is "DC01$".

3. **Security Groups**: Collections of users or machines. It's easier to manage permissions by assigning them to groups instead of individual users.
   Example: The "Domain Admins" group has administrative rights across the domain.

### Managing AD Users


Open `Active Directory Users And Computer`
in nav, click view, click `Advanced Features`

IN THM Users 
Delegate Control to Phillip
Reset Passwords

windows RDP to IP: 10.10.10.10

user: THM\phillip
password: 

powershell change other user password
```pwsh
PS C:\Users\phillip> Set-ADAccountPassword sophie -Reset -NewPassword (Read-Host -AsSecureString -Prompt 'New Password') -Verbose

New Password: *********

VERBOSE: Performing the operation "Set-ADAccountPassword" on target "CN=Sophie,OU=Sales,OU=THM,DC=thm,DC=local".
```
powershell change password on login
```
PS C:\Users\phillip> Set-ADUser -ChangePasswordAtLogon $true -Identity sophie -Verbose

VERBOSE: Performing the operation "Set" on target "CN=Sophie,OU=Sales,OU=THM,DC=thm,DC=local".
```

### Managing AD Computers


## Breachin Active Directory

## Enumerating Active Directory

## Lateral Movement and Pivoting 

## Exploiting Active Directory 

## Persisting Active Directory

## Credential Harvesting

