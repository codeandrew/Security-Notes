# Active Directory

Windows Active Directory environments by and large dominate the corporate and governmental world's organizational networking structure. Active Directory allows user and service interaction from machines within the domain, rather than individual workstations. A Domain Controller manages user accounts, services, networking shares, and more. In this section, users will learn about:

- Active Directory Basics
- Attacking Kerberos
- Exploiting a Domain Controller
- Post exploitation tasks

## Active Directory Basics
> https://tryhackme.com/room/winadbasics


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

