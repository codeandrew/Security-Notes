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

## Breachin Active Directory

## Enumerating Active Directory

## Lateral Movement and Pivoting 

## Exploiting Active Directory 

## Persisting Active Directory

## Credential Harvesting

