# The Lay of the Land

It is essential to be familiar with the environment where you have initial access to a compromised machine during a red team engagement. Therefore, performing reconnaissance and enumeration is a significant part, and the primary goal is to gather as much information as possible to be used in the next stage. 

With an initial foothold established, the post-exploitation process begins! 

This room introduces commonly-used concepts, technologies, and security products that we need to be aware of.

In this room, the assumption is that we have already gained access to the machine, and we are ready to expand our knowledge more about the environment by performing enumerating for the following:

- Network infrastrucutre
- Active Directory Environment
- Users and Groups
- Host-based security solutions
- Network-based security solutions
- Applications and services


## RDP
```bash
brew install freerdp

xfreerdp /v:10.10.16.105 /u:kkid

# example
xfreerdp /u:ido.montekyo@domain /p:mypass /v:10.10.20.20 /cert-ignore /auto-reconnect-max-retries:0 /smart-sizing +clipboard /home-drive

/u:ido.montekyo@domain        --> User name @ domain
/p:mypass                     --> Your password
/v:10.10.20.20                --> Remote IP address or Hostname
/cert-ignore                  --> Ignore certificate issues
/auto-reconnect-max-retries:0 --> Auto Reconnect if needed
/smart-sizing                 --> Enable window resize
+clipboard                    --> Share the clipboard (copy-paste)
/home-drive                   --> Share/Expose my home directory

```


If you prefer to connect via RDP, make sure you deploy the AttackBox or connect to the VPN.
Use the following credentials: kkidd:Pass123321@.

```bash
user@machine$ xfreerdp /v:10.10.16.105 /u:kkidd
```

## Network Infrastructure

Once arriving onto an unknown network, our first goal is to identify where we are and what we can get to. During the red team engagement, we need to understand what target system we are dealing with, what service the machine provides, what kind of network we are in. Thus, the enumeration of the compromised machine after getting initial access is the key to answering these questions. This task will discuss the common types of networks we may face during the engagement.

Network segmentation is an extra layer of network security divided into multiple subnets. It is used to improve the security and management of the network. For example, it is used for preventing unauthorized access to corporate most valuable assets such as customer data, financial records, etc.

The Virtual Local Area Networks (VLANs) is a network technique used in network segmentation to control networking issues, such as broadcasting issues in the local network, and improve security. Hosts within the VLAN can only communicate with other hosts in the same VLAN network. 

If you want to learn more about network fundamentals, we suggest trying the following TryHackMe module: Network Fundamentals.

**Internal Networks**

Internal Networks are subnetworks that are segmented and separated based on the importance of the internal device or the importance of the accessibility of its data. The main purpose of the internal network(s) is to share information, faster and easier communications, collaboration tools, operational systems, and network services within an organization. In a corporate network, the network administrators intend to use network segmentation for various reasons, including controlling network traffic, optimizing network performance, and improving security posture. 

![0](./media/37-network.png)

The previous diagram is an example of the simple concept of network segmentation as the network is divided into two networks. The first one is for employee workstations and personal devices. The second is for private and internal network devices that provide internal services such as DNS, internal web, email services, etc.

**A Demilitarized Zone (DMZ)**

A DMZ Network is an edge network that protects and adds an extra security layer to a corporation's internal local-area network from untrusted traffic. A common design for DMZ is a subnetwork that sits between the public internet and internal networks.

Designing a network within the company depends on its requirements and need. For example, suppose a company provides public services such as a website, DNS, FTP, Proxy, VPN, etc. In that case, they may design a DMZ network to isolate and enable access control on the public network traffic, untrusted traffic.
![0](./media/37-dmz.png)


In the previous diagram, we represent the network traffic to the DMZ network in red color, which is untrusted ( comes directly from the internet). The green network traffic between the internal network is the controlled traffic that may go through one or more than one network security device(s).

Enumerating the system and the internal network is the discovering stage, which allows the attacker to learn about the system and the internal network. Based on the gained information, we use it to process lateral movement or privilege escalation to gain more privilege on the system or the AD environment.

```cmd
C:\Users\kkidd>netstat -na

Active Connections

  Proto  Local Address          Foreign Address        State
  TCP    0.0.0.0:80             0.0.0.0:0              LISTENING
  TCP    0.0.0.0:88             0.0.0.0:0              LISTENING
  TCP    0.0.0.0:135            0.0.0.0:0              LISTENING
  TCP    0.0.0.0:389            0.0.0.0:0              LISTENING
  TCP    0.0.0.0:445            0.0.0.0:0              LISTENING
  TCP    0.0.0.0:464            0.0.0.0:0              LISTENING
  TCP    0.0.0.0:593            0.0.0.0:0              LISTENING
  TCP    0.0.0.0:636            0.0.0.0:0              LISTENING
  TCP    0.0.0.0:2179           0.0.0.0:0              LISTENING
  TCP    0.0.0.0:3268           0.0.0.0:0              LISTENING
  TCP    0.0.0.0:3269           0.0.0.0:0              LISTENING
  TCP    0.0.0.0:3389           0.0.0.0:0              LISTENING
  TCP    0.0.0.0:5985           0.0.0.0:0              LISTENING
  TCP    0.0.0.0:7680           0.0.0.0:0              LISTENING
  TCP    0.0.0.0:9389           0.0.0.0:0              LISTENING
  TCP    0.0.0.0:13337          0.0.0.0:0              LISTENING
  TCP    0.0.0.0:47001          0.0.0.0:0              LISTENING
  TCP    0.0.0.0:49664          0.0.0.0:0              LISTENING
  TCP    0.0.0.0:49665          0.0.0.0:0              LISTENING
  TCP    0.0.0.0:49666          0.0.0.0:0              LISTENING
  TCP    0.0.0.0:49667          0.0.0.0:0              LISTENING
  TCP    0.0.0.0:49669          0.0.0.0:0              LISTENING
  TCP    0.0.0.0:49670          0.0.0.0:0              LISTENING
  TCP    0.0.0.0:49671          0.0.0.0:0              LISTENING
  TCP    0.0.0.0:49673          0.0.0.0:0              LISTENING
  TCP    0.0.0.0:49680          0.0.0.0:0              LISTENING
  TCP    0.0.0.0:49713          0.0.0.0:0              LISTENING
  TCP    0.0.0.0:49729          0.0.0.0:0              LISTENING
  TCP    0.0.0.0:49794          0.0.0.0:0              LISTENING
  TCP    10.10.16.105:53        0.0.0.0:0              LISTENING
  TCP    10.10.16.105:139       0.0.0.0:0              LISTENING
  TCP    10.10.16.105:3389      10.100.2.80:60874      ESTABLISHED
  TCP    10.10.16.105:49816     52.165.165.26:443      SYN_SENT
  TCP    127.0.0.1:53           0.0.0.0:0              LISTENING
  TCP    [::]:80                [::]:0                 LISTENING
  ...
   UDP    [::1]:56774            *:*
  UDP    [2001:0:14be:4c8:28a4:288b:f5f5:ef96]:88  *:*
  UDP    [2001:0:14be:4c8:28a4:288b:f5f5:ef96]:464  *:*
  UDP    [fe80::28a4:288b:f5f5:ef96%15]:88  *:*
  UDP    [fe80::28a4:288b:f5f5:ef96%15]:464  *:*
  UDP    [fe80::28a4:288b:f5f5:ef96%15]:546  *:*
  UDP    [fe80::4079:57b7:e593:e5cf%9]:53  *:*
  UDP    [fe80::4079:57b7:e593:e5cf%9]:88  *:*
  UDP    [fe80::4079:57b7:e593:e5cf%9]:464  *:*

C:\Users\kkidd>arp -a

Interface: 10.10.16.105 --- 0x9
  Internet Address      Physical Address      Type
  10.10.0.1             02-c8-85-b5-5a-aa     dynamic
  10.10.255.255         ff-ff-ff-ff-ff-ff     static
  224.0.0.22            01-00-5e-00-00-16     static
  224.0.0.251           01-00-5e-00-00-fb     static
  224.0.0.252           01-00-5e-00-00-fc     static
  255.255.255.255       ff-ff-ff-ff-ff-ff     static
```

commands
```cmd
netstat -na
arp -a
```

**Internal Network Services**

It provides private and internal network communication access for internal network devices. An example of network services is an internal DNS, web servers, custom applications, etc. It is important to note that the internal network services are not accessible outside the network. However, once we have initial access to one of the networks that access these network services, they will be reachable and available for communications. 

We will discuss more Windows applications and services in Task 9, including DNS and custom web applications.


## ACTIVE DIRECTORY ENVIRONMENT

Internal Network Services

It provides private and internal network communication access for internal network devices. An example of network services is an internal DNS, web servers, custom applications, etc. It is important to note that the internal network services are not accessible outside the network. However, once we have initial access to one of the networks that access these network services, they will be reachable and available for communications. 

We will discuss more Windows applications and services in Task 9, including DNS and custom web applications.

![0](./media/37-ad.png )

The diagram is one possible example of how Active Directory can be designed. The AD controller is placed in a subnet for servers (shown above as server network), and then the AD clients are on a separate network where they can join the domain and use the AD services via the firewall.

The following is a list of Active Directory components that we need to be familiar with:
- Domain Controllers
- Organizational Units
- AD objects
- AD Domains
- Forest
- AD Service Accounts: Built-in local users, Domain users, Managed service accounts
- Domain Administrators

A Domain Controller is a Windows server that provides Active Directory services and controls the entire domain. It is a form of centralized user management that provides encryption of user data as well as controlling access to a network, including users, groups, policies, and computers. It also enables resource access and sharing. These are all reasons why attackers target a domain controller in a domain because it contains a lot of high-value information.

![0](./media/37-domain-controller.png )

Organizational Units (OU's) are containers within the AD domain with a hierarchical structure.

Active Directory Objects can be a single user or a group, or a hardware component, such as a computer or printer. Each domain holds a database that contains object identity information that creates an AD environment, including:

- Users - A security principal that is allowed to authenticate to machines in the domain
- Computers - A special type of user accounts
- GPOs - Collections of policies that are applied to other AD objects
- AD domains are a collection of Microsoft components within an AD network. 

AD Forest is a collection of domains that trust each other. 
![0](./media/37-domain-forest.png)


For more information about the basics of Active Directory, we suggest trying the following TryHackMe room: Active Directory Basics.
> https://tryhackme.com/room/winadbasics

Once Initial Access has been achieved, finding an AD environment in a corporate network is significant as the Active Directory environment provides a lot of information to joined users about the environment. As a red teamer, we take advantage of this by enumerating the AD environment and gaining access to various details, which can then be used in the lateral movement stage.

```
PS C:\Users\thm> systeminfo | findstr Domain
OS Configuration:          Primary Domain Controller
Domain:                    thmdomain.com

```
![0](./media/37-pc-domain.png)


## Users and GroupS Management
In this task, we will learn more about users and groups, especially within the Active Directory. Gathering information about the compromised machine is essential that could be used in the next stage. Account discovery is the first step once we have gained initial access to the compromised machine to understand what we have and what other accounts are in the system. 

An Active Directory environment contains various accounts with the necessary permissions, access, and roles for different purposes. Common Active Directory service accounts include built-in local user accounts, domain user accounts, managed service accounts, and virtual accounts. 

- The built-in local users' accounts are used to manage the system locally, which is not part of the AD environment.
- Domain user accounts with access to an active directory environment can use the AD services (managed by AD).
- AD managed service accounts are limited domain user account with higher privileges to manage AD services.
- Domain Administrators are user accounts that can manage information in an Active Directory environment, including AD configurations, users, groups, permissions, roles, services, etc. One of the red team goals in engagement is to hunt for information that leads to a domain administrator having complete control over the AD environment.


The following are Active Directory Administrators accounts:
|   BUILTIN\Administrator   |          Local admin access on a domain controller         |
|:-------------------------:|:----------------------------------------------------------:|
|       Domain Admins       |    Administrative access to all resources in the domain    |
|     Enterprise Admins     |              Available only in the forest root             |
|       Schema Admins       | Capable of modifying domain/forest; useful for red teamers |
|      Server Operators     |                  Can manage domain servers                 |
|     Account Operators     |     Can manage users that are not in privileged groups     |

Now that we learn about various account types within the AD environment. Let's enumerate the Windows machine that we have access to during the initial access stage. As a current user, we have specific permissions to view or manage things within the machine and the AD environment. 

**Active Directory (AD) Enum**


```ps1
PS C:\Users\kkidd> Get-ADUser -Filter *


DistinguishedName : CN=Administrator,CN=Users,DC=thmredteam,DC=com
Enabled           : True
GivenName         :
Name              : Administrator
ObjectClass       : user
ObjectGUID        : 4094d220-fb71-4de1-b5b2-ba18f6583c65
SamAccountName    : Administrator
SID               : S-1-5-21-1966530601-3185510712-10604624-500
Surname           :
UserPrincipalName :

DistinguishedName : CN=Guest,CN=Users,DC=thmredteam,DC=com
GivenName         :
Name              : Guest
ObjectClass       : user
ObjectGUID        : e2c30114-37c2-4ab2-abd6-0e6c84753518
SamAccountName    : Guest
SID               : S-1-5-21-1966530601-3185510712-10604624-501
Surname           :
UserPrincipalName :

DistinguishedName : CN=krbtgt,CN=Users,DC=thmredteam,DC=com
Enabled           : False
GivenName         :
Name              : krbtgt
ObjectClass       : user
ObjectGUID        : 001ec69b-76a0-456a-b8bb-a5648f624a23
SamAccountName    : krbtgt
SID               : S-1-5-21-1966530601-3185510712-10604624-502
Surname           :
UserPrincipalName :

DistinguishedName : CN=Pierre Pittman,OU=THM,DC=thmredteam,DC=com
GivenName         : Pierre
Name              : Pierre Pittman
ObjectClass       : user
ObjectGUID        : 34febcdd-49dc-4160-b88e-7e6323f40dba
SamAccountName    : ppittman
SID               : S-1-5-21-1966530601-3185510712-10604624-1113
Surname           : Pittman
UserPrincipalName : ppittman@thmredteam.com

DistinguishedName : CN=Dario Philips,OU=THM,DC=thmredteam,DC=com
GivenName         : Dario
Name              : Dario Philips
ObjectClass       : user
ObjectGUID        : 3cc9cfc7-3c62-4d46-8a83-b8c02f45efbb
SamAccountName    : dphilips
SID               : S-1-5-21-1966530601-3185510712-10604624-1114
Surname           : Philips
UserPrincipalName : dphilips@thmredteam.com

DistinguishedName : CN=Weronika Burgess,OU=THM,DC=thmredteam,DC=com
GivenName         : Weronika
Name              : Weronika Burgess
ObjectClass       : user
ObjectGUID        : 88e2935a-2b50-4510-816d-8eab5b06f548
SamAccountName    : wburgess
SID               : S-1-5-21-1966530601-3185510712-10604624-1116
Surname           : Burgess
UserPrincipalName : wburgess@thmredteam.com

DistinguishedName : CN=Cecil Solomon,OU=THM,DC=thmredteam,DC=com
GivenName         : Cecil
Name              : Cecil Solomon
ObjectClass       : user
ObjectGUID        : 88ca7ae9-0f03-4956-8916-b0cbd985520c
SamAccountName    : csolomon
SID               : S-1-5-21-1966530601-3185510712-10604624-1120
Surname           : Solomon
UserPrincipalName : csolomon@thmredteam.com

DistinguishedName : CN=Kevin Kidd,OU=THM,DC=thmredteam,DC=com
Enabled           : True
GivenName         : Kevin
Name              : Kevin Kidd
ObjectClass       : user
ObjectGUID        : 42353060-b13d-48b4-af2f-70543e6ca8f8
SamAccountName    : kkidd
SID               : S-1-5-21-1966530601-3185510712-10604624-1122
Surname           : Kidd
UserPrincipalName : kkidd@thmredteam.com

DistinguishedName : CN=THMServiceUser,CN=Managed Service Accounts,DC=thmredteam,DC=com
GivenName         : THMServiceUser
Name              : THMServiceUser
ObjectClass       : user
ObjectGUID        : efca9543-aac2-48b3-b5ee-b36e274954a5
SamAccountName    : thmserviceuser_
SID               : S-1-5-21-1966530601-3185510712-10604624-1123
Surname           :
UserPrincipalName : thmserviceuser_@thmredteam.com

DistinguishedName : CN=THM Admin,OU=THM,DC=thmredteam,DC=com
Enabled           : True
GivenName         : THM
Name              : THM Admin
ObjectClass       : user
ObjectGUID        : 8974cd3d-9bf0-4c43-ac7d-068413fb462c
SamAccountName    : thmadmin
SID               : S-1-5-21-1966530601-3185510712-10604624-1124
Surname           : Admin
UserPrincipalName : thmadmin@thmredteam.com
```

We can also use the LDAP hierarchical tree structure to find a user within the AD environment. The Distinguished Name (DN) is a collection of comma-separated key and value pairs used to identify unique records within the directory. The DN consists of Domain Component (DC), OrganizationalUnitName (OU), Common Name (CN), and others. The following **"CN=User1,CN=Users,DC=thmredteam,DC=com"** is an example of DN, which can be visualized as follow:
> https://www.ietf.org/rfc/rfc2253.txt

![0](./media/37-dn.png  )

Using the SearchBase option, we specify a specific Common-Name CN in the active directory. For example, we can specify to list any user(s) that part of Users.


```

PS C:\Users\kkidd> Get-ADUser -Filter * -SearchBase "CN=Users,DC=THMREDTEAM,DC=COM"


DistinguishedName : CN=Administrator,CN=Users,DC=thmredteam,DC=com
Enabled           : True
GivenName         :
Name              : Administrator
ObjectClass       : user
ObjectGUID        : 4094d220-fb71-4de1-b5b2-ba18f6583c65
SamAccountName    : Administrator
SID               : S-1-5-21-1966530601-3185510712-10604624-500
Surname           :
UserPrincipalName :

DistinguishedName : CN=Guest,CN=Users,DC=thmredteam,DC=com
GivenName         :
Name              : Guest
ObjectClass       : user
ObjectGUID        : e2c30114-37c2-4ab2-abd6-0e6c84753518
SamAccountName    : Guest
SID               : S-1-5-21-1966530601-3185510712-10604624-501
Surname           :
UserPrincipalName :

DistinguishedName : CN=krbtgt,CN=Users,DC=thmredteam,DC=com
Enabled           : False
GivenName         :
Name              : krbtgt
ObjectClass       : user
ObjectGUID        : 001ec69b-76a0-456a-b8bb-a5648f624a23
SamAccountName    : krbtgt
SID               : S-1-5-21-1966530601-3185510712-10604624-502
Surname           :
UserPrincipalName :
```




commands
```
Get-ADUser  -Filter *
Get-ADUser -Filter * -SearchBase "CN=Users,DC=THMREDTEAM,DC=COM"

Get-ADUser -Filter * -SearchBase "OU=THM,DC=THMREDTEAM,DC=COM"
```


TASKS
Use the Get-ADUser -Filter * -SearchBase command to list the available user accounts within THM OU in the thmredteam.com domain. How many users are available?

```
PS C:\Users\kkidd> Get-ADUser -Filter * -SearchBase "OU=THM,DC=THMREDTEAM,DC=COM"


DistinguishedName : CN=Pierre Pittman,OU=THM,DC=thmredteam,DC=com
GivenName         : Pierre
Name              : Pierre Pittman
ObjectClass       : user
ObjectGUID        : 34febcdd-49dc-4160-b88e-7e6323f40dba
SamAccountName    : ppittman
SID               : S-1-5-21-1966530601-3185510712-10604624-1113
Surname           : Pittman
UserPrincipalName : ppittman@thmredteam.com

DistinguishedName : CN=Dario Philips,OU=THM,DC=thmredteam,DC=com
GivenName         : Dario
Name              : Dario Philips
ObjectClass       : user
ObjectGUID        : 3cc9cfc7-3c62-4d46-8a83-b8c02f45efbb
SamAccountName    : dphilips
SID               : S-1-5-21-1966530601-3185510712-10604624-1114
Surname           : Philips
UserPrincipalName : dphilips@thmredteam.com

DistinguishedName : CN=Weronika Burgess,OU=THM,DC=thmredteam,DC=com
GivenName         : Weronika
Name              : Weronika Burgess
ObjectClass       : user
ObjectGUID        : 88e2935a-2b50-4510-816d-8eab5b06f548
SamAccountName    : wburgess
SID               : S-1-5-21-1966530601-3185510712-10604624-1116
Surname           : Burgess
UserPrincipalName : wburgess@thmredteam.com

DistinguishedName : CN=Cecil Solomon,OU=THM,DC=thmredteam,DC=com
GivenName         : Cecil
Name              : Cecil Solomon
ObjectClass       : user
ObjectGUID        : 88ca7ae9-0f03-4956-8916-b0cbd985520c
SamAccountName    : csolomon
SID               : S-1-5-21-1966530601-3185510712-10604624-1120
Surname           : Solomon
UserPrincipalName : csolomon@thmredteam.com

DistinguishedName : CN=Kevin Kidd,OU=THM,DC=thmredteam,DC=com
Enabled           : True
GivenName         : Kevin
Name              : Kevin Kidd
ObjectClass       : user
ObjectGUID        : 42353060-b13d-48b4-af2f-70543e6ca8f8
SamAccountName    : kkidd
SID               : S-1-5-21-1966530601-3185510712-10604624-1122
Surname           : Kidd
UserPrincipalName : kkidd@thmredteam.com

DistinguishedName : CN=THM Admin,OU=THM,DC=thmredteam,DC=com
Enabled           : True
GivenName         : THM
Name              : THM Admin
ObjectClass       : user
ObjectGUID        : 8974cd3d-9bf0-4c43-ac7d-068413fb462c
SamAccountName    : thmadmin
SID               : S-1-5-21-1966530601-3185510712-10604624-1124
Surname           : Admin
UserPrincipalName : thmadmin@thmredteam.com
```

