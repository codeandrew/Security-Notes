# Linux Privilige Escalation

## Common Linux PrivEsc
> https://tryhackme.com/room/commonlinuxprivesc

What does "privilege escalation" mean?  

At it's core, Privilege Escalation usually involves going from a lower permission to a higher permission. More technically, it's the exploitation of a vulnerability, design flaw or configuration oversight in an operating system or application to gain unauthorized access to resources that are usually restricted from the users.

![privesc](./media/16-common-privesc.png)

There are two main privilege escalation variants:

- Horizontal privilege escalation: This is where you expand your reach over the compromised system by taking over a different user who is on the same privilege level as you
- Vertical privilege escalation (privilege elevation): This is where you attempt to gain higher privileges or access, with an existing account that you have already compromised

### Enumeration 
LinEnum is a simple bash script that performs common commands related to privilege escalation, saving time and allowing more effort to be put toward getting root

https://github.com/rebootuser/LinEnum/blob/master/LinEnum.sh
```bash 
wget https://raw.githubusercontent.com/rebootuser/LinEnum/master/LinEnum.sh
```
### Abusing SUID/GUID Files

We already know that there is SUID capable files on the system, thanks to our LinEnum scan. However, if we want to do this manually we can use the command: `find / -perm -u=s -type f 2>/dev/null` to search the file system for SUID/GUID files. Let's break down this command.

```bash
$ find / -perm -u=s -type f 2>/dev/null

find - Initiates the "find" command
/ - Searches the whole file system
-perm - searches for files with specific permissions
-u=s - Any of the permission bits mode are set for the file. Symbolic modes are accepted in this form
-type f - Only search for files
2>/dev/null - Suppresses errors

```



## Linux PrivEsc
> https://tryhackme.com/room/linuxprivesc

wget https://raw.githubusercontent.com/diego-treitos/linux-smart-enumeration/master/lse.sh; chmod +x ./lse.sh
