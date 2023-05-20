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

### Exploiting Writable /etc/passwd

Understanding /etc/passwd

The /etc/passwd file stores essential information, which  is required during login. In other words, it stores user account information. The /etc/passwd is a plain text file. It contains a list of the system’s accounts, giving for each account some useful information like user ID, group ID, home directory, shell, and more.

The /etc/passwd file should have general read permission as many command utilities use it to map user IDs to user names. However, write access to the /etc/passwd must only limit for the superuser/root account. When it doesn't, or a user has erroneously been added to a write-allowed group. We have a vulnerability that can allow the creation of a root user that we can access.

The /etc/passwd file contains one entry per line for each user (user account) of the system. All fields are separated by a colon : symbol. Total of seven fields as follows. Generally, /etc/passwd file entry looks as follows:

    test:x:0:0:root:/root:/bin/bash

[as divided by colon (:)]

- Username: It is used when user logs in. It should be between 1 and 32 characters in length.
- Password: An x character indicates that encrypted password is stored in /etc/shadow file. Please note that you need to use the passwd command to compute the hash of a password typed at the CLI or to store/update the hash of the password in /etc/shadow file, in this case, the password hash is stored as an "x".
- User ID (UID): Each user must be assigned a user ID (UID). UID 0 (zero) is reserved for root and UIDs 1-99 are reserved for other predefined accounts. Further UID 100-999 are reserved by system for administrative and system accounts/groups.
- Group ID (GID): The primary group ID (stored in /etc/group file)
- User ID Info: The comment field. It allow you to add extra information about the users such as user’s full name, phone number etc. This field use by finger command.
- Home directory: The absolute path to the directory the user will be in when they log in. If this directory does not exists then users directory becomes /
- Command/shell: The absolute path of a command or shell (/bin/bash). Typically, this is a shell. Please note that it does not have to be a shell.

**How to exploit a writable /etc/passwd**

It's simple really, if we have a writable /etc/passwd file, we can write a new line entry according to the above formula and create a new user! We add the password hash of our choice, and set the UID, GID and shell to root. Allowing us to log in as our own root user!

`openssl passwd -1 -salt [salt] [password]`
`openssl passwd -1 -salt hacker tryhackme_password`

```
user7@polobox:/home/user3$ openssl passwd -1 -salt hacker tryhackme_password
$1$hacker$USbXjKgMZxKTGtRhS57M31
user7@polobox:/home/user3$ openssl passwd -1 -salt new 123
$1$new$p7ptkEKU1HnaHpRtzNizS1
```

to create new user
```
# template
username:passwordhash:0:0:root:/root:/bin/bash
# our test 
thm:$1$new$p7ptkEKU1HnaHpRtzNizS1:0:0:root:/bin/bash

# su thm :with the password use added
```


## Linux PrivEsc
> https://tryhackme.com/room/linuxprivesc

wget https://raw.githubusercontent.com/diego-treitos/linux-smart-enumeration/master/lse.sh; chmod +x ./lse.sh
