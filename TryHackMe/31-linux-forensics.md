# Linux Forensics

## OS and Account Info
```bash
cat /etc/os-release
# user accounts
# The /etc/passwd file contains information about the user accounts that exist on a Linux system. We can use the cat utility to read this file. The output contains 7 colon-separated fields, describing username, password information, user id (uid), group id (gid), description, home directory information, and the default shell that executes when the user logs in. It can be noticed that just like Windows, the user-created user accounts have uids 1000 or above. You can use the following command to make it more readable:
cat /etc/passwd | column -t -s :

# linux groups
cat /etc/group

# A Linux host allows only those users to elevate privileges to sudo, which are present in the Sudoers list. This list is stored in the file /etc/sudoers and can be read using the cat utility. You will need to elevate privileges to access this file.
sudo cat /etc/sudoers
```

**Login Information**   
In the /var/log directory, we can find log files of all kinds including wtmp and btmp. The btmp file saves information about failed logins, while the wtmp keeps historical data of logins. These files are not regular text files that can be read using cat, less or vim; instead, they are binary files, which have to be read using the last utility. You can learn more about the last utility by reading its man page.

man last
The following terminal shows the contents of wtmp being read using the last utility.

```bash
user@machine$ sudo last -f /var/log/wtmp
reboot   system boot  5.4.0-1029-aws   Tue Mar 29 17:28   still running
reboot   system boot  5.4.0-1029-aws   Tue Mar 29 04:46 - 15:52  (11:05)
reboot   system boot  5.4.0-1029-aws   Mon Mar 28 01:35 - 01:51 (1+00:16)

wtmp begins Mon Mar 28 01:35:10 2022
```

**Authentication logs**
Every user that authenticates on a Linux host is logged in the auth log. The auth log is a file placed in the location /var/log/auth.log. It can be read using the cat utility, however, given the size of the file, we can use tail, head, more or less utilities to make it easier to read.

```bash
user@machine$ cat /var/log/auth.log |tail
Mar 29 17:28:48 tryhackme gnome-keyring-daemon[989]: The PKCS#11 component was already initialized
Mar 29 17:28:48 tryhackme gnome-keyring-daemon[989]: The SSH agent was already initialized
Mar 29 17:28:49 tryhackme polkitd(authority=local): Registered Authentication Agent for unix-session:2 (system bus name :1.73 [/usr/lib/x86_64-linux-gnu/polkit-mate/polkit-mate-authentication-agent-1], object path /org/mate/PolicyKit1/AuthenticationAgent, locale en_US.UTF-8)
Mar 29 17:28:58 tryhackme pkexec[1618]: ubuntu: Error executing command as another user: Not authorized [USER=root] [TTY=unknown] [CWD=/home/ubuntu] [COMMAND=/usr/lib/update-notifier/package-system-locked]
Mar 29 17:29:09 tryhackme dbus-daemon[548]: [system] Failed to activate service 'org.bluez': timed out (service_start_timeout=25000ms)
Mar 29 17:30:01 tryhackme CRON[1679]: pam_unix(cron:session): session opened for user root by (uid=0)
Mar 29 17:30:01 tryhackme CRON[1679]: pam_unix(cron:session): session closed for user root
Mar 29 17:49:52 tryhackme sudo:   ubuntu : TTY=pts/0 ; PWD=/home/ubuntu ; USER=root ; COMMAND=/usr/bin/cat /etc/sudoers
Mar 29 17:49:52 tryhackme sudo: pam_unix(sudo:session): session opened for user root by (uid=0)
Mar 29 17:49:52 tryhackme sudo: pam_unix(sudo:session): session closed for user root
```

## System Configuration

```bash
# hostname
user@machine$ cat /etc/hostname 
# timezone
user@machine$ cat /etc/timezone

# network configuration
user@machine$ cat /etc/network/interfaces
# This file describes the network interfaces available on your system
# and how to activate them. For more information, see interfaces(5).

source /etc/network/interfaces.d/*

# The loopback network interface
auto lo
iface lo inet loopback

auto eth0
iface eth0 inet dhcp
# ------ end

# IP address
user@machine$ ip address show 
1: lo:  mtu 65536 qdisc noqueue state UNKNOWN group default qlen 1000
    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
    inet 127.0.0.1/8 scope host lo
       valid_lft forever preferred_lft forever
    inet6 ::1/128 scope host 
       valid_lft forever preferred_lft forever
2: eth0:  mtu 9001 qdisc mq state UP group default qlen 1000
    link/ether 02:20:61:f1:3c:e9 brd ff:ff:ff:ff:ff:ff
    inet 10.10.95.252/16 brd 10.10.255.255 scope global dynamic eth0
       valid_lft 2522sec preferred_lft 2522sec
    inet6 fe80::20:61ff:fef1:3ce9/64 scope link 
       valid_lft forever preferred_lft forever

```

**Active network connections**
On a live system, knowing the active network connections provides additional context to the investigation. We can use the netstat utility to find active network connections on a Linux host. We can learn more about the netstat utility by reading its man page.

man netstat

The below terminal shows the usage of the netstat utility.
```bash
user@machine$ netstat -natp
(Not all processes could be identified, non-owned process info
 will not be shown, you would have to be root to see it all.)
Active Internet connections (servers and established)
Proto Recv-Q Send-Q Local Address           Foreign Address         State       PID/Program name    
tcp        0      0 127.0.0.1:5901          0.0.0.0:*               LISTEN      829/Xtigervnc       
tcp        0      0 0.0.0.0:80              0.0.0.0:*               LISTEN      -                   
tcp        0      0 127.0.0.53:53           0.0.0.0:*               LISTEN      -                   
tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN      -                   
tcp        0      0 127.0.0.1:631           0.0.0.0:*               LISTEN      -                   
tcp        0      0 127.0.0.1:60602         127.0.0.1:5901          ESTABLISHED -                   
tcp        0      0 10.10.95.252:57432      18.66.171.77:443        ESTABLISHED -                   
tcp        0      0 10.10.95.252:80         10.100.1.33:51934       ESTABLISHED -                   
tcp        0      0 127.0.0.1:5901          127.0.0.1:60602         ESTABLISHED 829/Xtigervnc       
tcp6       0      0 ::1:5901                :::*                    LISTEN      829/Xtigervnc       
tcp6       0      0 :::22                   :::*                    LISTEN      -                   
tcp6       0      0 ::1:631                 :::*                    LISTEN      -               
```

**Running processes**
If performing forensics on a live system, it is helpful to check the running processes. The ps utility shows details about the running processes. To find out about the ps utility, we can use the man page.

man ps

The below terminal shows the usage of the ps utility.
```bash
user@machine$ ps aux
USER         PID %CPU %MEM    VSZ   RSS TTY      STAT START   TIME COMMAND
root         729  0.0  0.0   7352  2212 ttyS0    Ss+  17:28   0:00 /sbin/agetty -o -p -- \u --keep-baud 115200,38400,9600 ttyS0 vt220
root         738  0.0  0.0   5828  1844 tty1     Ss+  17:28   0:00 /sbin/agetty -o -p -- \u --noclear tty1 linux
root         755  0.0  1.5 272084 63736 tty7     Ssl+ 17:28   0:00 /usr/lib/xorg/Xorg -core :0 -seat seat0 -auth /var/run/lightdm/root/:0 -nolisten tcp vt7 -novtswitch
ubuntu      1672  0.0  0.1   5264  4588 pts/0    Ss   17:29   0:00 bash
ubuntu      1985  0.0  0.0   5892  2872 pts/0    R+   17:40   0:00 ps au
```

**DNS information**
The file /etc/hosts contains the configuration for the DNS name assignment. We can use the cat utility to read the hosts file. To learn more about the hosts file, we can use the manpage.

man hosts

The below terminal shows a sample output of the hosts file.
```bash
user@machine$ cat /etc/hosts
127.0.0.1 localhost

# The following lines are desirable for IPv6 capable hosts
::1 ip6-localhost ip6-loopback
fe00::0 ip6-localnet
ff00::0 ip6-mcastprefix
ff02::1 ip6-allnodes
ff02::2 ip6-allrouters
ff02::3 ip6-allhosts
```
The information about DNS servers that a Linux host talks to for DNS resolution is stored in the resolv.conf file. Its location is /etc/resolv.conf. We can use the cat utility to read this file.

```bash
user@machine$ cat /etc/resolv.conf 
# This file is managed by man:systemd-resolved(8). Do not edit.
#
# This is a dynamic resolv.conf file for connecting local clients to the
# internal DNS stub resolver of systemd-resolved. This file lists all
# configured search domains.
#
# Run "resolvectl status" to see details about the uplink DNS servers
# currently in use.
#
# Third party programs must not access this file directly, but only through the
# symlink at /etc/resolv.conf. To manage man:resolv.conf(5) in a different way,
# replace this symlink by a static file or a different symlink.
#
# See man:systemd-resolved.service(8) for details about the supported modes of
# operation for /etc/resolv.conf.

nameserver 127.0.0.53
options edns0 trust-ad
search eu-west-1.compute.internal
```


What is the full path of program?
```
ps aux | grep program-name
```

How to get programs listening in this address 10.10.10.10:xxxx
```
netstat -natp
```


## Persistence and Mechanisms
Knowing the environment we are investigating, we can then move on to finding out what persistence mechanisms exist on the Linux host under investigation. Persistence mechanisms are ways a program can survive after a system reboot. This helps malware authors retain their access to a system even if the system is rebooted. Let's see how we can identify persistence mechanisms in a Linux host.

**Cron jobs**
Cron jobs are commands that run periodically after a set amount of time. A Linux host maintains a list of Cron jobs in a file located at /etc/crontab. We can read the file using the cat utility.

```bash
user@machine$ cat /etc/crontab 
# /etc/crontab: system-wide crontab
# Unlike any other crontab you don't have to run the `crontab'
# command to install the new version when you edit this file
# and files in /etc/cron.d. These files also have username fields,
# that none of the other crontabs do.

SHELL=/bin/sh
PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin

# Example of job definition:
# .---------------- minute (0 - 59)
# |  .------------- hour (0 - 23)
# |  |  .---------- day of month (1 - 31)
# |  |  |  .------- month (1 - 12) OR jan,feb,mar,apr ...
# |  |  |  |  .---- day of week (0 - 6) (Sunday=0 or 7) OR sun,mon,tue,wed,thu,fri,sat
# |  |  |  |  |
# *  *  *  *  * user-name command to be executed
17 *	* * *	root    cd / && run-parts --report /etc/cron.hourly
25 6	* * *	root	test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.daily )
47 6	* * 7	root	test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.weekly )
52 6	1 * *	root	test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.monthly )

```

**Service Startup**
Like Windows, services can be set up in Linux that will start and run in the background after every system boot. A list of services can be found in the /etc/init.d directory. We can check the contents of the directory by using the ls utility.

```bash
user@machine$ ls /etc/init.d/
acpid       avahi-daemon      cups          hibagent           kmod             networking     pppd-dns                     screen-cleanup     unattended-upgrades
alsa-utils  bluetooth         cups-browsed  hwclock.sh         lightdm          open-iscsi     procps                       speech-dispatcher  uuidd
anacron     console-setup.sh  dbus          irqbalance         lvm2             open-vm-tools  pulseaudio-enable-autospawn  spice-vdagent      whoopsie
apparmor    cron              gdm3          iscsid             lvm2-lvmpolld    openvpn        rsync                        ssh                x11-common
apport      cryptdisks        grub-common   kerneloops         multipath-tools  plymouth       rsyslog                      udev
atd         cryptdisks-early  hddtemp       keyboard-setup.sh  network-manager  plymouth-log   saned                        ufw

```


**.Bashrc**
When a bash shell is spawned, it runs the commands stored in the .bashrc file. This file can be considered as a startup list of actions to be performed. Hence it can prove to be a good place to look for persistence. 

The following terminal shows an example .bashrc file.
```bash
user@machine$ cat ~/.bashrc
# ~/.bashrc: executed by bash(1) for non-login shells.
# see /usr/share/doc/bash/examples/startup-files (in the package bash-doc)
# for examples

# If not running interactively, don't do anything
case $- in
    *i*) ;;
      *) return;;
esac

# set variable identifying the chroot you work in (used in the prompt below)
if [ -z "${debian_chroot:-}" ] && [ -r /etc/debian_chroot ]; then
    debian_chroot=$(cat /etc/debian_chroot)
fi

# set a fancy prompt (non-color, unless we know we "want" color)
case "$TERM" in
    xterm-color|*-256color) color_prompt=yes;;
esac

# If this is an xterm set the title to user@host:dir
case "$TERM" in
xterm*|rxvt*)
    PS1="\[\e]0;${debian_chroot:+($debian_chroot)}\u@\h: \w\a\]$PS1"
    ;;
*)
    ;;
esac

# Add an "alert" alias for long running commands.  Use like so:
#   sleep 10; alert
alias alert='notify-send --urgency=low -i "$([ $? = 0 ] && echo terminal || echo error)" "$(history|tail -n1|sed -e '\''s/^\s*[0-9]\+\s*//;s/[;&|]\s*alert$//'\'')"'

# Alias definitions.
# You may want to put all your additions into a separate file like
# ~/.bash_aliases, instead of adding them here directly.
# See /usr/share/doc/bash-doc/examples in the bash-doc package.

if [ -f ~/.bash_aliases ]; then
    . ~/.bash_aliases
fi

# enable programmable completion features (you don't need to enable
# this, if it's already enabled in /etc/bash.bashrc and /etc/profile
# sources /etc/bash.bashrc).
if ! shopt -oq posix; then
  if [ -f /usr/share/bash-completion/bash_completion ]; then
    . /usr/share/bash-completion/bash_completion
  elif [ -f /etc/bash_completion ]; then
    . /etc/bash_completion
  fi
fi
```

System-wide settings are stored in /etc/bash.bashrc and /etc/profile files, so it is often a good idea to take a look at these files as well.

## Evidence of Execution

Knowing what programs have been executed on a host is one of the main purposes of performing forensic analysis. On a Linux host, we can find the evidence of execution from the following sources.

**Sudo execution history**
All the commands that are run on a Linux host using sudo are stored in the auth log. We already learned about the auth log in Task 3. We can use the grep utility to filter out only the required information from the auth log.

```bash
user@machine$ cat /var/log/auth.log* |grep -i COMMAND|tail
Mar 29 17:28:58 tryhackme pkexec[1618]: ubuntu: Error executing command as another user: Not authorized [USER=root] [TTY=unknown] [CWD=/home/ubuntu] [COMMAND=/usr/lib/update-notifier/package-system-locked]
Mar 29 17:49:52 tryhackme sudo:   ubuntu : TTY=pts/0 ; PWD=/home/ubuntu ; USER=root ; COMMAND=/usr/bin/cat /etc/sudoers
Mar 29 17:55:22 tryhackme sudo:   ubuntu : TTY=pts/0 ; PWD=/home/ubuntu ; USER=root ; COMMAND=/usr/bin/cat /var/log/btmp
Mar 29 17:55:39 tryhackme sudo:   ubuntu : TTY=pts/0 ; PWD=/home/ubuntu ; USER=root ; COMMAND=/usr/bin/cat /var/log/wtmp
Mar 29 18:00:54 tryhackme sudo:   ubuntu : TTY=pts/0 ; PWD=/home/ubuntu ; USER=root ; COMMAND=/usr/bin/tail -f /var/log/btmp
Mar 29 18:01:24 tryhackme sudo:   ubuntu : TTY=pts/0 ; PWD=/home/ubuntu ; USER=root ; COMMAND=/usr/bin/last -f /var/log/btmp
Mar 29 18:03:58 tryhackme sudo:   ubuntu : TTY=pts/0 ; PWD=/home/ubuntu ; USER=root ; COMMAND=/usr/bin/last -f /var/log/wtmp
Mar 29 18:05:41 tryhackme sudo:   ubuntu : TTY=pts/0 ; PWD=/home/ubuntu ; USER=root ; COMMAND=/usr/bin/last -f /var/log/btmp
Mar 29 18:07:51 tryhackme sudo:   ubuntu : TTY=pts/0 ; PWD=/home/ubuntu ; USER=root ; COMMAND=/usr/bin/last -f /var/log/utmp
Mar 29 18:08:13 tryhackme sudo:   ubuntu : TTY=pts/0 ; PWD=/home/ubuntu ; USER=root ; COMMAND=/usr/bin/last -f /var/run/utmp
```
The above terminal shows commands run by the user ubuntu using sudo.

**Bash history**

Any commands other than the ones run using sudo are stored in the bash history. Every user's bash history is stored separately in that user's home folder. Therefore, when examining bash history, we need to get the bash_history file from each user's home directory. It is important to examine the bash history from the root user as well, to make note of all the commands run using the root user as well.

```bash
user@machine$ cat ~/.bash_history 
cd Downloads/
ls
unzip PracticalMalwareAnalysis-Labs-master.zip 
cd PracticalMalwareAnalysis-Labs-master/
ls
cd ..
ls
rm -rf sality/
ls
mkdir wannacry
mv Ransomware.WannaCry.zip wannacry/
cd wannacry/
unzip Ransomware.WannaCry.zip 
cd ..
rm -rf wannacry/
ls
mkdir exmatter
mv 325ecd90ce19dd8d184ffe7dfb01b0dd02a77e9eabcb587f3738bcfbd3f832a1.7z exmatter/
cd exmatter/
strings -d 325ecd90ce19dd8d184ffe7dfb01b0dd02a77e9eabcb587f3738bcfbd3f832a1|sort|uniq>str-sorted
cd ..
ls
```

**Files accessed using vim**
The Vim text editor stores logs for opened files in Vim in the file named .viminfo in the home directory. This file contains command line history, search string history, etc. for the opened files. We can use the cat utility to open .viminfo.

```bash
user@machine$ cat ~/.viminfo
# This viminfo file was generated by Vim 8.1.
# You may edit it if you're careful!

# Viminfo version
|1,4

# Value of 'encoding' when this file was written
*encoding=utf-8


# hlsearch on (H) or off (h):
~h
# Command Line History (newest to oldest):
:q
|2,0,1636562413,,"q"

# Search String History (newest to oldest):

# Expression History (newest to oldest):

# Input Line History (newest to oldest):

# Debug Line History (newest to oldest):

# Registers:

# File marks:
'0  1139  0  ~/Downloads/str
|4,48,1139,0,1636562413,"~/Downloads/str"

# Jumplist (newest first):
-'  1139  0  ~/Downloads/str
|4,39,1139,0,1636562413,"~/Downloads/str"
-'  1  0  ~/Downloads/str
|4,39,1,0,1636562322,"~/Downloads/str"

# History of marks within files (newest to oldest):

> ~/Downloads/str
	*	1636562410	0
	"	1139	0

```


## Log files

One of the most important sources of information on the activity on a Linux host is the log files. These log files maintain a history of activity performed on the host and the amount of logging depends on the logging level defined on the system. Let's take a look at some of the important log sources. Logs are generally found in the /var/log directory.

**Syslog**
The Syslog contains messages that are recorded by the host about system activity. The detail which is recorded in these messages is configurable through the logging level. We can use the cat utility to view the Syslog, which can be found in the file /var/log/syslog. Since the Syslog is a huge file, it is easier to use tail, head, more or less utilities to help make it more readable.

```bash
user@machine$ cat /var/log/syslog* | head
Mar 29 00:00:37 tryhackme systemd-resolved[519]: Server returned error NXDOMAIN, mitigating potential DNS violation DVE-2018-0001, retrying transaction with reduced feature level UDP.
Mar 29 00:00:37 tryhackme rsyslogd: [origin software="rsyslogd" swVersion="8.2001.0" x-pid="635" x-info="https://www.rsyslog.com"] rsyslogd was HUPed
Mar 29 00:00:37 tryhackme systemd[1]: man-db.service: Succeeded.
Mar 29 00:00:37 tryhackme systemd[1]: Finished Daily man-db regeneration.
Mar 29 00:09:01 tryhackme CRON[7713]: (root) CMD (   test -x /etc/cron.daily/popularity-contest && /etc/cron.daily/popularity-contest --crond)
Mar 29 00:17:01 tryhackme CRON[7726]: (root) CMD (   cd / && run-parts --report /etc/cron.hourly)
Mar 29 00:30:45 tryhackme snapd[2930]: storehelpers.go:721: cannot refresh: snap has no updates available: "amazon-ssm-agent", "core", "core18", "core20", "lxd"
Mar 29 00:30:45 tryhackme snapd[2930]: autorefresh.go:536: auto-refresh: all snaps are up-to-date
Mar 29 01:17:01 tryhackme CRON[7817]: (root) CMD (   cd / && run-parts --report /etc/cron.hourly)
Mar 29 01:50:37 tryhackme systemd[1]: Starting Cleanup of Temporary Directories...
```
The above terminal shows the system time, system name, the process that sent the log [the process id], and the details of the log. We can see a couple of cron jobs being run here in the logs above, apart from some other activity. We can see an asterisk(*) after the syslog. This is to include rotated logs as well. With the passage of time, the Linux machine rotates older logs into files such as syslog.1, syslog.2 etc, so that the syslog file doesn't become too big. In order to search through all of the syslogs, we use the asterisk(*) wildcard.


**Auth logs**
We have already discussed the auth logs in the previous tasks. The auth logs contain information about users and authentication-related logs. The below terminal shows a sample of the auth logs.

```bash
user@machine$ cat /var/log/auth.log* |head
Feb 27 13:52:33 ip-10-10-238-44 useradd[392]: new group: name=ubuntu, GID=1000
Feb 27 13:52:33 ip-10-10-238-44 useradd[392]: new user: name=ubuntu, UID=1000, GID=1000, home=/home/ubuntu, shell=/bin/bash, from=none
Feb 27 13:52:33 ip-10-10-238-44 useradd[392]: add 'ubuntu' to group 'adm'
Feb 27 13:52:33 ip-10-10-238-44 useradd[392]: add 'ubuntu' to group 'dialout'
Feb 27 13:52:33 ip-10-10-238-44 useradd[392]: add 'ubuntu' to group 'cdrom'
Feb 27 13:52:33 ip-10-10-238-44 useradd[392]: add 'ubuntu' to group 'floppy'
Feb 27 13:52:33 ip-10-10-238-44 useradd[392]: add 'ubuntu' to group 'sudo'
Feb 27 13:52:33 ip-10-10-238-44 useradd[392]: add 'ubuntu' to group 'audio'
Feb 27 13:52:33 ip-10-10-238-44 useradd[392]: add 'ubuntu' to group 'dip'
Feb 27 13:52:33 ip-10-10-238-44 useradd[392]: add 'ubuntu' to group 'video'
```

We can see above that the log stored information about the creation of a new group, a new user, and the addition of the user into different groups.

**Third-party logs**
Similar to the syslog and authentication logs, the /var/log/ directory contains logs for third-party applications such as webserver, database, or file share server logs. We can investigate these by looking at the/var/log/ directory.

```bash
user@machine$ ls /var/log
Xorg.0.log          apt                    cloud-init.log  dmesg.2.gz      gdm3                    kern.log.1         prime-supported.log  syslog.2.gz
Xorg.0.log.old      auth.log               cups            dmesg.3.gz      gpu-manager-switch.log  landscape          private              syslog.3.gz
alternatives.log    auth.log.1             dist-upgrade    dmesg.4.gz      gpu-manager.log         lastlog            samba                syslog.4.gz
alternatives.log.1  btmp                   dmesg           dpkg.log        hp                      lightdm            speech-dispatcher    syslog.5.gz
amazon              btmp.1                 dmesg.0         dpkg.log.1      journal                 openvpn            syslog               unattended-upgrades
apache2             cloud-init-output.log  dmesg.1.gz      fontconfig.log  kern.log                prime-offload.log  syslog.1             wtmp
```

As is obvious, we can find the apache logs in the apache2 directory and samba logs in the samba directory.

```bash
user@machine$  ls /var/log/apache2/
access.log  error.log  other_vhosts_access.log
```
Similarly, if any database server like MySQL is installed on the system, we can find the logs in this directory.

Check System Logs for changed hostname activity
```
cat /var/log/syslog* | grep hostname | grep change
```


## SUMMARY

Forensic scripts
```bash
report_file="report/forensics.md"
mkdir -p report

cat /etc/os-release | tee -a $report_file # OS config
cat /etc/passwd | column -t -s : |  tee -a $report_file # Users
# Login Sessions
sudo last -f /var/log/wtmp |  tee -a $report_file # login activity

# Active Connections
sudo netstat -natp |  tee -a $report_file # active connections
# Cron Job
sudo cat /etc/crontab | tee -a $report_file # Check cron 
# Service Startup
ls /etc/init.d/ | tee -a $report_file # Service Startups

# Auth log suspicious activity
grep sudo /var/log/auth.log | grep adduser | tee -a $report_file # Add user
grep sudo /var/log/auth.log | grep visudo | tee -a $report_file # 
cat /var/log/auth.log* | grep -i COMMAND| tail | tee -a $report_file # Sudo Execution history
grep sudo /var/log/auth.log | grep vi # check for vi execution
# check cat /home/user/.viminfo

# check command for Not authorized
```

