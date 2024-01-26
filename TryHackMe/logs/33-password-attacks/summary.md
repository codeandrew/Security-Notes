
```bash

cewl -m 8 -w clinic_wordlist.txt https://clinic.thmredteam.com/  

#vi /opt/john/john.conf
vi /etc/john/john.conf
"
[List.Rules:THM-Password-Attacks]
Az"[0–9][0–9]" ^[!@]
"
/sbin/john --wordlist=clinic_wordlist.txt --rules=THM-Password-Attacks --stdout > dict.lst

```

