# Bruteforcing 

## HYDRA
> https://tryhackme.com/room/hydra
```
hydra -l user -P passlist.txt ftp://MACHINE_IP
hydra -l <username> -P <full path to pass> MACHINE_IP -t 4 ssh


```
