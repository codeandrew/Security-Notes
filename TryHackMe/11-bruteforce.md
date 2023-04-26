# Bruteforcing 

## HYDRA
> https://tryhackme.com/room/hydra
```
hydra -l user -P passlist.txt ftp://MACHINE_IP
hydra -l <username> -P <full path to pass> MACHINE_IP -t 4 ssh


```

### HYDRA on Postgre

```bash
username_list="/path/to/file"
password_list="/path/to/file"
target_ip=1.1.1.1
hydra -L $username_list -P $password_list -s 5432 -v -V postgres://$target_ip

```
### Hydra on BlogEngine
