# OWASP TOP 10

## 1 - Broken Access Control 

Websites have pages that are protected from regular visitors. For example, only the site's admin user should be able to access a page to manage other users. If a website visitor can access protected pages they are not meant to see, then the access controls are broken.

A regular visitor being able to access protected pages can lead to the following:

Being able to view sensitive information from other users
Accessing unauthorized functionality
Simply put, broken access control allows attackers to bypass authorisation, allowing them to view sensitive data or perform tasks they aren't supposed to.

**IDOR - Insecure Direct Object Reference**

Insecure Direct Object Reference

IDOR or Insecure Direct Object Reference refers to an access control vulnerability where you can access resources you wouldn't ordinarily be able to see. This occurs when the programmer exposes a Direct Object Reference, which is just an identifier that refers to specific objects within the server. By object, we could mean a file, a user, a bank account in a banking application, or anything really.

example:

after authenticating and getting to your account
`https://bank.thm/account?id=111111` 
you should not have the capability to access 
`https://bank.thm/account?id=22222` 


## 2 - Cryptographic Failures

A cryptographic failure refers to any vulnerability arising from the misuse (or lack of use) of cryptographic algorithms for protecting sensitive information. Web applications require cryptography to provide confidentiality for their users at many levels.

Take, for example, a secure email application:

- When you are accessing your email account using your browser, you want to be sure that the communications between you and the server are encrypted. That way, any eavesdropper trying to capture your network packets won't be able to recover the content of your email addresses. When we encrypt the network traffic between the client and server, we usually refer to this as encrypting data in transit.
- Since your emails are stored in some server managed by your provider, it is also desirable that the email provider can't read their client's emails. To this end, your emails might also be encrypted when stored on the servers. This is referred to as encrypting data at rest.





**CHALLENGE**

```bash
root@ip-10-10-244-246:~# sqlite3 webapp.db 
SQLite version 3.22.0 2018-01-22 18:45:57
Enter ".help" for usage hints.
sqlite> show tables;
Error: near "show": syntax error
sqlite> .tables
sessions  users   
sqlite> select * from users;
4413096d9c933359b898b6202288a650|admin|6eea9b7ef19179a06954edd0f6c05ceb|1
23023b67a32488588db1e28579ced7ec|Bob|ad0234829205b9033196ba818f7a872b|1
4e8423b514eef575394ff78caed3254d|Alice|268b38ca7b84f44fa0a6cdc86e6301e0|0
sqlite> 


# go to https://crackstation.net/ and paste the admin password
qwertyuiop

```


## 3 - Injection 

Injection

Injection flaws are very common in applications today. These flaws occur because the application interprets user-controlled input as commands or parameters. Injection attacks depend on what technologies are used and how these technologies interpret the input. Some common examples include:

- SQL Injection: This occurs when user-controlled input is passed to SQL queries. As a result, an attacker can pass in SQL queries to manipulate the outcome of such queries. This could potentially allow the attacker to access, modify and delete information in a database when this input is passed into database queries. This would mean an attacker could steal sensitive information such as personal details and credentials.
- Command Injection: This occurs when user input is passed to system commands. As a result, an attacker can execute arbitrary system commands on application servers, potentially allowing them to access users' systems.

The main defence for preventing injection attacks is ensuring that user-controlled input is not interpreted as queries or commands. There are different ways of doing this:

- Using an allow list: when input is sent to the server, this input is compared to a list of safe inputs or characters. If the input is marked as safe, then it is processed. Otherwise, it is rejected, and the application throws an error.
- Stripping input: If the input contains dangerous characters, these are removed before processing.

Dangerous characters or input is classified as any input that can change how the underlying data is processed. Instead of manually constructing allow lists or stripping input, various libraries exist that can perform these actions for you.


**3.1 Challenge**

```
/htdocs total 24 drwxr-xr-x 2 root root \
    | 4096 Sep 9 2022 js drwxr-xr-x 2 root    |
    | root 4096 Sep 9 2022 css -rw-r--r-- 1   |
    | root root 2402 Sep 9 2022 index.php     |
    | -rw-r--r-- 1 root root 78 Feb 3 2023    |
    | drpepper.txt drwxr-xr-x 4 root root     |
    | 4096 Feb 3 2023 . drwxr-xr-x 1 root     |
    | root 4096 Feb 3 2023 .. uid=100(apache) |
    | gid=101(apache)                         |
    | groups=82(www-data),101(apache),101(apa |
        | che) eth0 Link encap:Ethernet HWaddr    |
    | 02:42:AC:13:00:09 inet addr:172.19.0.9  |
    | Bcast:172.19.255.255 Mask:255.255.0.0   |
    | UP BROADCAST RUNNING MULTICAST MTU:1500 |
    | Metric:1 RX packets:68 errors:0         |
    | dropped:0 overruns:0 frame:0 TX         |
    | packets:52 errors:0 dropped:0           |
    | overruns:0 carrier:0 collisions:0       |
    | txqueuelen:0 RX bytes:8409 (8.2 KiB) TX |
    | bytes:234956 (229.4 KiB) lo Link        |
    | encap:Local Loopback inet               |
    | addr:127.0.0.1 Mask:255.0.0.0 UP        |
    | LOOPBACK RUNNING MTU:65536 Metric:1 RX  |
    | packets:496 errors:0 dropped:0          |
    | overruns:0 frame:0 TX packets:496       |
    | errors:0 dropped:0 overruns:0 carrier:0 |
    | collisions:0 txqueuelen:1000 RX         |
    | bytes:147176 (143.7 KiB) TX             |
    | bytes:147176 (143.7 KiB) Linux          |
    | c78e67901a6d 5.4.0-1029-aws #30-Ubuntu  |
    | SMP Tue Oct 20 10:06:38 UTC 2020 x86_64 |
    | Linux PID USER TIME COMMAND 1 root 0:00 |
    | {docker-entrypoi} /bin/sh               |
    | /docker-entrypoint.sh 24 root 0:00      |
    | httpd -D FOREGROUND 25 apache 0:00      |
    | httpd -D FOREGROUND 26 apache 0:00      |
    | httpd -D FOREGROUND 27 apache 0:00      |
    | httpd -D FOREGROUND 28 apache 0:00      |
    | httpd -D FOREGROUND 29 apache 0:00      |
    | httpd -D FOREGROUND 333 apache 0:00     |
    | httpd -D FOREGROUND 334 apache 0:00     |
    | httpd -D FOREGROUND 335 apache 0:00     |
    | httpd -D FOREGROUND 371 apache 0:00 sh  |
    | -c perl /usr/bin/cowsay -f default      |
    | $(pwd;ls -latr; id; ifconfig;uname -a   |
        \ ;ps -ef) 372 apache 0:00 ps -ef  
```



## 4  Insecure Design

**Insecure Design** 

Insecure design refers to vulnerabilities which are inherent to the application's architecture. They are not vulnerabilities regarding bad implementations or configurations, but the idea behind the whole application (or a part of it) is flawed from the start. Most of the time, these vulnerabilities occur when an improper threat modelling is made during the planning phases of the application and propagate all the way up to your final app. Some other times, insecure design vulnerabilities may also be introduced by developers while adding some "shortcuts" around the code to make their testing easier. A developer could, for example, disable the OTP validation in the development phases to quickly test the rest of the app without manually inputting a code at each login but forget to re-enable it when sending the application to production.

**Insecure Password Resets**

A good example of such vulnerabilities occurred on Instagram a while ago. Instagram allowed users to reset their forgotten passwords by sending them a 6-digit code to their mobile number via SMS for validation. If an attacker wanted to access a victim's account, he could try to brute-force the 6-digit code. As expected, this was not directly possible as Instagram had rate-limiting implemented so that after 250 attempts, the user would be blocked from trying further.

Bruteforcing code

However, it was found that the rate-limiting only applied to code attempts made from the same IP. If an attacker had several different IP addresses from where to send requests, he could now try 250 codes per IP. For a 6-digit code, you have a million possible codes, so an attacker would need 1000000/250 = 4000 IPs to cover all possible codes. This may sound like an insane amount of IPs to have, but cloud services make it easy to get them at a relatively small cost, making this attack feasible.


Since insecure design vulnerabilities are introduced at such an early stage in the development process, resolving them often requires rebuilding the vulnerable part of the application from the ground up and is usually harder to do than any other simple code-related vulnerability. The best approach to avoid such vulnerabilities is to perform threat modelling at the early stages of the development lifecycle. To get more information on how to implement secure development lifecycles, be sure to check out the SSDLC room.


## 5 Security Misconfiguration

Security Misconfigurations are distinct from the other Top 10 vulnerabilities because they occur when security could have been appropriately configured but was not. Even if you download the latest up-to-date software, poor configurations could make your installation vulnerable.

Security misconfigurations include:

- Poorly configured permissions on cloud services, like S3 buckets.
- Having unnecessary features enabled, like services, pages, accounts or privileges.
- Default accounts with unchanged passwords.
- Error messages that are overly detailed and allow attackers to find out more about the system.
- Not using HTTP security headers.

This vulnerability can often lead to more vulnerabilities, such as default credentials giving you access to sensitive data, XML External Entities (XXE) or command injection on admin pages.

For more info, look at the OWASP top 10 entry for Security Misconfiguration.


**Debugging Interfaces**

A common security misconfiguration concerns the exposure of debugging features in production software. Debugging features are often available in programming frameworks to allow the developers to access advanced functionality that is useful for debugging an application while it's being developed. Attackers could abuse some of those debug functionalities if somehow, the developers forgot to disable them before publishing their applications.

One example of such a vulnerability was allegedly used when Patreon got hacked in 2015. Five days before Patreon was hacked, a security researcher reported to Patreon that he had found an open debug interface for a Werkzeug console. Werkzeug is a vital component in Python-based web applications as it provides an interface for web servers to execute the Python code. Werkzeug includes a debug console that can be accessed either via URL on /console, or it will also be presented to the user if an exception is raised by the application. In both cases, the console provides a Python console that will run any code you send to it. For an attacker, this means he can execute commands arbitrarily.


