# Red Team password Attacks
> https://tryhackme.com/room/passwordattacks

- Password profiling
- Password attacks techniques
- Online password attacks

How secure are passwords?
Passwords are a protection method for accessing online accounts or computer systems. Passwords authentication methods are used to access personal and private systems, and its main goal of using the password is to keep it safe and not share it with others.

To answer the question: How secure are passwords? depends on various factors. Passwords are usually stored within the file system or database, and keeping them safe is essential. We've seen cases where companies store passwords into plaintext documents, such as the Sony breach in 2014. Therefore, once an attacker accesses the file system, he can easily obtain and reuse these passwords. On the other hand, others store passwords within the system using various techniques such as hashing functions or encryption algorithms to make them more secure. Even if the attacker has to access the system, it will be harder to crack. We will cover cracking hashes in the upcoming tasks.

references: https://www.techdirt.com/articles/20141204/12032329332/shocking-sony-learned-no-password-lessons-after-2011-psn-hack.shtml

## Password Attack Techniques

We will cover various techniques such as a dictionary, brute-force, rule-base, and guessing attacks. All the above techniques are considered active 'online' attacks where the attacker needs to communicate with the target machine to obtain the password in order to gain unauthorized access to the machine

- Password guessing is a technique used to target online protocols and services. Therefore, it's considered time-consuming and opens up the opportunity to generate logs for the failed login attempts. A password guessing attack conducted on a web-based system often requires a new request to be sent for each attempt, which can be easily detected. It may cause an account to be locked out if the system is designed and configured securely.
- Password cracking is a technique performed locally or on systems controlled by the attacker.


## Password Profiling #1 - Default, Weak, Leaked, Combined and Username Wordlists

Default Passwords

Before performing password attacks, it is worth trying a couple of default passwords against the targeted service. Manufacturers set default passwords with products and equipment such as switches, firewalls, routers. There are scenarios where customers don't change the default password, which makes the system vulnerable. Thus, it is a good practice to try out admin:admin, admin:123456, etc. If we know the target device, we can look up the default passwords and try them out. For example, suppose the target server is a Tomcat, a lightweight, open-source Java application server. In that case, there are a couple of possible default passwords we can try: admin:admin or tomcat:admin.

Here are some website lists that provide default passwords for various products.
- https://cirt.net/passwords
- https://default-password.info/
- https://datarecovery.com/rd/default-passwords/

**Combined Wordlist**
```bash
cat file1.txt file2.txt file3.txt > combined_list.txt
#To clean up the generated combined list to remove duplicated words, we can use sort and uniq 
sort combined_list.txt | uniq -u > cleaned_combined_list.txt
```