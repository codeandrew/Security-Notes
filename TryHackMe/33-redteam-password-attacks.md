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

**Customized Wordlist**

```bash
domain=https://clinic.thmredteam.com
cewl -w list.txt -d 5 -m 5 $domain
# -w will write the contents to a file. In this case, list.txt.
# -m 5 gathers strings (words) that are 5 characters or more
# -d 5 is the depth level of web crawling/spidering (default 2)
```
![00](./media/33-password-target.png)

generated list
```
Medical
Elite
email
protected
Health
Research
Welcome
Doctors
THUMB
Oxytocin
Jason
Carlson
Paracetamol
Cortisol
About
Contact
appointment
Cardiology
Latest
March
February
providing
treatment
patient
doctors
SECTION
TITLE
commonly
January
stress
Select
point
Click
hospital
clinic
Template
tooplate
health
LOADER
HEADER
LINKS
Center
Staff
Pregnancy
Dental
Google
Share
FOOTER
Opening
Hours
Monday
Friday
Saturday
Sunday
Closed
Copyright
Laboratory
Tests
Departments
Insurance
Policy
Careers
SCRIPTS
Website
healthier
Healthy
Living
Exercise
regime
customised
Lifestyle
Balanced
right
nutrition
Benefits
Stories
ABOUT
safest
clinical
innovative
technology
experience
century
multidisciplinary
teams
surgeons
researchers
other
specialists
together
address
medicine
pressing
issues
convert
findings
novel
medicines
treatments
Tanisha
Hughes
President
Pierre
Pittman
Chief
Weronika
Burgess
Dario
Phillips
released
reaction
social
connections
stressful
situations
reliever
alleviate
aches
pains
referred
hormone
because
response
APPOINTMENT
CONTACT
Email
Department
General
Phone
Number
Additional
Message
Submit
Button
GOOGLE
change
location
choose
Embed
paste
within
field
below
affiliated
company
employs
based
medical
professionals
assist
establishing
maintaining
network
highly
qualified
physicians
committed
quality
tailored
specific
requirements
official
website
Medicalmedical
surgery
porttitor
lorem
iaculis
libero
justo
vitae
gravida
imperdiet
vestibulum
porta
neque
purus
commodo
posuere
molestie
semper
euismod
Phasellus
lectus
rutrum
vulputate
Vestibulum
vehicula
sodales
placerat
venenatis
risus
eleifend
ipsum
Fusce
dolor
augue
Amazing
Technology
Consultant
Topic
Clinic
thmredteam
Professional
ealth
DETAIL
Review
Annual
Aenean
Aliquam
finibus
egestas
interdum
condimentum
pellentesque
fringilla
congue
maximus
felis
volutpat
Morbi
tempor
Mauris
tincidunt
Maecenas
aliquam
Etiam
tellus
Vivamus
ligula
tortor
lobortis
Nullam
ornare
turpis
luctus
facilisis
Nulla
sapien
pulvinar
rhoncus
lacinia
dignissim
Suspendisse
metus
laoreet
auctor
article
Facebook
Twitter
author
Lorem
maecenas
voluptate
Recent
Posts
Introducing
healing
process
Categories
Sidebar
Banner
Social
pharetra
Curabitur
consequat
ultricies
Healing
Process
```

**Username Wordlists**
Gathering employees' names in the enumeration stage is essential. We can generate username lists from the target's website. For the following example, we'll assume we have a {first name} {last name} (ex: John Smith) and a method of generating usernames.

- {first name}: john
- {last name}: smith
- {first name}{last name}:  johnsmith 
- {last name}{first name}:  smithjohn  
- first letter of the {first name}{last name}: jsmith 
- first letter of the {last name}{first name}: sjohn  
- first letter of the {first name}.{last name}: j.smith 
- first letter of the {first name}-{last name}: j-smith 
- and so on

```bash
└─# git clone https://github.com/therodri2/username_generator.git
Cloning into 'username_generator'...
remote: Enumerating objects: 9, done.
remote: Counting objects: 100% (9/9), done.
remote: Compressing objects: 100% (7/7), done.
remote: Total 9 (delta 0), reused 0 (delta 0), pack-reused 0
Receiving objects: 100% (9/9), done.
                                                                                                                
┌──(root㉿kali)-[/tmp/pass]
└─# ls
list.txt  username_generator
                                                                                                                
┌──(root㉿kali)-[/tmp/pass]
└─# cd username_generator 
                                                                                                                
┌──(root㉿kali)-[/tmp/pass/username_generator]
└─# python3 username_generator.py -h
usage: username_generator.py [-h] -w wordlist [-u]
Python script to generate user lists for bruteforcing!

options:
  -h, --help            show this help message and exit
  -w wordlist, --wordlist wordlist
                        Specify path to the wordlist
  -u, --uppercase       Also produce uppercase permutations. Disabled by default
                                                                                                                
┌──(root㉿kali)-[/tmp/pass/username_generator]
└─# echo "John Smith" > users.lst

┌──(root㉿kali)-[/tmp/pass/username_generator]
└─# python3 username_generator.py -w users.lst
john
smith
j.smith
j-smith
j_smith
j+smith
jsmith
smithjohn
```
https://default-password.info/juniper/isg2000

