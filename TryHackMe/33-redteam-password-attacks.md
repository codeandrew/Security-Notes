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

## Password Profiling #2 - Keyspace technique and CUPP

```
└─# crunch -h

crunch version 3.6

Crunch can create a wordlist based on criteria you specify.  The output from crunch can be sent to the screen, file, or to another program.

Usage: crunch <min> <max> [options]
where min and max are numbers

Please refer to the man page for instructions and examples on how to use crunch.
┌──(root㉿kali)-[/tmp/pass/crunch]
└─# crunch 2 2 01234abcd -o crunch.txt
Crunch will now generate the following amount of data: 243 bytes
0 MB
0 GB
0 TB
0 PB
Crunch will now generate the following number of lines: 81 
crunch: 100% completed generating output

-> cat crunch.txt
00
01
02
03
04
0a
0b
0c
0d
10
.
.
.
cb
cc
cd
d0
d1
d2
d3
d4
da
db
dc
dd
```

It's worth noting that crunch can generate a very large text file depending on the word length and combination options you specify. The following command creates a list with an 8 character minimum and maximum length containing numbers 0-9, a-f lowercase letters, and A-F uppercase letters:

`crunch 8 8 0123456789abcdefABCDEF -o crunch.txt` the file generated is `459 GB` and contains `54,875,873,536` words

crunch also lets us specify a character set using the -t option to combine words of our choice. Here are some of the other options that could be used to help create different combinations of your choice:

- @ - lower case alpha characters
- , - upper case alpha characters
- % - numeric characters
- ^ - special characters including space

For example, if part of the password is known to us, and we know it starts with pass and follows two numbers, we can use the % symbol from above to match the numbers. Here we generate a wordlist that contains pass followed by 2 numbers:

```bash
user@thm$  crunch 6 6 -t pass%%
Crunch will now generate the following amount of data: 700 bytes
0 MB
0 GB
0 TB
0 PB
Crunch will now generate the following number of lines: 100
pass00
pass01
pass02
pass03
```

CUPP - Common User Passwords Profiler

> git clone https://github.com/Mebus/cupp.git
![33](./media/33-cupp.png)

Interactive mode
```
user@thm$  python3 cupp.py -i
 ___________
   cupp.py!                 # Common
      \                     # User
       \   ,__,             # Passwords
        \  (oo)____         # Profiler
           (__)    )\
              ||--|| *      [ Muris Kurgas | j0rgan@remote-exploit.org ]
                            [ Mebus | https://github.com/Mebus/]


[+] Insert the information about the victim to make a dictionary
[+] If you don't know all the info, just hit enter when asked! ;)

> First Name: 
> Surname: 
> Nickname: 
> Birthdate (DDMMYYYY): 


> Partners) name:
> Partners) nickname:
> Partners) birthdate (DDMMYYYY):


> Child's name:
> Child's nickname:
> Child's birthdate (DDMMYYYY):


> Pet's name:
> Company name:


> Do you want to add some key words about the victim? Y/[N]:
> Do you want to add special chars at the end of words? Y/[N]:
> Do you want to add some random numbers at the end of words? Y/[N]:
> Leet mode? (i.e. leet = 1337) Y/[N]:

[+] Now making a dictionary...
[+] Sorting list and removing duplicates...
[+] Saving dictionary to .....txt, counting ..... words.
> Hyperspeed Print? (Y/n)

```

Pre created List
```
┌──(root㉿kali)-[/tmp/pass/cupp]
└─# python3 cupp.py -l

 ___________ 
   cupp.py!                 # Common
      \                     # User
       \   ,__,             # Passwords
        \  (oo)____         # Profiler
           (__)    )\   
              ||--|| *      [ Muris Kurgas | j0rgan@remote-exploit.org ]
                            [ Mebus | https://github.com/Mebus/]


        Choose the section you want to download:

     1   Moby            14      french          27      places
     2   afrikaans       15      german          28      polish
     3   american        16      hindi           29      random
     4   aussie          17      hungarian       30      religion
     5   chinese         18      italian         31      russian
     6   computer        19      japanese        32      science
     7   croatian        20      latin           33      spanish
     8   czech           21      literature      34      swahili
     9   danish          22      movieTV         35      swedish
    10   databases       23      music           36      turkish
    11   dictionaries    24      names           37      yiddish
    12   dutch           25      net             38      exit program
    13   finnish         26      norwegian       


        Files will be downloaded from http://ftp.funet.fi/pub/unix/security/passwd/crack/dictionaries/ repository

        Tip: After downloading wordlist, you can improve it with -w option

> Enter number: 24
[+] Downloading dictionaries/names/ASSurnames.gz from http://ftp.funet.fi/pub/unix/security/passwd/crack/dictionaries/names/ASSurnames.gz ... 
[+] Downloading dictionaries/names/Congress.gz from http://ftp.funet.fi/pub/unix/security/passwd/crack/dictionaries/names/Congress.gz ... 
[+] Downloading dictionaries/names/Family-Names.gz from http://ftp.funet.fi/pub/unix/security/passwd/crack/dictionaries/names/Family-Names.gz ... 
[+] Downloading dictionaries/names/Given-Names.gz from http://ftp.funet.fi/pub/unix/security/passwd/crack/dictionaries/names/Given-Names.gz ... 
[+] Downloading dictionaries/names/actor-givenname.gz from http://ftp.funet.fi/pub/unix/security/passwd/crack/dictionaries/names/actor-givenname.gz ... 
[+] Downloading dictionaries/names/actor-surname.gz from http://ftp.funet.fi/pub/unix/security/passwd/crack/dictionaries/names/actor-surname.gz ... 
[+] Downloading dictionaries/names/cis-givenname.gz from http://ftp.funet.fi/pub/unix/security/passwd/crack/dictionaries/names/cis-givenname.gz ... 
[+] Downloading dictionaries/names/cis-surname.gz from http://ftp.funet.fi/pub/unix/security/passwd/crack/dictionaries/names/cis-surname.gz ... 
[+] Downloading dictionaries/names/crl-names.gz from http://ftp.funet.fi/pub/unix/security/passwd/crack/dictionaries/names/crl-names.gz ... 
[+] Downloading dictionaries/names/famous.gz from http://ftp.funet.fi/pub/unix/security/passwd/crack/dictionaries/names/famous.gz ... 
[+] Downloading dictionaries/names/fast-names.gz from http://ftp.funet.fi/pub/unix/security/passwd/crack/dictionaries/names/fast-names.gz ... 
[+] Downloading dictionaries/names/female-names-kantr.gz from http://ftp.funet.fi/pub/unix/security/passwd/crack/dictionaries/names/female-names-kantr.gz ... 
[+] Downloading dictionaries/names/female-names.gz from http://ftp.funet.fi/pub/unix/security/passwd/crack/dictionaries/names/female-names.gz ... 
[+] Downloading dictionaries/names/givennames-ol.gz from http://ftp.funet.fi/pub/unix/security/passwd/crack/dictionaries/names/givennames-ol.gz ... 
[+] Downloading dictionaries/names/male-names-kantr.gz from http://ftp.funet.fi/pub/unix/security/passwd/crack/dictionaries/names/male-names-kantr.gz ... 
[+] Downloading dictionaries/names/male-names.gz from http://ftp.funet.fi/pub/unix/security/passwd/crack/dictionaries/names/male-names.gz ... 
[+] Downloading dictionaries/names/movie-characters.gz from http://ftp.funet.fi/pub/unix/security/passwd/crack/dictionaries/names/movie-characters.gz ... 
[+] Downloading dictionaries/names/names.french.gz from http://ftp.funet.fi/pub/unix/security/passwd/crack/dictionaries/names/names.french.gz ... 
[+] Downloading dictionaries/names/names.hp.gz from http://ftp.funet.fi/pub/unix/security/passwd/crack/dictionaries/names/names.hp.gz ... 
[+] Downloading dictionaries/names/other-names.gz from http://ftp.funet.fi/pub/unix/security/passwd/crack/dictionaries/names/other-names.gz ... 
[+] Downloading dictionaries/names/shakesp-names.gz from http://ftp.funet.fi/pub/unix/security/passwd/crack/dictionaries/names/shakesp-names.gz ... 
[+] Downloading dictionaries/names/surnames-ol.gz from http://ftp.funet.fi/pub/unix/security/passwd/crack/dictionaries/names/surnames-ol.gz ... 
[+] Downloading dictionaries/names/surnames.finnish.gz from http://ftp.funet.fi/pub/unix/security/passwd/crack/dictionaries/names/surnames.finnish.gz ... 
[+] Downloading dictionaries/names/usenet-names.gz from http://ftp.funet.fi/pub/unix/security/passwd/crack/dictionaries/names/usenet-names.gz ... 
[+] files saved to dictionaries/names/
                                                                                                               
┌──(root㉿kali)-[/tmp/pass/cupp]
└─# ls
CHANGELOG.md  LICENSE  README.md  cupp.cfg  cupp.py  dictionaries  screenshots  test_cupp.py
└─# cd dictionaries         
└─# cd names       
┌──(root㉿kali)-[/tmp/pass/cupp/dictionaries/names]
└─# ls
ASSurnames.gz       actor-surname.gz  fast-names.gz          male-names.gz        shakesp-names.gz
Congress.gz         cis-givenname.gz  female-names-kantr.gz  movie-characters.gz  surnames-ol.gz
Family-Names.gz     cis-surname.gz    female-names.gz        names.french.gz      surnames.finnish.gz
Given-Names.gz      crl-names.gz      givennames-ol.gz       names.hp.gz          usenet-names.gz
actor-givenname.gz  famous.gz         male-names-kantr.gz    other-names.gz

```

Based on your interest, you can choose the wordlist from the list above to aid in generating wordlists for brute-forcing!

Finally, CUPP could also provide default usernames and passwords from the Alecto database by using the -a option. 

```
┌──(root㉿kali)-[/tmp/pass/cupp]
└─# python3 cupp.py -a

 ___________ 
   cupp.py!                 # Common
      \                     # User
       \   ,__,             # Passwords
        \  (oo)____         # Profiler
           (__)    )\   
              ||--|| *      [ Muris Kurgas | j0rgan@remote-exploit.org ]
                            [ Mebus | https://github.com/Mebus/]


[+] Checking if alectodb is not present...
[+] Downloading alectodb.csv.gz from https://github.com/yangbh/Hammer/raw/b0446396e8d67a7d4e53d6666026e078262e5bab/lib/cupp/alectodb.csv.gz ... 

[+] Exporting to alectodb-usernames.txt and alectodb-passwords.txt
[+] Done.

```

crunch 5 5 -t "THM@%" -o tryhackme.txt
crunch 5 5 -t “THM^%" -o tryhackme.txt
crunch 5 5 -t "THM^^" -o tryhackme.txt