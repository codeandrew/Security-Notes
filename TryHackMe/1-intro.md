
```
gobuster -u http://fakebank.com -w wordlist.txt dir
```
In the command above, -u is used to state the website we're scanning, -w takes a list of words to iterate through to find hidden pages.

---

Web Application Security

```
This task will investigate a vulnerable website that uses Insecure Direct Object References (IDOR). IDOR falls under the category of Broken Access Control. Broken access control means that an attacker can access information or perform actions not intended for them. Consider the case where a web server receives user-supplied input to retrieve objects (files, data, documents) and that they are numbered sequentially. Let’s say that the user has permission to access a photo named IMG_1003.JPG. We might guess that there are also IMG_1002.JPG and IMG_1004.JPG; however, the web application should not provide us with that image even if we figured out its name. In general, an IDOR vulnerability can occur if too much trust has been placed on that input data. In other words, the web application does not validate whether the user has permission to access the requested object.

Just providing the correct URL for a user or a product does not necessarily mean the user should be able to access that URL. For instance, consider the product page https://store.tryhackme.thm/products/product?id=52. We can expect this URL to provide details about product number 52. In the database, items would be assigned numbers sequentially. The attacker would try other numbers such as 51 or 53 instead of 52; this might reveal other retired or unreleased products if the web application is vulnerable.

Let’s consider a more critical example; the URL https://store.tryhackme.thm/customers/user?id=16 would return the user with id=16. Again, we expect the users to have sequential ID numbers. The attacker would try other numbers and possibly access other user accounts. This vulnerability might work with sequential files; for instance, if the attacker sees 007.txt, the attacker might try other numbers such as 001.txt, 006.txt, and 008.txt. Similarly, if you were ID number 16 and ID number 17 was another user, by changing the ID to 17, you could see sensitive data that belongs to another user. Likewise, they can change the ID to 16 and see sensitive data that belongs to you. (Of course, we assume here that the system is vulnerable to IDOR.)


my user:
https://inventory-management.thm/activity?user_id=11 

just by entering this url with user id 9
https://inventory-management.thm/activity?user_id=9

i was able to make changes with the website using the identity of user_id=9
the database admin
```

