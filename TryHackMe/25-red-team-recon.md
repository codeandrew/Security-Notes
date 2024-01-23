# Red Team Recon
> https://tryhackme.com/room/redteamrecon

The tasks of this room cover the following topics:
- Types of reconnaissance activities
- WHOIS and DNS-based reconnaissance
- Advanced searching
- Searching by image
- Google Hacking
- Specialized search engines
- Recon-ng
- Maltego


**Reconnaissance (recon) can be classified into two parts:**
- Passive Recon: can be carried out by watching passively
- Active Recon: requires interacting with the target to provoke it in order to observe its response.

Common Builtin Tools
- whois
- dig, nslookup, host
- traceroute/tracert

```bash
whois thmredteam.com
nslookup cafe.thmredteam.com
dig cafe.thmredteam.com @1.1.1.1 # using CloudFlares DNS server
host cafe.thmredteam.com
```
using this tools, try to findout:
- how many IPv4 addresses?
- how many IPv6 Addressess
- when the domain was registered


## Advance Searching

|         Symbol / Syntax        |                      Function                      |
|:------------------------------:|:--------------------------------------------------:|
|         "search phrase"        |        Find results with exact search phrase       |
|       OSINT filetype:pdf       |  Find files of type PDF related to a certain term. |
| salary site:blog.tryhackme.com |      Limit search results to a specific site.      |
|    pentest -site:example.com   |        Exclude a specific site from results        |
|  walkthrough intitle:TryHackMe | Find pages with a specific term in the page title. |
|    challenge inurl:tryhackme   |  Find pages with a specific term in the page URL.  |

Note: In addition to pdf, other filetypes to consider are: doc, docx, ppt, pptx, xls and xlsx.

Search engines crawl the world wide web day and night to index new web pages and files. Sometimes this can lead to indexing confidential information. Examples of confidential information include:

- Documents for internal company use
- Confidential spreadsheets with usernames, email addresses, and even passwords
- Files containing usernames
- Sensitive directories
- Service version number (some of which might be vulnerable and unpatched)
- Error messages


**Google Hacking Database**
https://www.exploit-db.com/google-hacking-database
Combining advanced Google searches with specific terms, documents containing sensitive information or vulnerable web servers can be found. Websites such as Google Hacking Database (GHDB) collect such search terms and are publicly available. Let's take a look at some of the GHDB queries to see if our client has any confidential information exposed via search engines. GHDB contains queries under the following categories:

Examples:
- Footholds
Consider GHDB-ID: 6364 as it uses the query intitle:"index of" "nginx.log" to discover Nginx logs and might reveal server misconfigurations that can be exploited.
- Files Containing Usernames
For example, GHDB-ID: 7047 uses the search term intitle:"index of" "contacts.txt" to discover files that leak juicy information.
- Sensitive Directories
For example, consider GHDB-ID: 6768, which uses the search term inurl:/certs/server.key to find out if a private RSA key is exposed.
- Web Server Detection
Consider GHDB-ID: 6876, which detects GlassFish Server information using the query intitle:"GlassFish Server - Server Running".
- Vulnerable Files
For example, we can try to locate PHP files using the query intitle:"index of" "*.php", as provided by GHDB-ID: 7786.
- Vulnerable Servers
For instance, to discover SolarWinds Orion web consoles, GHDB-ID: 6728 uses the query intext:"user name" intext:"orion core" -solarwinds.com.
- Error Messages
Plenty of useful information can be extracted from error messages. One example is GHDB-ID: 5963, which uses the query intitle:"index of" errors.log to find log files related to errors.

recommended rooms to try: https://tryhackme.com/room/googledorking


**Wayback Machine**
> https://archive.org/web/   
can be helpful to retrieve previous versions of a job opening page on your client’s site

**Social Media**

- LinkedIn
- Twitter
- Facebook
- Instagram

**Job Ads**

Job advertisements can also tell you a lot about a company. In addition to revealing names and email addresses, job posts for technical positions could give insight into the target company’s systems and infrastructure. The popular job posts might vary from one country to another. Make sure to check job listing sites in the countries where your client would post their ads. Moreover, it is always worth checking their website for any job opening and seeing if this can leak any interesting information


Answer the questions below
How would you search using Google for xls indexed for http://clinic.thmredteam.com?
```
filetype:xls site:clinic.thmredteam.com
```
How would you search using Google for files with the word passwords for http://clinic.thmredteam.com?

```
passwords site:clinic.thmredteam.com
```

## Specialized Search Engines
There are a handful of websites that offer advanced DNS services that are free to use. Some of these websites offer rich functionality and could have a complete room dedicated to exploring one domain. For now, we'll focus on key DNS related aspects. We will consider the following:

- ViewDNS.info
- Threat Intelligence Platform

**Censys**
https://search.censys.io/
Censys Search can provide a lot of information about IP addresses and domains. In this example, we look up one of the IP addresses that cafe.thmredteam.com resolves to. We can easily infer that the IP address we looked up belongs to Cloudflare. We can see information related to ports 80 and 443, among others; however, it's clear that this IP address is used to server websites other than cafe.thmredteam.com. In other words, this IP address belongs to a company other than our client, Organic Cafe. It's critical to make this distinction so that we don’t probe systems outside the scope of our contract.

**Shodan**
To use Shodan from the command-line properly, you need to create an account with Shodan, then configure shodan to use your API key using the command, shodan init API_KEY.

You can use different filters depending on the type of your Shodan account. To learn more about what you can do with shodan, we suggest that you check out Shodan CLI. Let’s demonstrate a simple example of looking up information about one of the IP addresses we got from nslookup cafe.thmredteam.com. Using shodan host IP_ADDRESS, we can get the geographical location of the IP address and the open ports, as shown below.

```
pentester@TryHackMe$ shodan host 172.67.212.249

172.67.212.249
City:                    San Francisco
Country:                 United States
Organisation:            Cloudflare, Inc.
Updated:                 2021-11-22T05:55:54.787113
Number of open ports:    5

Ports:
     80/tcp  
    443/tcp  
	|-- SSL Versions: -SSLv2, -SSLv3, -TLSv1, -TLSv1.1, TLSv1.2, TLSv1.3
   2086/tcp  
   2087/tcp  
   8080/tcp 
```
> https://cli.shodan.io/

## Recon-ng

Recon-ng is a framework that helps automate the OSINT work. It uses modules from various authors and provides a multitude of functionality. Some modules require keys to work; the key allows the module to query the related online API. In this task, we will demonstrate using Recon-ng in the terminal.

In this task, we will follow the following workflow:

- Create a workspace for your project
- Insert the starting information into the database
- Search the marketplace for a module and learn about it before installing
- List the installed modules and load one
- Run the loaded module

![recon-ng](media/25-recon-ng-demo.gif)

## Maltego


## Summary
Sun Tzu once said, “If you know the enemy and know yourself, you need not fear the result of a hundred battles. If you know yourself but not the enemy, for every victory gained you will also suffer a defeat. If you know neither the enemy nor yourself, you will succumb in every battle.” Fast forward to the cyber warfare era; in addition to knowing our red team skillset and capabilities, we need to gain as much information about the target as possible. The terrain is constantly evolving, and new ways to collect data are becoming possible.

We have reviewed essential built-in tools such as whois, dig, and tracert. Moreover, we explored the power of search engines to aid in our passive reconnaissance activities. Finally, we demonstrated two tools, Recon-ng and Maltego, that allow us to collect information from various sources and present them in one place.

The purpose is to expand our knowledge about the target and collect various information that can be leveraged in the subsequent attack phases. For instance, hosts that are discovered can be scanned and probed for vulnerabilities, while contact information and email addresses can be used to launch phishing campaigns efficiently. In brief, the more information we gather about the target, the more we can refine our attacks and increase our chances of success.



## References:

- https://github.com/asciinema/agg
