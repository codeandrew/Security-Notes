# Red Team - Post Compromise Enumeration
> https://tryhackme.com/r/room/enumerationpe


Recommended Rooms:
- https://tryhackme.com/r/room/windowsprivesc20
- https://tryhackme.com/r/room/linprivesc

Recommended Scripts:
- https://github.com/peass-ng/PEASS-ng/tree/master/winPEAS
- https://grimbins.github.io/grimbins/linpeas/
- https://github.com/peass-ng/PEASS-ng/tree/master/linPEAS

## Purpose
When you gain a “shell” on the target system, you usually have very basic knowledge of the system. If it is a server, you already know which service you have exploited; however, you don’t necessarily know other details, such as usernames or network shares. Consequently, the shell will look like a “dark room” where you have an incomplete and vague knowledge of what’s around you. In this sense, enumeration helps you build a more complete and accurate picture.

The purpose behind post-exploitation enumeration is to gather as much information about the system and its network. The exploited system might be a company desktop/laptop or a server. We aim to collect the information that would allow us to pivot to other systems on the network or to loot the current system. Some of the information we are interested in gathering include:

- Users and groups
- Hostnames
- Routing tables
- Network shares
- Network services
- Applications and banners
- Firewall configurations
- Service settings and audit configurations
- SNMP and DNS details
- Hunting for credentials (saved on web browsers or client applications)

