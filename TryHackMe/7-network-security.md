# Network Security

 Network Security Modules:

- Passive Reconnaissance
- Active Reconnaissance
- Nmap Live Host Discovery
- Nmap Basic Port Scans
- Nmap Advanced Port Scans
- Nmap Post Port Scans
- Protocols and Servers
- Protocols and Servers 2
- Network Security Challenge

 after we define passive reconnaissance and active reconnaissance, we focus on essential tools related to passive reconnaissance. We will learn three command-line tools:

- whois to query WHOIS servers
- nslookup to query DNS servers
- dig to query DNS servers

We use whois to query WHOIS records, while we use nslookup and dig to query DNS database records. These are all publicly available records and hence do not alert the target.


We will also learn the usage of two online services:

DNSDumpster
Shodan.io

## PASSIVE VS ACTIVE RECONNAISSANCE 

In passive reconnaissance, you rely on publicly available knowledge. It is the knowledge that you can access from publicly available resources without directly engaging with the target. Think of it like you are looking at target territory from afar without stepping foot on that territory.

Passive reconnaissance activities include many activities, for instance:
- Looking up DNS records of a domain from a public DNS server.
- Checking job ads related to the target website.
- Reading news articles about the target company.

Active reconnaissance, on the other hand, cannot be achieved so discreetly. It requires direct engagement with the target. Think of it like you check the locks on the doors and windows, among other potential entry points.
examples:
- Connecting to one of the company servers such as HTTP, FTP, and SMTP.
- Calling the company in an attempt to get information (social engineering).
- Entering company premises pretending to be a repairman.

### WHOIS 
WHOIS is a request and response protocol that follows the RFC 3912 specification. A WHOIS server listens on TCP port 43 for incoming requests. The domain registrar is responsible for maintaining the WHOIS records for the domain names it is leasing. The WHOIS server replies with various information related to the domain requested. Of particular interest, we can learn:

- Registrar: Via which registrar was the domain name registered?
- Contact info of registrant: Name, organization, address, phone, among other things. (unless made hidden via a privacy service)
- Creation, update, and expiration dates: When was the domain name first registered? When was it last updated? And when does it need to be renewed?
- Name Server: Which server to ask to resolve the domain name?

### NSLOOKUP AND DIG 

Find the IP address of a domain name using `nslookup`, which stands for Name Server Look Up.

| Query type |       Result       |
|:----------:|:------------------:|
|      A     |   IPv4 Addresses   |
|    AAAA    |   IPv6 Addresses   |
|    CNAME   |   Canonical Name   |
|     MX     |    Mail Servers    |
|     SOA    | Start of Authority |
|     TXT    |     TXT Records    |


For instance, nslookup -type=A tryhackme.com 1.1.1.1 (or nslookup -type=a tryhackme.com 1.1.1.1 as it is case-insensitive) can be used to return all the IPv4 addresses used by tryhackme.com.
 
### Conclusion 

|         Lookup WHOIS record         |           whois tryhackme.com           |
|:-----------------------------------:|:---------------------------------------:|
|         Lookup DNS A records        |      nslookup -type=A tryhackme.com     |
| Lookup DNS MX records at DNS server | nslookup -type=MX tryhackme.com 1.1.1.1 |
|        Lookup DNS TXT records       |     nslookup -type=TXT tryhackme.com    |
|         Lookup DNS A records        |           dig tryhackme.com A           |
| Lookup DNS MX records at DNS server |      dig @1.1.1.1 tryhackme.com MX      |
|        Lookup DNS TXT records       |          dig tryhackme.com TXT          |

## ACTIVE RECONNAISSANCE

Active reconnaissance requires you to make some kind of contact with your target. This contact can be a phone call or a visit to the target company under some pretence to gather more information, usually as part of social engineering. Alternatively, it can be a direct connection to the target system, whether visiting their website or checking if their firewall has an SSH port open. Think of it like you are closely inspecting windows and door locks. Hence, it is essential to remember not to engage in active reconnaissance work before getting signed legal authorization from the client.

There are also plenty of add-ons for Firefox and Chrome that can help in penetration testing. Here are a few examples:

- **FoxyProxy** lets you quickly change the proxy server you are using to access the target website. This browser extension is convenient when you are using a tool such as Burp Suite or if you need to switch proxy servers regularly. You can get FoxyProxy for Firefox from here.
- **User-Agent Switcher and Manager** gives you the ability to pretend to be accessing the webpage from a different operating system or different web browser. In other words, you can pretend to be browsing a site using an iPhone when in fact, you are accessing it from Mozilla Firefox. You can download User-Agent Switcher and Manager for Firefox here.
- **Wappalyzer** provides insights about the technologies used on the visited websites. Such extension is handy, primarily when you collect all this information while browsing the website like any other user. A screenshot of Wappalyzer is shown below. You can find Wappalyzer for Firefox here.

**PING**
-c count
-s packet size 


**telnet**
telnet $IP $PORT 
(once connected)
GET / HTTP/1.1
host: example 
( double enter)


### Conclusion 

|      Command     |                   Example                  |
|:----------------:|:------------------------------------------:|
|       ping       | ping -c 10 10.10.235.164 on Linux or macOS |
|       ping       |   ping -n 10 10.10.235.164 on MS Windows   |
|    traceroute    | traceroute 10.10.235.164 on Linux or macOS |
|      tracert     |     tracert 10.10.235.164 on MS Windows    |
|      telnet      |      telnet 10.10.235.164 PORT_NUMBER      |
| netcat as client |        nc 10.10.235.164 PORT_NUMBER        |
| netcat as server |            nc -lvnp PORT_NUMBER            | 



##  NMAP LIVE HOST DICOVERY 

This room is the first of four in this Nmap series 

- Nmap Live Host Discovery
- Nmap Basic Port Scans
- Nmap Advanced Port Scans
- Nmap Post Port Scans

We present the different approaches that Nmap uses to discover live hosts. In particular, we cover:

- **ARP scan**: This scan uses ARP requests to discover live hosts
- **ICMP scan**: This scan uses ICMP requests to identify live hosts
- **TCP/UDP ping scan**: This scan sends packets to TCP ports and UDP ports to determine live hosts.

 Nmap was created by Gordon Lyon (Fyodor), a network security expert and open source programmer. It was released in 1997 
A Nmap scan usually goes through the steps shown in the figure below, although many are optional and depend on the command-line arguments you provide.

![nmap](./media/7-nmap.png)

### DISCOVERING LIVEHOST 

To visualize an ARP and PING to subnetworks
![site](./media/7-network-subnet.png)

**Same subnet**
![same_subnet](./media/ping-same-subnet.gif)

The first ping will require to make an ARP request first to know where is the location of the target.
the second request is will no longer require an ARP request because the address is cached

**Different subnet**
![dif_subnet](./media/ping-different-subnet.gif)
same from top, will first request an ARP then if it's not on the same subnet. 
the router will send another arp request to the Different subnet. 
before the ping request is received.

the second request no longer requires ARP request because address is cached 

### SUMMARY 

|        Scan Type       |              Example Command              |
|:----------------------:|:-----------------------------------------:|
|        ARP Scan        |      sudo nmap -PR -sn MACHINE_IP/24      |
|     ICMP Echo Scan     |      sudo nmap -PE -sn MACHINE_IP/24      |
|   ICMP Timestamp Scan  |      sudo nmap -PP -sn MACHINE_IP/24      |
| ICMP Address Mask Scan |      sudo nmap -PM -sn MACHINE_IP/24      |
|    TCP SYN Ping Scan   |  sudo nmap -PS22,80,443 -sn MACHINE_IP/30 |
|    TCP ACK Ping Scan   |  sudo nmap -PA22,80,443 -sn MACHINE_IP/30 |
|      UDP Ping Scan     | sudo nmap -PU53,161,162 -sn MACHINE_IP/30 |

Remember to add `-sn` if you are only interested in host discovery without port-scanning. Omitting `-sn` will let Nmap default to port-scanning the live hosts.

| Option |              Purpose             |
|:------:|:--------------------------------:|
|   -n   |           no DNS lookup          |
|   -R   | reverse-DNS lookup for all hosts |
|   -sn  |        host discovery only       |

If you want to use a specific DNS server `--dns-servers DNS_SERVER`

> return to finish notes. https://tryhackme.com/room/nmap01 


## NMAP BASIC PORT SCANS

In the previous room, we focused on discovering online systems. So far, we have covered three steps of a Nmap scan:

- Enumerate targets
- Discover live hosts
- Reverse-DNS lookup

![nmap](./media/7-nmap-room2.png)

The next step would be checking which ports are open and listening and which ports are closed. Therefore, in this room and the next one, we focus on port scanning and the different types of port scans used by nmap. This room explains:

- TCP connect port scan
- TCP SYN port scan
- UDP port scan

### TCP AND UDP PORTS 

a TCP port or UDP port is used to identify a network service running on that host

At the risk of oversimplification, we can classify ports in two states:

- Open port indicates that there is some service listening on that port.
- Closed port indicates that there is no service listening on that port.

However, in practical situations, we need to consider the impact of firewalls. For instance, a port might be open, but a firewall might be blocking the packets. Therefore, Nmap considers the following six states:

- Open: indicates that a service is listening on the specified port.
- Closed: indicates that no service is listening on the specified port, although the port is accessible. By accessible, we mean that it is reachable and is not blocked by a firewall or other security appliances/programs.
- Filtered: means that Nmap cannot determine if the port is open or closed because the port is not accessible. This state is usually due to a firewall preventing Nmap from reaching that port. Nmap’s packets may be blocked from reaching the port; alternatively, the responses are blocked from reaching Nmap’s host.
- Unfiltered: means that Nmap cannot determine if the port is open or closed, although the port is accessible. This state is encountered when using an ACK scan -sA.
- Open|Filtered: This means that Nmap cannot determine whether the port is open or filtered.
- Closed|Filtered: This means that Nmap cannot decide whether a port is closed or filtered.

### TCP FLAGS

**The following figure shows the TCP header as defined in RFC 793.**
This figure looks sophisticated at first; however, it is pretty simple to understand. In the first row, we have the source TCP port number and the destination port number. We can see that the port number is allocated 16 bits (2 bytes). In the second and third rows, we have the sequence number and the acknowledgement number. Each row has 32 bits (4 bytes) allocated, with six rows total, making up 24 bytes.

![tcp_flag](./media/7-tcp-flags.png)

- URG: Urgent flag indicates that the urgent pointer filed is significant. The urgent pointer indicates that the incoming data is urgent, and that a TCP segment with the URG flag set is processed immediately without consideration of having to wait on previously sent TCP segments.
- ACK: Acknowledgement flag indicates that the acknowledgement number is significant. It is used to acknowledge the receipt of a TCP segment.
- PSH: Push flag asking TCP to pass the data to the application promptly.
- RST: Reset flag is used to reset the connection. Another device, such as a firewall, might send it to tear a TCP connection. This flag is also used when data is sent to a host and there is no service on the receiving end to answer.
- SYN: Synchronize flag is used to initiate a TCP 3-way handshake and synchronize sequence numbers with the other host. The sequence number should be set randomly during TCP connection establishment.
- FIN: The sender has no more data to send.


### kk


## MY NOTES 


```bash
#PASSIVE RECON - Public info

nslookup -type=A tryhackme.com     # IPv4 Address
nslookup -type=MX tryhackme.com 1.1.1.1  # Mail Servers
nslookup -type=TXT tryhackme.com     # Txt records

```

other useful sites 
- DNSDumpster 
- shodan.io


