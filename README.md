# eJPT Study Notes

Author: Samuel Pérez López

# Introduction

These notes are intended to serve as a comprehensive guide for the eJPT (Junior Penetration Tester) certification. They cover various aspects of the certification, including assessment methodologies, host and network auditing, host and network penetration testing, and web application penetration testing.

The notes are divided into sections, each corresponding to a specific area of the certification. Each section contains a list of courses, along with their duration and the instructor's name.

The aim is to provide a structured and easy-to-follow study guide for anyone preparing for the eJPT certification.

# Table of Contents

1. **Assessment Methodologies**
   - [Information Gathering](#information-gathering)
      - [Introduction To Information Gathering](#introduction-to-information-gathering)
      - [Passive Information Gathering](#passive-information-gathering)
         - [Website Recon & Footprinting](#website-recon--footprinting)
         - [Whois Enumeration](#whois-enumeration)
         - [Website Footprinting With Netcraft](#website-footprinting-with-netcraft)
         - [DNS Recon](#dns-recon)
         - [WAF With wafw00f](#waf-with-wafw00f)
         - [Subdomain Enumeration With Sublist3r](#subdomain-enumeration-with-sublist3r)
         - [Google Dorks](#google-dorks)
         - [Email Harvesting With theHarvester](#email-harvesting-with-theharvester)
         - [Leaked Password Databases](#leaked-password-databases)
      - [Active Information Gathering](#active-information-gathering)
         - [DNS Zone Transfers](#dns-zone-transfers)
         - [Host Discovery](#host-discovery)
         - [Port Scanning](#port-scanning)
   - [Footprinting & Scanning](#footprinting-and-scanning)
      - [Introduction to Footprinting & Scanning](#introduction-to-footprinting-and-scanning)
      - [Networking Primer](#networking-primer)
         - [Networking Fundamentals](#networking-fundamentals)
         - [Network Layer](#network-layer)
         - [Transport Layer](#transport-layer)
      - [Host Discovery](#host-discovery)
         - [Network Mapping](#network-mapping)
         - [Host Discovery Techniques](#host-discovery-techniques)
         - [Ping Sweeps](#ping-sweeps)
         - [Host Discovery With Nmap](#host-discovery-with-nmap)
      - [Port Scanning](#port-scanning)
         - [Port Scanning With Nmap](#port-scanning-with-nmap)
         - [Service Version & OS Detection](#service-version--os-detection)
         - [Nmap Scripting Engine (NSE)](#nmap-scripting-engine-nse)
      - [Evasion, Scan Performance & Output](#evasion-scan-performance--output)
         - [Firewall Detection & IDS Evasion](#firewall-detection--ids-evasion)
         - [Optimizing Nmap Scans](#optimizing-nmap-scans)
         - [Nmap Output Formats](#nmap-output-formats)
   - [Enumeration](#enumeration)
   - [Vulnerability Assessment](#vulnerability-assessment)

2. **Host & Networking Auditing**
   - [Auditing Fundamentals](#auditing-fundamentals)

3. **Host & Network Penetration Testing**
   - [System/Host Based Attacks](#systemhost-based-attacks)
   - [Network-Based Attacks](#network-based-attacks)
   - [The Metasploit Framework (MSF)](#the-metasploit-framework-msf)
   - [Exploitation](#exploitation)
   - [Post-Exploitation](#post-exploitation)
   - [Social Engineering](#social-engineering)

4. **Web Application Penetration Testing**
   - [Introduction to the Web and HTTP Protocol](#introduction-to-the-web-and-http-protocol)

# **Assessment Methodologies**

## **Information Gathering**

Information gathering is the first step of any penetration test and is arguably the most important as all other phases rely on the information obtained about the target during the information gathering phase. This course will introduce you to information gathering and will cover the process of performing both passive and active information gathering by leveraging various tools and techniques to obtain as much information as possible from a target.

### **Introduction To Information Gathering**

Information gathering is the first step of any penetration test and involves gathering or collecting information about an individual, company, website or system that you are targeting. It is typically broken into passive and active information gathering.

### **Passive Information Gathering**

- Identifying IP addresses and DNS info
- Identifying domain names and ownership info
- Identifying email addresses and social media profiles
- Identifying web technologies being used on target sites
- Identifying subdomains

#### **Website Recon & Footprinting**

The `host` command is a simple command-line utility in Unix/Linux systems that is used to perform DNS lookups. You can use it to find the IP address associated with a domain, identify the mail server, and more. Here's an example of how to use the `host` command to get the IP address of a domain:

```bash
host -a <url> 
```

If you see two IP addresses in the output, it could indicate that the target is using a proxy or a Content Delivery Network (CDN) like Cloudflare. These services can provide an additional layer of protection by hiding the real IP address of the server.

Once you access the website, search for:
- The `/robots.txt` file, which guides web crawlers on which site areas to avoid. It's used to keep certain website parts out of search engine indexing. It can reveal areas of the site that the administrators don't want to be indexed and might contain private data or functionality. 
- The `/sitemap.xml` file, which helps search engines understand the structure of the website and find all the important pages. This can help an attacker understand the structure of the site more quickly and identify potential areas to probe for vulnerabilities. 

For more information about the technologies used on a website or for website analysis, it would be advisable to add plugins and programs such as:
- `BuiltWith` 
- `Wappalyzer`
- `whatweb`
- `HTTrack`

#### **Whois Enumeration**

`Whois` is a protocol that is used to query databases to obtain information about the registration of a domain name, an IP address block, or an autonomous system. This information can include the owner of the domain, the contact information, and the nameservers. Whois Enumeration is a process used in information gathering where a whois lookup is performed on a target domain to gather detailed information about the domain. You can use the command:

```bash
whois whois {url/ip}
```

Alternatively, you can use many websites such as:
- [who.is](https://who.is/)
- [whois.com](https://www.whois.com/)

#### **Website Footprinting With Netcraft**

[Netcraft](https://sitereport.netcraft.com/) is a web services company offering tools for cybersecurity and web server surveys. Its Site Report tool is particularly useful for penetration testers, providing detailed information about a website's technologies, which aids in identifying potential vulnerabilities during the reconnaissance phase of a penetration test. 

#### **DNS Recon**

`dnsrecon` is a powerful DNS (Domain Name System) enumeration script designed for penetration testers and security professionals. It is written in Python and provides the ability to perform:
- Standard DNS queries (A, AAAA, SOA, MX, TXT, and more)
- Zone transfers
- Top-level domain (TLD) expansion
- Reverse lookups for a range of IP addresses
- Subdomain enumeration
- DNS cache snooping
- DNSSEC zone walking

It can be used like this:

```bash
dnsrecon -d <url>
```

Another useful resource for DNS enumeration is the website [DNSDumpster](https://dnsdumpster.com/). It's an online tool that provides free domain research services. By simply entering a target domain, DNSDumpster generates a comprehensive map of DNS records, visualizing the connections between different components. 

#### **WAF With wafw00f**

A `WAF` or `Web Application Firewall` is a specific form of firewall that helps protect web applications by filtering and monitoring HTTP traffic between a web application and the Internet. It typically protects web applications from attacks such as cross-site forgery, cross-site-scripting (XSS), file inclusion, and SQL injection, among others. `wafw00f` is a tool used to identify and detect what WAF a website is using. The tool works by sending a series of tests to the target site and then analyzing the responses to identify the WAF. You can use it in terminal:

```bash
wafw00f -a <url>
```

#### **Subdomain Enumeration With Sublist3r**

`sublist3r` is a Python tool designed to enumerate website subdomains. It uses a variety of techniques and sources to gather subdomain names, including search engines like Google, Yahoo, Bing, and Baidu, as well as services like Netcraft, Virustotal, ThreatCrowd, DNSdumpster, and ReverseDNS. Sublist3r also supports multithreading for faster results, and can integrate with the dnsrecon tool to conduct DNS queries and zone transfers on the discovered subdomains. It can be used liek this:

```bash
sublist3r -d <url> 
```

#### **Google Dorks**

This technique is employed to discover specific data associated with an organization that's publicly available on the Internet, typically through web pages or applications. These resources are indexed based on their front-end components. As security practices evolve and companies respond to vulnerability reports, older methods (often referred to as 'dorks') used for this kind of information gathering are likely to be replaced with newer, more effective techniques. This continuous evolution is part of an ongoing effort to close off potential security loopholes. They work the following way: `command:query`
 
- `site:<url>` → Searches only pages within the specified domain (e.g., site:ull.es, site:gov ...)
- `filetype:<extension> = ext:<extension>` → Filters by file type (e.g., filetype:pdf, ext:txt, filetype:sql ...)
- `define:<word>` → Displays definitions from web pages for the specified word
- `link:<url>` → Displays pages that link to the specified URL
- `cache:<url>` → Displays the cached version of the specified URL that Google has stored ([WayBack Machine](https://archive.org/))
- `info:<url>` → Presents information about the web page corresponding to the specified URL
- `related:<url>` → Google will display pages similar to the one specified by the URL
- `(all)inurl:<word>` → Searches for pages that contain the specified word in their URL (e.g., inurl:index.php?id=)
- `(all)intitle:<word>` → Searches for the specified word in the page titles (e.g., allintitle:restricted, intitle:index of)
- `(all)intext:<word>` → Shows results for texts that contain the specified word
- `(all)inanchor:<word>` → Displays pages linked by anchors where the text contains the specified word
- Boolean operators:
    - `"X"` → Specifically searches for the text string X (e.g., "MySQL dump")
    - `"X" (Y)` → Searches in the text where Y appears (e.g., "MySQL dump" (password))
    - `X-Y` → Excludes Y from the search (e.g., gmail-hotmail)
    - `"X" / "Y"` → / = AND (e.g., "Index of" / "chat/logs")
    - `"X" | "Y"` → | = OR (e.g., password|pass|passwd|pwd)
    - `*` → Used as a wildcard to replace a word
    - `+` → Allows to include words, accents, dieresis

Might be useful: [Google Hacking Database (GHDB)](https://www.exploit-db.com/google-hacking-database)

#### **Email Harvesting With theHarvester**

`theHarvester` is a tool designed to gather publicly available information on a target, such as emails, subdomains, hosts, employee names, open ports, and banners from different public sources like search engines, PGP key servers, and the SHODAN database. It can be used like this:

```bash
theHarvester -d <url>
```

Other tools that are useful:
- [Phonebook](https://phonebook.cz/) 
- [Censys](https://search.censys.io/) - [Queries](https://search.censys.io/search/examples?resource=hosts&utm_medium=email&_hsmi=131003068&_hsenc=p2ANqtz--90D7fxWSYpNNnBzwQcQLwzEtI1hv_qktKGVZNpfaFDxgL26F21FT_HgJUyIGy6AhzJhFkNscpkTBPYqTelsKz0fyYyg&utm_content=131003068&utm_source=hs_automation)
- [Shodan](https://www.shodan.io/dashboard?language=en) - [Queries](https://github.com/jakejarvis/awesome-shodan-queries)

#### **Leaked Password Databases**

[have i been pwned?](https://haveibeenpwned.com/) is a website and service that allows internet users to check if their personal data has been compromised by data breaches. The service collects and analyzes hundreds of database dumps and pastes containing information about billions of leaked accounts, and allows users to search for their own information by entering their username or email address.

### **Active Information Gathering**

- Discovering open ports on target systems
- Learning about the internal infrastructure of a target network or organization
- Enumerating info from target systems

#### **DNS Zone Transfers**

`DNS (Domain Name System)` is a protocol that maps domain names to their respective IP addresses. This system makes it easier for users to remember and access websites without needing to know the specific IP addresses. Public DNS servers, like those provided by Cloudflare (1.1.1.1) and Google (8.8.8.8), maintain records of almost all domains on the internet. DNS records come in various types:

- `A` - Resolves a hostname or domain to an IPv4 address
- `AAAA` - Resolves a hostname or domain to an IPv6 address
- `NS`- Reference to the domains nameserver
- `MX` - Resolves a domain to a mail server
- `CNAME` - Used for domain aliases
- `TXT` - Text records
- `HINFO` - Host information
- `SOA` - Domain authority
- `SRV` - Service records
- `PTR` - Resolves an IP address to a hostname

`DNS interrogation` is the process of enumerating DNS records for a specific domain, providing valuable information like IP addresses, subdomains, and mail server addresses. `DNS Zone Transfer` is a process used to copy zone files from one DNS server to another. If misconfigured, this can be exploited by attackers to gain a comprehensive view of an organization's network layout, potentially revealing internal network addresses.

DNS can work by changing the `/etc/hosts` file. This file is a simple text file that associates IP addresses with hostnames, one line per IP address. It is used by the operating system to map hostnames to IP addresses. When you type a URL into your browser, the operating system will first look at the /etc/hosts file to see if there's an associated IP address. If there is, it will direct the traffic to that IP address. If not, it will then use the DNS servers configured on your system to resolve the hostname. For each host a single line should be present with the following information:

```bash
<ip> <hostname> <alias>
```

For example:
```
192.168.1.10 mywebsite.com www
```

We can actively enumerate the different DNS records using the tool `DNSenum` or `dig`like this:

```bash
dnsenum <url>
```

```bash
dig <zone_transfer_switch> <@server> <url>
```

Here you can see an example of [zone transfer](https://digi.ninja/projects/zonetransferme.php).

#### **Host Discovery**

`Nmap`, short for Network Mapper, is a free and open-source tool for network discovery and security auditing. It is used to discover hosts and services on a computer network, thus creating a "map" of the network. Nmap can be used to monitor single hosts as well as vast networks that encompass hundreds of thousands of machines and subnets. Some of the features of Nmap include:

- `Host discovery`: Identifying hosts on a network. For example, listing the hosts that respond to TCP and/or ICMP requests or have a particular port open.
- `Port scanning`: Enumerating the open ports on target hosts.
- `Version detection`: Interrogating network services on remote devices to determine application name and version number.
- `OS detection`: Determining the operating system and hardware characteristics of network devices.
- `Scriptable interaction with the target`: Using Nmap Scripting Engine (NSE) and Lua programming language, you can automate a wide variety of networking tasks.

You can see your ip address with the command:

```bash
ip a
```

To generate a list of systems on the network, along with the hosts that responded to the host discovery probes, you can use `nmap` or `netdiscover`. By default, `nmap` sends an ICMP echo request, a TCP SYN to port 443, a TCP ACK to port 80, and an ICMP timestamp request. On the other hand, `netdiscover` utilizes ARP requests.

```bash
sudo nmap -sn <ip/subnet>
```

```bash
sudo netdiscover -i <interface> -r <ip/subnet>
```

#### **Port Scanning**

To conduct a comprehensive port scan using nmap, the following command can be utilized:

```bash
nmap -p- -Pn -F -vvv -sCV -O -sC -T5 <ip>
```

This command performs a TCP port scan on the specified IP address which can provide valuable information about the services running on that system and potentially reveal vulnerabilities that could be exploited.

- The `-p-` option instructs Nmap to scan all 65535 ports. Without this option, Nmap would only scan the most commonly used 1000 ports.
- The `-Pn` option in Nmap is often used when scanning systems, especially Windows, as it bypasses the host discovery phase and proceeds directly to the scan. This is useful when the target system ignores or denies ICMP echo requests, which are typically used for host discovery.
- The `-F` option enables fast mode, which speeds up the scan by limiting it to fewer than 100 ports. This can be useful for quick, high-level audits of a system or network.
- The `-sU` option instructs Nmap to perform a UDP scan, which can be useful for identifying open UDP ports that could be vulnerable to exploitation.
- The `-vvv` option increases the verbosity level of Nmap's output. This means that Nmap will provide more detailed information about the scan as it progresses. The more `v` characters you include in the option (`-v`, `-vv`, `-vvv`, etc.), the more verbose the output.
- The `-sV` option enables version detection in Nmap. This instructs Nmap to interact with the open ports it finds in an attempt to determine the version of the application that is running and listening on each port.
- The `-O` option enables OS detection in Nmap. This instructs Nmap to use a variety of techniques to determine the operating system of the target host. This can be useful for identifying potential vulnerabilities specific to the detected operating system.
- The `-sC` option instructs Nmap to run a script scan using the default set of scripts. Nmap's Scripting Engine can perform a wide variety of tasks such as advanced version detection, vulnerability detection, and more. This option can be useful for automating a wide range of networking tasks.
- The `-T` option adjusts the timing template for Nmap. It accepts a number (0-5) or a name. The options are:
  - `-T0` (paranoid): Suitable for IDS evasion. Slowest scan speed.
  - `-T1` (sneaky): Suitable for IDS evasion. Slow scan speed.
  - `-T2` (polite): Slows down the scan to use less bandwidth and target machine resources.
  - `-T3` (normal): The default scanning speed.
  - `-T4` (aggressive): Speeds up the scan, but may miss some information.
  - `-T5` (insane): Fastest scan speed. Requires a fast and reliable network connection.
- The `-o` option is used to specify the output format of the scan results. Nmap supports several output formats, including:
  - `-oN` (Normal): This is the standard and most human-readable output format.
  - `-oX` (XML): This format can be parsed by software, including Nmap's own Zenmap GUI.
  - `-oG` (Grepable): This format is easily parsed by Unix/Linux tools such as grep, awk, and cut.
  - `-oA` (All): This option saves the results in all three of the above formats at once.

The ports on a networked computer can be in one of three states:

- `Open`: It means that the program or service assigned to that port is listening for connections/packets and ready to accept them at any time.
- `Filtered`: The system has received and discarded the packet. It means that a firewall, filter, or other network obstacle is blocking the port.
- `Closed`: They respond to probes, but there is no application listening on them. They can sometimes be useful to attackers, as they indicate that the host is up and running and has not been firewalled off.

## **Footprinting and Scanning**

In the realm of penetration testing, Network Scanning & Footprinting stands as a crucial phase, wielding significant influence over the test's success. This process involves identifying hosts, scanning for open ports, and discerning services and operating systems—a skill pivotal for the subsequent exploitation phase. To master these techniques, a foundational understanding of networks and protocols is imperative. This comprehensive course begins by introducing Networking and the OSI model, progressing to the Network and Transport Layers, covering key protocols like TCP/IP, ICMP, and UDP.

### **Introduction to Footprinting and Scanning**

- Introduction To Network Mapping
- Networking Fundamentals
- Host Discovery With Nmap
- Port Scanning With Nmap
- Host Fingerprinting With Nmap
- Introduction To The Nmap Scripting Engine (NSE)
- Firewall Detection & Evasion With Nmap
- Nmap Scan Timing & Performance
- Nmap Output & Verbosity

#### **Active Information Gathering**

The methodology in pentesting is something like:
1. Information Gathering:
   - Passive Information Gathering (OSINT) 
   - Active Information Gathering (Network mapping, host discovery, port scanning, service detection and OS)
2. Enumeration
   - Service and OS enumeration (Service enumeration, user enumeration, share enumeration)
3. Exploitation
   - Vulnerability analysis and threat modeling (Vulnerability analysis and identification)
   - Exploitation (Deploying or modifying exploits, service exploitation)
4. Post exploitation 
   - Post exploitation (Local enumeration, privilege escalation, credential access, persistence, defense evasion, lateral movement)
5. Reporting
   - Reporting (Report writing and recommendations)

Active information gathering is a phase in penetration testing where the tester directly interacts with the target system or network to collect data and identify potential vulnerabilities. This phase, which goes beyond passive reconnaissance, may involve scanning, probing, and directly interacting with network services.

### **Networking Primer**

This section serves as a preliminary guide to the field of networking. It's designed to provide the foundational knowledge necessary for understanding more complex networking concepts and tasks. This section might cover topics such as the basics of network protocols, the structure and function of different network layers, and the principles of network communication.

#### **Networking Fundamentals**

In `computer networking`, `hosts` communicate using `network protocols`, enabling systems with different hardware and software to interact effectively. Network protocols cater to various services and functionalities. The main aim of networking is to exchange information between networked computers through packets. Packets, which are streams of bits transmitted as electrical signals on physical media like `Ethernet` or `Wi-Fi`, are interpreted as bits (zeros and ones) that form the information. This process facilitates effective data exchange.

Every packet in all protocols has the following structure: `Header` and `Payload`. The `Header` has a protocol-specific structure. This ensures that the receiving host can correctly interpret the `Payload` and handle the overall communication. The `Payload` is the actual information being sent. It could be something like part of an email message or the content of a file during a download.

The `OSI (Open Systems Interconnection) Model`
- The OSI Model is a conceptual framework that standardizes the functions of a telecommunication or computing system into seven abstraction layers.
- Developed by the International Organization for Standardization (ISO), it facilitates communication between different systems and devices, ensuring interoperability and understanding across a broad range of networking technologies.
- The OSI Model is divided into seven layers, each representing a specific functionality in the process of network communication.
- The OSI model serves as a guideline for developing and understanding network protocols and communication processes. 
- While it is a conceptual model, it helps in organizing the complex task of network communication into manageable and structured layers. 
- The OSI model is not a strict blueprint for every networking system but rather a reference model that aids in understanding and designing network architectures.

| OSI Layer | Function | Examples |
|-----------|----------|----------|
| 7. Application Layer | Provides network services directly to end-users or applications. | HTTP, FTP, IRC, SSH, DNS |
| 6. Presentation Layer | Translates data between the application layer and lower layers. Responsible for data format translation, encryption, and compression to ensure that data is presented in a readable format. | SSL/TLS, JPEG, GIF, SSH, IMAP |
| 5. Session Layer | Manages sessions or connections between applications. Handles synchronization, dialog control, and token management. (Interhost communication) | APIs, NetBIOS, RPC |
| 4. Transport Layer | Ensures end-to-end communication and provides flow control. | TCP, UDP |
| 3. Network Layer | Responsible for logical addressing and routing. (Logical Addressing) | IP, ICMP, IPSec |
| 2. Data Link Layer | Manages access to the physical medium and provides error detection. Responsible for framing, addressing, and error checking of data frames. (Physical addressing) | Ethernet, PPP, Switches etc |
| 1. Physical Layer | Deals with the physical connection between devices. | USB, Ethernet Cables, Coax, Fiber, Hubs etc |

#### **Network Layer**

The `Network Layer` (Layer 3) of the OSI model is responsible for logical addressing, routing, and forwarding data packets between devices across different networks. Its primary goal is to determine the optimal path for data to travel from the source to the destination, even if the devices are on separate networks. The Network Layer abstracts the underlying physical network, enabling the creation of a cohesive internetwork. Several key protocols operate at the Network Layer of the OSI model. Here are some prominent Network Layer protocols:

1. Internet Protocol (IP)
   - Handles logical addressing, routing, and data packet fragmentation and reassembly.
   - IPv4
     - Uses 32-bit addresses (e.g., 192.168.0.1).
     - Limited address space led to the development of IPv6.
   - IPv6
     - Uses 128-bit addresses (e.g., 2001:0db8:85a3:0000:0000:8a2e:0370:7334).
     - Provides a much larger address space than IPv4.
   - IP Functionality
     - *Logical Addressing*: Identifies devices on a network.
     - *Packet Structure*: Organizes data into packets with a header and payload.
     - *IP Header Format*: Contains key information for packet delivery.
     - *Fragmentation and Reassembly*: Breaks down and rebuilds packets for efficient transmission.
     - *IP Addressing Types*: Addresses can be unicast, broadcast, or multicast.
     - *Subnetting*: Divides a large network into smaller subnets for efficiency and security.
2. Internet Control Message Protocol (ICMP)
   - Associated with IP.
   - Used for error reporting and diagnostics.
3. Dynamic Host Configuration Protocol (DHCP)
   - Dynamically assigns IP addresses to network devices.

The `IPv4 header fields` look like this:

| IPv4 Header Fields | Purpose |
| --- | --- |
| Version (4 bits) | Indicates the version of the IP protocol being used. For IPv4, the value is 4. |
| Header Length (4 bits) | Specifies the length of the IPv4 header in 32-bit words. The minimum value is 5 (20-byte header), and the maximum is 15 (60-byte header). |
| Type of Service (8 bits) | Originally designed for specifying the quality of service. Includes fields such as Differentiated Services Code Point (DSCP) and Explicit Congestion Notification (ECN) for packet priority and congestion control. |
| Total Length (16 bits) | Represents the total size of the IP packet, including both the header and the payload (data). The maximum size is 65,535 bytes. |
| Identification (16 bits) | Used for reassembling fragmented packets. Each fragment of a packet is assigned the same identification value. |
| Flags (3 bits) | Includes three flags related to packet fragmentation: Reserved (bit 0), Don't Fragment (DF, bit 1), and More Fragments (MF, bit 2). |
| Time-to-Live (TTL, 8 bits) | Represents the maximum number of hops (routers) a packet can traverse before being discarded. It is decremented by one at each hop. |
| Protocol (8 bits) | Identifies the higher-layer protocol that will receive the packet after IP processing. Common values include 6 for TCP, 17 for UDP, and 1 for ICMP. |
| Source IP Address (32 bits) | Specifies the IPv4 address of the sender (source) of the packet. |
| Destination IP Address (32 bits) | Specifies the IPv4 address of the intended recipient (destination) of the packet. |

`IPv4 Addresses`
- The vast majority of networks run IP version 4 (IPv4).
- An IPv4 address consists of four bytes, or octets; a byte consists of 8 bits. A dot delimits every octet in the address. For example: `73.5.12.132`.
- There are some reserved address ranges:
  - `0.0.0.0 – 0.255.255.255`: Represents "this" network.
  - `127.0.0.0 – 127.255.255.255`: Represents the local host (e.g., your computer).
  - `192.168.0.0 – 192.168.255.255`: Reserved for private networks.
- You can find the details about the special use of IPv4 addresses in [RFC5735](https://tools.ietf.org/html/rfc5735).

#### **Transport Layer**

The `Transport Layer`, which is the fourth layer of the `OSI (Open Systems Interconnection)` model, plays a crucial role in facilitating communication between two devices across a network. This layer is responsible for ensuring `reliable, end-to-end communication`. It handles tasks such as `error detection`, `flow control`, and `segmentation` of data into smaller units. The primary responsibility of the `Transport Layer` is to provide `end-to-end communication` and ensure the `reliable and ordered delivery` of data between two devices on a network. There are two protocols:

- `TCP (Transmission Control Protocol)`: A connection-oriented protocol providing reliable and ordered delivery of data. It operates at the Transport Layer of the OSI model. It's a connection-oriented protocol that ensures reliable and ordered data transfer between two devices over a network. TCP establishes a virtual circuit for data exchange, uses acknowledgments (ACK) and retransmission for reliable delivery, and reorders any out-of-order data segments before passing them to the application. It uses the `3-Way Handshake` which is a process used to establish a reliable connection between two devices before they begin data transmission and involves a series of three messages exchanged between the sender (client) and the receiver (server): 
   - `SYN (Synchronize)`: The process begins with the client sending a TCP segment with the SYN (Synchronize) flag set. This initial message indicates the client's intention to establish a connection and includes an initial sequence number (ISN), which is a randomly chosen value.
   - `SYN-ACK (Synchronize-Acknowledge)`: Upon receiving the SYN segment, the server responds with a TCP segment that has both the SYN and ACK (Acknowledge) flags set. The acknowledgment (ACK) number is set to one more than the initial sequence number received in the client's SYN segment. The server also generates its own initial sequence number.
   - `ACK (Acknowledge)`: Finally, the client acknowledges the server's response by sending a TCP segment with the ACK flag set. The acknowledgment number is set to one more than the server's initial sequence number.
   
   At this point, the connection is established, and both devices can begin transmitting data. After the three-way handshake is complete, the devices can exchange data in both directions. The acknowledgment numbers in subsequent segments are used to confirm the receipt of data and to manage the flow of information. The `fields` TCP uses are the `SRC (16 bits)` & `DST (16 bits)` which identifies the source and destination port. It also uses `control flags` to manage various aspects of the communication process. They are included in the TCP header and control different features during the establishment, maintenance, and termination of a TCP connection:

   - Establishing a Connection:
      + SYN (Set): Initiates a connection request.
      + ACK (Clear): No acknowledgment yet.
      + FIN (Clear): No termination request.
   - Establishing a Connection (Response):
      + SYN (Set): Acknowledges the connection request.
      + ACK (Set): Acknowledges the received data.
      + FIN (Clear): No termination request.
   - Terminating a Connection:
      + SYN (Clear): No connection request.
      + ACK (Set): Acknowledges the received data.
      + FIN (Set): Initiates connection termination.

   TCP utilizes port numbers to differentiate between various services or applications on a device. These port numbers are 16-bit unsigned integers, falling into three distinct ranges. The highest port number available in the TCP/IP protocol suite is 65,535. The range from 0 to 1023, known as "Well-Known Ports", is reserved for recognized services and protocols, standardized by the Internet. 
   - Assigned Numbers Authority (`IANA`):
      + 80: HTTP (Hypertext Transfer Protocol)
      + 443: HTTPS (HTTP Secure)
      + 21: FTP (File Transfer Protocol)
      + 22: SSH (Secure Shell)
      + 25: SMTP (Simple Mail Transfer Protocol)
      + 110: POP3 (Post Office Protocol version 3)
   - `Registered Ports` (1024-49151): Port numbers from 1024 to 49151 are registered for specific services or applications. These are typically assigned by the IANA to software vendors or developers for their applications. While they are not standardized, they are often used for well-known services:
      + 3389: Remote Desktop Protocol (RDP)
      + 3306: MySQL Database
      + 8080: HTTP alternative port
      + 27017: MongoDB Database

- `UDP (User Datagram Protocol)`: A connectionless protocol that prioritizes speed over reliability or order of data delivery. This means that UDP does not establish a connection before transmitting data and does not provide any guarantees that data will be delivered in the order it was sent or even delivered at all. Despite these limitations, the simplicity and efficiency of UDP make it an ideal choice for certain types of applications.

`TCP vs UDP`

| Feature | UDP | TCP |
|---------|-----|-----|
| Connection | Connectionless | 3-Way Handshake |
| Reliability | Unreliable, no guaranteed delivery of packets | Reliable, guarantees delivery and order of packets and supports retransmission |
| Header Size | Smaller header size, lower overhead | Larger header size |
| Applications | VOIP, streaming, gaming | HTTP, Email |
| Examples | DNS, DHCP, SNMP, VoIP (e.g., SIP), online gaming. | HTTP, FTP, Telnet, SMTP (email), HTTPS. |

### **Host Discovery**

#### **Network Mapping**

#### **Host Discovery Techniques**

#### **Ping Sweeps**

#### **Host Discovery With Nmap**

### **Port Scanning**

#### **Port Scanning With Nmap**

#### **Service Version & OS Detection**

#### **Nmap Scripting Engine (NSE)**

### **Evasion, Scan Performance & Output**

#### **Firewall Detection & IDS Evasion**

#### **Optimizing Nmap Scans**

#### **Nmap Output Formats**

## **Enumeration**

## **Vulnerability Assessment**

# **Host & Networking Auditing**

## **Auditing Fundamentals**

# **Host & Network Penetration Testing**

## **System/Host Based Attacks**

## **Network-Based Attacks**

## **The Metasploit Framework (MSF)**

## **Exploitation**

## **Post-Exploitation**

## **Social Engineering**

# **Web Application Penetration Testing**

## **Introduction to the Web and HTTP Protocol**