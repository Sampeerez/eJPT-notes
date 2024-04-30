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
         - [Host Discovery With Nmap](#host-discovery-with-nmap)
         - [Port Scanning With Nmap](#port-scanning-with-nmap)
   - [Footprinting & Scanning](#footprinting-and-scanning)
      - [Introduction to Footprinting & Scanning](#introduction-to-footprinting-and-scanning)
      - [Networking Primer](#networking-primer)
         - [Networking Fundamentals](#networking-fundamentals)
         - [Network Layer](#network-layer)
         - [Transport Layer - Part 1](#transport-layer---part-1)
         - [Transport Layer - Part 2](#transport-layer---part-2)
      - [Host Discovery](#host-discovery)
         - [Network Mapping](#network-mapping)
         - [Host Discovery Techniques](#host-discovery-techniques)
         - [Ping Sweeps](#ping-sweeps)
         - [Host Discovery With Nmap - Part 1](#host-discovery-with-nmap---part-1)
         - [Host Discovery With Nmap - Part 2](#host-discovery-with-nmap---part-2)
      - [Port Scanning](#port-scanning)
         - [Port Scanning With Nmap - Part 1](#port-scanning-with-nmap---part-1)
         - [Port Scanning With Nmap - Part 2](#port-scanning-with-nmap---part-2)
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

#### **Host Discovery With Nmap**

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

#### **Port Scanning With Nmap**

To conduct a comprehensive port scan using nmap, the following command can be utilized:

```bash
nmap -p- -Pn -F -vvv -sV -O -sC <ip>
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

### **Introduction to Footprinting and Scanning**

#### **Active Information Gathering**

### **Networking Primer**

#### **Networking Fundamentals**

#### **Network Layer**

#### **Transport Layer - Part 1**

#### **Transport Layer - Part 2**

### **Host Discovery**

#### **Network Mapping**

#### **Host Discovery Techniques**

#### **Ping Sweeps**

#### **Host Discovery With Nmap - Part 1**

#### **Host Discovery With Nmap - Part 2**

### **Port Scanning**

#### **Port Scanning With Nmap - Part 1**

#### **Port Scanning With Nmap - Part 2**

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