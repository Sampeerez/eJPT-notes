# eJPT Study Notes

Author: Samuel Pérez López

## Introduction

These notes are intended to serve as a comprehensive guide for the eJPT (Junior Penetration Tester) certification. They cover various aspects of the certification, including assessment methodologies, host and network auditing, host and network penetration testing, and web application penetration testing.

The notes are divided into sections, each corresponding to a specific area of the certification. Each section contains a list of courses, along with their duration and the instructor's name.

The aim is to provide a structured and easy-to-follow study guide for anyone preparing for the eJPT certification.

## Table of Contents

1. Assessment Methodologies
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
       - [Windows Recon: Nmap Host Discovery](#windows-recon-nmap-host-discovery)
   - [Footprinting & Scanning](#footprinting--scanning)
   - [Enumeration](#enumeration)
   - [Vulnerability Assessment](#vulnerability-assessment)

2. Host & Networking Auditing
   - [Auditing Fundamentals](#auditing-fundamentals)

3. Host & Network Penetration Testing
   - [System/Host Based Attacks](#systemhost-based-attacks)
   - [Network-Based Attacks](#network-based-attacks)
   - [The Metasploit Framework (MSF)](#the-metasploit-framework-msf)
   - [Exploitation](#exploitation)
   - [Post-Exploitation](#post-exploitation)
   - [Social Engineering](#social-engineering)

4. Web Application Penetration Testing
   - [Introduction to the Web and HTTP Protocol](#introduction-to-the-web-and-http-protocol)

## Assessment Methodologies

### Information Gathering

Information gathering is the first step of any penetration test and is arguably the most important as all other phases rely on the information obtained about the target during the information gathering phase. This course will introduce you to information gathering and will cover the process of performing both passive and active information gathering by leveraging various tools and techniques to obtain as much information as possible from a target.

#### Introduction To Information Gathering

Information gathering is the first step of any penetration test and involvers gathering or collecting information about an individual, company, website or system that you are targeting. It is typically broken into passive and active information gathering.

#### Passive Information Gathering

- Identifying IP addresses and DNS info
- Identifying domain names and ownership info
- Identifying email addresses and social media profiles
- Identifying web technologies being used on target sites
- Identifying subdomains

##### Website Recon & Footprinting

The `host` command is a simple command-line utility in Unix/Linux systems that is used to perform DNS lookups. You can use it to find the IP address associated with a domain, identify the mail server, and more. Here's an example of how to use the `host` command to get the IP address of a domain:

<div style="display: flex; justify-content: space-between;">
  <code>host -a url
  <button onclick="navigator.clipboard.writeText('host -a url')" style="background: transparent; border: none; margin-left: 70px; color: #fff;"><strong>Copy</strong> 📒</button>
  </code>
</div> <p>

If you see two IP addresses in the output, it could indicate that the target is using a proxy or a Content Delivery Network (CDN) like Cloudflare. These services can provide an additional layer of protection by hiding the real IP address of the server.

Once you access the website, search for:
- The `/robots.txt` file, which guides web crawlers on which site areas to avoid. It's used to keep certain website parts out of search engine indexing. It can reveal areas of the site that the administrators don't want to be indexed and might contain private data or functionality. 
- The `/sitemap.xml` file, which helps search engines understand the structure of the website and find all the important pages. This can help an attacker understand the structure of the site more quickly and identify potential areas to probe for vulnerabilities. 

For more information about the technologies used on a website or for website analysis, it would be advisable to add plugins and programs such as:
- `BuiltWith` 
- `Wappalyzer`
- `whatweb`
- `HTTrack`

##### Whois Enumeration

`Whois` is a protocol that is used to query databases to obtain information about the registration of a domain name, an IP address block, or an autonomous system. This information can include the owner of the domain, the contact information, and the nameservers. Whois Enumeration is a process used in information gathering where a whois lookup is performed on a target domain to gather detailed information about the domain. You can use the command:

<div style="display: flex; justify-content: space-between;">
  <code>whois url / ip
  <button onclick="navigator.clipboard.writeText('whois url / ip')" style="background: transparent; border: none; margin-left: 70px; color: #fff;"><strong>Copy</strong> 📒</button>
  </code>
</div> <p>

Alternatively, you can use many websites such as:
- who.is
- whois.com

##### Website Footprinting With Netcraft
`Netcraft` is a web services company offering tools for cybersecurity and web server surveys. Its Site Report tool is particularly useful for penetration testers, providing detailed information about a website's technologies, which aids in identifying potential vulnerabilities during the reconnaissance phase of a penetration test. 

##### DNS Recon
##### WAF With wafw00f
##### Subdomain Enumeration With Sublist3r
##### Google Dorks
##### Email Harvesting With theHarvester
##### Leaked Password Databases

#### Active Information Gathering

- Discovering open ports on target systems
- Learning about the internal infrastructure of a target network or organization
- Enumerating info from target systems

##### DNS Zone Transfers
##### Host Discovery With Nmap
##### Port Scanning With Nmap
##### Windows Recon: Nmap Host Discovery

### Footprinting & Scanning

### Enumeration

### Vulnerability Assessment

## Host & Networking Auditing

### Auditing Fundamentals

## Host & Network Penetration Testing

### System/Host Based Attacks

### Network-Based Attacks

### The Metasploit Framework (MSF)

### Exploitation

### Post-Exploitation

### Social Engineering

## Web Application Penetration Testing

### Introduction to the Web and HTTP Protocol