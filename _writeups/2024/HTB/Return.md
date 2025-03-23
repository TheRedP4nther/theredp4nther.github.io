---
layout: writeup
category: HTB
date: 2024-12-29
comments: false
tags: reverseshell nodejs deserializationattack scripting python javascript iife
---

<br />

![Machine-Icon](../../../assets/images/Celestial/Celestial.png)

<br />

OS -> Windows.

Difficulty -> Easy.

<br />

# Introduction:
<br />


 
<br />

# Enumeration:

<br />

We start by running the typical `nmap` scan to see which ports are open:

<br />

```bash

```

<br />

As we can see, nmap has only detected Port `3000` open, node.js default port, so we proceed to list it and find the following:

<br />

![1](../../../assets/images/Celestial/1.png)

<br />

At first glance, it doesn't seem interesting at all, but when `intercepting the request with Burp Suite` we find the following:

<br />

![2](../../../assets/images/Celestial/2.png)

<br />

# Deserialization Attack (Node.js): 

<br />

The `cookie` appears to be in `base64`, so let's apply a decode:

<br />

```bash
❯ nmap -p- 10.10.11.108 --open --min-rate 5000 -sS -T5 -Pn -n -sCV
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-03-23 18:53 CET
Nmap scan report for 10.10.11.108
Host is up (0.041s latency).
Not shown: 65498 closed tcp ports (reset), 11 filtered tcp ports (no-response)
Some closed ports may be reported as filtered due to --defeat-rst-ratelimit
PORT      STATE SERVICE       VERSION
53/tcp    open  domain        Simple DNS Plus
80/tcp    open  http          Microsoft IIS httpd 10.0
| http-methods: 
|_  Potentially risky methods: TRACE
|_http-title: HTB Printer Admin Panel
|_http-server-header: Microsoft-IIS/10.0
88/tcp    open  kerberos-sec  Microsoft Windows Kerberos (server time: 2025-03-23 18:11:44Z)
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp   open  ldap          Microsoft Windows Active Directory LDAP (Domain: return.local0., Site: Default-First-Site-Name)
445/tcp   open  microsoft-ds?
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp   open  tcpwrapped
3268/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: return.local0., Site: Default-First-Site-Name)
3269/tcp  open  tcpwrapped
5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
9389/tcp  open  mc-nmf        .NET Message Framing
47001/tcp open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
49664/tcp open  msrpc         Microsoft Windows RPC
49665/tcp open  msrpc         Microsoft Windows RPC
49666/tcp open  msrpc         Microsoft Windows RPC
49667/tcp open  msrpc         Microsoft Windows RPC
49671/tcp open  msrpc         Microsoft Windows RPC
49674/tcp open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
49675/tcp open  msrpc         Microsoft Windows RPC
49679/tcp open  msrpc         Microsoft Windows RPC
49682/tcp open  msrpc         Microsoft Windows RPC
49697/tcp open  msrpc         Microsoft Windows RPC
49723/tcp open  msrpc         Microsoft Windows RPC
Service Info: Host: PRINTER; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
|_clock-skew: 17m38s
| smb2-time: 
|   date: 2025-03-23T18:12:36
|_  start_date: N/A
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled and required

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 77.08 seconds
```

<br />

Open Ports:

It looks like we are dealing with a Windows host, since the open ports and services are typical of this operating system, such as:

- `Port 80` -> http

- `Port 88` -> Kerberos

- `Port 135` -> RPC 

- `Port 139` -> NetBIOS

- `Port 389` -> LDAP 

-  `Port 445` -> SMB 

- `Port 5985` -> WINRM

<br />
