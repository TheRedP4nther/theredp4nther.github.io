---
layout: writeup
category: HTB
date: 2024-12-29
comments: false
tags:  
---

<br />

![1](../../../assets/images/Poison/1.png)

<br />

OS -> FreeBSD.

Difficulty -> Medium.

<br />

# Introduction:

<br />



<br />

# Enumeration:

<br />

We begin with a standard `nmap` scan to identify open ports and running services:

<br />

```bash
❯ nmap -p- 10.10.10.84  --open --min-rate 5000 -sS -T5 -Pn -n -sCV
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-08-06 20:29 CEST
Nmap scan report for 10.10.10.84
Host is up (0.042s latency).
Not shown: 60743 filtered tcp ports (no-response), 4790 closed tcp ports (reset)
Some closed ports may be reported as filtered due to --defeat-rst-ratelimit
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.2 (FreeBSD 20161230; protocol 2.0)
| ssh-hostkey: 
|   2048 e3:3b:7d:3c:8f:4b:8c:f9:cd:7f:d2:3a:ce:2d:ff:bb (RSA)
|   256 4c:e8:c6:02:bd:fc:83:ff:c9:80:01:54:7d:22:81:72 (ECDSA)
|_  256 0b:8f:d5:71:85:90:13:85:61:8b:eb:34:13:5f:94:3b (ED25519)
80/tcp open  http    Apache httpd 2.4.29 ((FreeBSD) PHP/5.6.32)
|_http-server-header: Apache/2.4.29 (FreeBSD) PHP/5.6.32
|_http-title: Site doesn't have a title (text/html; charset=UTF-8).
Service Info: OS: FreeBSD; CPE: cpe:/o:freebsd:freebsd

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 32.36 seconds
```

<br />

Open Ports:

`Port 22` -> SSH 

`Port 80` -> HTTP 

<br />

# HTTP Enumeration: - Port 80

<br />

We start listing the http website:

<br />

![2](../../../assets/images/Poison/2.png)

<br />

Apparently, there is a temporal page to test `.php` tools.

<br />

### listfiles.php

<br />

This one, is a tool that allows us to list the following files:

<br />

![3](../../../assets/images/Poison/3.png)

<br />
