---
layout: writeup
category: HTB
date: 2024-12-29
comments: false
tags: 
---

<br />

![1](../../../assets/images/Nineveh/1.png)

<br />

OS -> Linux.

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
❯ nmap -p- 10.10.10.43 --open --min-rate 5000 -sS -T5 -Pn -n -sCV
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-07-28 16:12 CEST
Nmap scan report for 10.10.10.43
Host is up (0.082s latency).
Not shown: 65533 filtered tcp ports (no-response)
Some closed ports may be reported as filtered due to --defeat-rst-ratelimit
PORT    STATE SERVICE  VERSION
80/tcp  open  http     Apache httpd 2.4.18 ((Ubuntu))
|_http-server-header: Apache/2.4.18 (Ubuntu)
|_http-title: Site doesn't have a title (text/html).
443/tcp open  ssl/http Apache httpd 2.4.18 ((Ubuntu))
|_ssl-date: TLS randomness does not represent time
| ssl-cert: Subject: commonName=nineveh.htb/organizationName=HackTheBox Ltd/stateOrProvinceName=Athens/countryName=GR
| Not valid before: 2017-07-01T15:03:30
|_Not valid after:  2018-07-01T15:03:30
|_http-title: Site doesn't have a title (text/html).
|_http-server-header: Apache/2.4.18 (Ubuntu)
| tls-alpn: 
|_  http/1.1

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 45.38 seconds
```

<br />

Open Ports:

`Port 80` -> HTTP 

`Port 443` -> HTTPS 

<br />

# Http Enumeration: - Port 80

<br />

On port 80, we find a default web page:

<br />

![2](../../../assets/images/Nineveh/2.png)

<br />

Perhaps with some directory fuzzing, we can discover interesting paths to explore.

<br />

## Fuzzing 

<br />

To enumerate hidden directories and files, we use `gobuster`:

<br />

```bash
❯ gobuster dir -u http://10.10.10.43 -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt -t 20 -x php
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.10.10.43
[+] Method:                  GET
[+] Threads:                 20
[+] Wordlist:                /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.6
[+] Extensions:              php
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/info.php             (Status: 200) [Size: 83681]
/department           (Status: 301) [Size: 315] [--> http://10.10.10.43/department/]
/server-status        (Status: 403) [Size: 299]
Progress: 441134 / 441136 (100.00%)
===============================================================
Finished
===============================================================
```

<br />

We find several interesting results in the output.

Let's examine them one by one.

<br />

### info.php

<br />

This page is the typical `phpinfo()` file:

<br />

![3](../../../assets/images/Nineveh/3.png)

<br />

### department

<br />

This directory contains a `login` page:

<br />

![4](../../../assets/images/Nineveh/4.png)

<br />

We tested default credentials and basic `SQL` injection payloads `' or 1=1-- -` without success.

<br />

# Https Enumeration - Port 443:

<br />

On port 443, we find a page displaying only a static image:

<br />

![5](../../../assets/images/Nineveh/5.png)

<br />
