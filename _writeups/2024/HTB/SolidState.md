---
layout: writeup
category: HTB
date: 2024-12-29
comments: false
tags:  
---

<br />

![1](../../../assets/images/SolidState/1.png)

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
❯ nmap -p- 10.10.10.51 --open --min-rate 5000 -sS -T5 -Pn -n -sCV
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-08-13 16:50 CEST
Nmap scan report for 10.10.10.51
Host is up (0.080s latency).
Not shown: 65509 closed tcp ports (reset), 20 filtered tcp ports (no-response)
Some closed ports may be reported as filtered due to --defeat-rst-ratelimit
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 7.4p1 Debian 10+deb9u1 (protocol 2.0)
| ssh-hostkey: 
|   2048 77:00:84:f5:78:b9:c7:d3:54:cf:71:2e:0d:52:6d:8b (RSA)
|   256 78:b8:3a:f6:60:19:06:91:f5:53:92:1d:3f:48:ed:53 (ECDSA)
|_  256 e4:45:e9:ed:07:4d:73:69:43:5a:12:70:9d:c4:af:76 (ED25519)
25/tcp   open  smtp    JAMES smtpd 2.3.2
|_smtp-commands: solidstate Hello nmap.scanme.org (10.10.14.10 [10.10.14.10])
80/tcp   open  http    Apache httpd 2.4.25 ((Debian))
|_http-title: Home - Solid State Security
|_http-server-header: Apache/2.4.25 (Debian)
110/tcp  open  pop3    JAMES pop3d 2.3.2
119/tcp  open  nntp    JAMES nntpd (posting ok)
4555/tcp open  rsip?
| fingerprint-strings: 
|   GenericLines: 
|     JAMES Remote Administration Tool 2.3.2
|     Please enter your login and password
|     Login id:
|     Password:
|     Login failed for 
|_    Login id:
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port4555-TCP:V=7.94SVN%I=7%D=8/13%Time=689CA653%P=x86_64-pc-linux-gnu%r
SF:(GenericLines,7C,"JAMES\x20Remote\x20Administration\x20Tool\x202\.3\.2\
SF:nPlease\x20enter\x20your\x20login\x20and\x20password\nLogin\x20id:\nPas
SF:sword:\nLogin\x20failed\x20for\x20\nLogin\x20id:\n");
Service Info: Host: solidstate; OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 276.87 seconds
```

<br />

Open Ports:

`Port 22` -> SSH

`Port 25` -> SMTP

`Port 80` -> HTTP

`Port 110` -> POP3

`Port 119` -> NNTP

`Port 4555` -> JAMES Remote Administration Tool 2.3.2

<br />

# HTTP Enumeration: -> Port 80 

<br />

When we browse to the HTTP service, we see the following:

<br />

![2](../../../assets/images/SolidState/2.png)

<br />

In the menu we can find other endpoints `about.html` and `services.html`, but nothing relevant in those pages.

<br />

![3](../../../assets/images/SolidState/3.png)

<br />

At the bottom of the page there is a form:

<br />

![4](../../../assets/images/SolidState/4.png)

<br />

If we submit a message, a `POST` request is sent to `/`. This doesn't seem to be an important functionality.

<br />

# JAMES Remote Administration Tool 2.3.2

<br />

The rest of the ports are related to the `JAMES Remote Administration Tool` version `2.3.2`.

![5](../../../assets/images/SolidState/5.png)

<br />

Apache James (`Java Apache Mail Enterprise Server`) is an open-source mail server built using `Java`. It provides all the neccessary services to allow email communication, including:

- `SMTP` (Simple Mail Transfer Protocol).

- `POP3` (Post Office Protocol version 3).

- `IMAP` (Internet Message Access Protocol).

- `NNTP` (Network News Transfer Protocol).

- `Remote Administration` via a dedicated port (in this case, 4555).


