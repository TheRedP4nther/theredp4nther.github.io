---
layout: writeup
category: HTB
date: 2024-12-29
comments: false
tags: 
---

<br />

![1](../../../assets/images/CozyHosting/1.png)

<br />

OS -> Linux.

Difficulty -> Easy 

<br />

# Introduction:
<br />



<br />

# Enumeration:

<br />

We start by running the typical nmap scan to see which ports are open:

<br />

```bash
❯ nmap -p- 10.10.11.230 --open --min-rate 5000 -sS -T5 -Pn -n -sCV
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-01-26 15:24 CET
Nmap scan report for 10.10.11.230
Host is up (0.94s latency).
Not shown: 62221 closed tcp ports (reset), 3312 filtered tcp ports (no-response)
Some closed ports may be reported as filtered due to --defeat-rst-ratelimit
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 43:56:bc:a7:f2:ec:46:dd:c1:0f:83:30:4c:2c:aa:a8 (ECDSA)
|_  256 6f:7a:6c:3f:a6:8d:e2:75:95:d4:7b:71:ac:4f:7e:42 (ED25519)
80/tcp open  http    nginx 1.18.0 (Ubuntu)
|_http-title: Did not follow redirect to http://cozyhosting.htb
|_http-server-header: nginx/1.18.0 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 33.98 seconds
```

<br />

Open Ports:

- `Port 22` -> ssh

- `Port 80` -> http

<br />

# Http Enumeration: -> Port 80

<br />

Proceed to list the website and it redirects to cozyhosting.htb, so we add this domain to our /etc/hosts:

<br />

```bash
❯ echo '10.10.11.230 cozyhosting.htb' >> /etc/hosts
```

<br />

The website is very static and doesn't has anything interesting, only a /login:

<br />

![2](../../../assets/images/CozyHosting/2.png)

<br />

Try creds like admin:admin but don't work:

<br />

![3](../../../assets/images/CozyHosting/3.png)

<br />

The 404 error page seems interesting:

<br />

![4](../../../assets/images/CozyHosting/4.png)

<br />

Search about this error on Google and i discover that Spring Boot its being used in the backend of the Server:

<br />

![5](../../../assets/images/CozyHosting/5.png)

<br />
