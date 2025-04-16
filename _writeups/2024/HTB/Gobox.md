---
layout: writeup
category: HTB
date: 2024-12-29
comments: false
tags: 
---

<br />

![1](../../../assets/images/Gobox/1.png)

<br />

OS -> Linux.

Difficulty -> Medium.

<br />

# Introduction:

<br />



<br />

# Enumeration:

<br />

We start by running the typical `nmap` scan to see which ports are open:

<br />

```bash
❯ nmap -p- 10.10.11.113 --open --min-rate 5000 -sS -T5 -Pn -n -sCV
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-04-16 17:33 CEST
Nmap scan report for 10.10.11.113
Host is up (0.044s latency).
Not shown: 65413 closed tcp ports (reset), 118 filtered tcp ports (no-response)
Some closed ports may be reported as filtered due to --defeat-rst-ratelimit
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 d8:f5:ef:d2:d3:f9:8d:ad:c6:cf:24:85:94:26:ef:7a (RSA)
|   256 46:3d:6b:cb:a8:19:eb:6a:d0:68:86:94:86:73:e1:72 (ECDSA)
|_  256 70:32:d7:e3:77:c1:4a:cf:47:2a:de:e5:08:7a:f8:7a (ED25519)
80/tcp   open  http    nginx
|_http-title: Hacking eSports | {{.Title}}
4566/tcp open  http    nginx
|_http-title: 403 Forbidden
8080/tcp open  http    nginx
|_http-open-proxy: Proxy might be redirecting requests
|_http-title: Hacking eSports | Home page
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 27.39 seconds
```

<br />

Open Ports:

- `Port 22` -> ssh 

- `Port 80` -> http

- `Port 4566` -> internal service (?)

- `Port 8080` -> http

<br />

# Http Enumeration: -> Port 80

<br />

List the website on this port:

<br />

![2](../../../assets/images/Gobox/2.png)

<br />

It's a page dedicated to a `eSports` hacking competition, but we don't see nothing `relevant`.

So we keep enumerating the next port.

<br />

# Http Enumeration: -> Port 8080

<br />

The front page of the other website is a `login panel`:

<br />

![3](../../../assets/images/Gobox/3.png)

<br />

We try default `passwords` but doesn't work.

<br />

So we click on the "`Forgot Password`" option and see this:

<br />

![4](../../../assets/images/Gobox/4.png)

<br />
