---
layout: writeup
category: HTB
date: 2024-12-29
comments: false
tags: apachestruts struts interceptor abusingfileupload webshell sudoers
---

<br />

![1](../../../assets/images/Strutted/1.png)

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
❯ nmap -p- 10.10.11.59 --open --min-rate 5000 -sS -T5 -Pn -n -sCV
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-03-07 15:14 CET
Nmap scan report for 10.10.11.59
Host is up (0.044s latency).
Not shown: 64946 closed tcp ports (reset), 587 filtered tcp ports (no-response)
Some closed ports may be reported as filtered due to --defeat-rst-ratelimit
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.10 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 3e:ea:45:4b:c5:d1:6d:6f:e2:d4:d1:3b:0a:3d:a9:4f (ECDSA)
|_  256 64:cc:75:de:4a:e6:a5:b4:73:eb:3f:1b:cf:b4:e3:94 (ED25519)
80/tcp open  http    nginx 1.18.0 (Ubuntu)
|_http-title: Did not follow redirect to http://strutted.htb/
|_http-server-header: nginx/1.18.0 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 21.75 seconds
```

<br />

Open Ports:

`Port 22` -> ssh

`Port 80` -> http 

<br />

# Http Enumeration: -> Port 80

<br />

When we are going to list the website it redirects to -> strutted.htb, so we proceed to add it to the /etc/hosts:

<br />

```bash
echo "10.10.11.59 strutted.htb" >> /etc/hosts
```
