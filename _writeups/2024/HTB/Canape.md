---
layout: writeup
category: HTB
date: 2024-12-29
comments: false
tags: 
---

<br />

![Machine-Icon](../../../assets/images/Canape/1.png)

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
❯ nmap -p- 10.10.10.70 --open --min-rate 5000 -sS -T5 -Pn -n -sCV
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-02-01 19:13 CET
Nmap scan report for 10.10.10.70
Host is up (0.93s latency).
Not shown: 65533 filtered tcp ports (no-response)
Some closed ports may be reported as filtered due to --defeat-rst-ratelimit
PORT      STATE SERVICE VERSION
80/tcp    open  http    Apache httpd 2.4.29 ((Ubuntu))
|_http-trane-info: Problem with XML parsing of /evox/about
| http-git: 
|   10.10.10.70:80/.git/
|     Git repository found!
|     Repository description: Unnamed repository; edit this file 'description' to name the...
|     Last commit message: final # Please enter the commit message for your changes. Li...
|     Remotes:
|_      http://git.canape.htb/simpsons.git
|_http-server-header: Apache/2.4.29 (Ubuntu)
|_http-title: Simpsons Fan Site
65535/tcp open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.7 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 8d:82:0b:31:90:e4:c8:85:b2:53:8b:a1:7c:3b:65:e1 (RSA)
|   256 22:fc:6e:c3:55:00:85:0f:24:bf:f5:79:6c:92:8b:68 (ECDSA)
|_  256 0d:91:27:51:80:5e:2b:a3:81:0d:e9:d8:5c:9b:77:35 (ED25519)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 53.12 seconds
```

<br />

Open Ports:

- `Port 80` -> http

- `Port 65535` -> OpenSSH

<br />

# Http Enumeration: -> Port 80

<br />

When listing the website we find a fanpage of the famous series "The Simpsons":

<br />

![2](../../../assets/images/Canape/2.png)

<br />

Enumerating manually the page we found two interesting paths.

<br />

### 1.- /quotes:

<br />

Contains the most typical quotations of some characters in the series.

<br />

![3](../../../assets/images/Canape/3.png)

<br />

### 2.- /submit:

<br />

It has a couple of interesting inputs to test.

<br />

![4](../../../assets/images/Canape/4.png)

<br />



