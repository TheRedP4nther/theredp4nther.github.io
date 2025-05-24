---
layout: writeup
category: HTB
date: 2024-12-29
comments: false
tags:  
---

<br />

![1](../../../assets/images/Epsilon/1.png)

<br />

OS -> Linux.

Difficulty -> Medium.

<br />

# Introduction:

<br />



<br />

# Enumeration:

<br />

As always we are going to start with a `nmap` scan to enumerate the open ports and services running on the victim machine:

<br />

```bash
❯ nmap -p- 10.10.11.134 --open --min-rate 5000 -sS -T5 -Pn -n -sCV
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-05-24 12:29 CEST
Nmap scan report for 10.10.11.134
Host is up (0.049s latency).
Not shown: 65532 closed tcp ports (reset)
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.4 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 48:ad:d5:b8:3a:9f:bc:be:f7:e8:20:1e:f6:bf:de:ae (RSA)
|   256 b7:89:6c:0b:20:ed:49:b2:c1:86:7c:29:92:74:1c:1f (ECDSA)
|_  256 18:cd:9d:08:a6:21:a8:b8:b6:f7:9f:8d:40:51:54:fb (ED25519)
80/tcp   open  http    Apache httpd 2.4.41
|_http-title: 403 Forbidden
| http-git: 
|   10.10.11.134:80/.git/
|     Git repository found!
|     Repository description: Unnamed repository; edit this file 'description' to name the...
|_    Last commit message: Updating Tracking API  # Please enter the commit message for...
|_http-server-header: Apache/2.4.41 (Ubuntu)
5000/tcp open  http    Werkzeug httpd 2.0.2 (Python 3.8.10)
|_http-title: Costume Shop
|_http-server-header: Werkzeug/2.0.2 Python/3.8.10
Service Info: Host: 127.0.1.1; OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 21.86 seconds
```

<br />

Open Ports:

`Port 22` -> ssh 

`Port 80` -> http 

`Port 5000` -> http

<br />

# Http Enumeration: -> Port 80

<br />

There is a website running on the port 80, but attempting to access it returns a `403 forbidden` status code:

<br />

![2](../../../assets/images/Epsilon/2.png)

<br />

At first glance, it seems there isn't much we can do here.

However, upon analyzing the `nmap` output, we notice the presence of a `.git` directory on the web server.

Using the popular tool [git-dumper](), we can retrieve the repository with the following oneliner:

<br />

```bash
❯ python3 git_dumper.py http://10.10.11.134/.git EPSILON
```

<br />

Now, we can access the directory and access the `.git` content:

<br />

```bash
❯ ls -la
drwxr-xr-x root root  64 B  Sat May 24 12:44:24 2025  .
drwxr-xr-x root root 196 B  Sat May 24 12:44:21 2025  ..
drwxr-xr-x root root 146 B  Sat May 24 12:45:34 2025  .git
.rw-r--r-- root root 1.6 KB Sat May 24 12:44:24 2025  server.py
.rw-r--r-- root root 1.1 KB Sat May 24 12:44:24 2025  track_api_CR_148.py
```

<br />
