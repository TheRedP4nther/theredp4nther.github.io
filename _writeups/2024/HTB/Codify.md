---
layout: writeup
category: HTB
date: 2024-12-29
comments: false
tags: deserializationattack scripting bash python node.js cronjob reverseshell
---

<br />

![Icon-Image](../../../assets/images/Codify/1.png)

<br />

# Introduction:

<br />

As always we start with a nmap scan:

<br />

# Enumeration:

<br />

```bash
❯ nmap -sCV -p22,80 10.10.11.239 -oN targeted
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-01-01 18:38 CET
Nmap scan report for codify.htb (10.10.11.239)
Host is up (0.056s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.4 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 96:07:1c:c6:77:3e:07:a0:cc:6f:24:19:74:4d:57:0b (ECDSA)
|_  256 0b:a4:c0:cf:e2:3b:95:ae:f6:f5:df:7d:0c:88:d6:ce (ED25519)
80/tcp open  http    Apache httpd 2.4.52
|_http-title: Codify
|_http-server-header: Apache/2.4.52 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 11.08 seconds
```

<br />

# Web Enumeration:

<br />

![1](../../../assets/images/Codify/2.png)

<br />


