---
layout: writeup
category: HTB
date: 2024-12-29
comments: false
tags: test crypto
---

![Machine-Icon](../../../assets/images/Celestial/Celestial.png)


OS -> Linux.

Difficulty -> Medium.

# Introduction:

Hello hackers! Today we will be solving the Celestial Machine. An easy difficulty Machine in which we will have to exploit a deserialization attack in node.js that will allow us to gain access to the System. Once inside, we will carry out the privilege escalation by exploiting a Python script executed by root at time intervals in the system.

Without further ado, let's get to the first phase, the enumeration phase!

# Enumeration:

We start by running the typical nmap scan to see which ports are open:

```bash
❯ nmap -p- 10.10.10.85 --open --min-rate 5000 -sS -T5 -Pn -n -sCV
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-12-29 19:31 CET
Nmap scan report for 10.10.10.85
Host is up (0.076s latency).
Not shown: 64449 closed tcp ports (reset), 1085 filtered tcp ports (no-response)
Some closed ports may be reported as filtered due to --defeat-rst-ratelimit
PORT     STATE SERVICE VERSION
3000/tcp open  http    Node.js Express framework
|_http-title: Site doesn't have a title (text/html; charset=utf-8).

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 47.04 seconds
```


As we can see, nmap has only detected Port 3000 open, node.js default port, so we proceed to list it and find the following:


![1](../../../assets/images/Celestial/1.png)


At first glance, it doesn't seem interesting at all, but when intercepting the request with Burp Suite we find the following:

