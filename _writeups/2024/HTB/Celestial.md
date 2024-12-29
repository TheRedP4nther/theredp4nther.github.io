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
> nmap -p- 10.10.10.85 --open --min-rate 5000 -sS -T5 -vvv -Pn -n -oG allPorts
Host discovery disabled (-Pn). All addresses will be marked 'up' and scan times may be slower.
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-12-29 19:21 CET
Initiating SYN Stealth Scan at 19:21
Scanning 10.10.10.85 [65535 ports]
Discovered open port 3000/tcp on 10.10.10.85
Completed SYN Stealth Scan at 19:21, 15.44s elapsed (65535 total ports)
Nmap scan report for 10.10.10.85
Host is up, received user-set (0.050s latency).
Scanned at 2024-12-29 19:21:16 CET for 15s
Not shown: 65534 closed tcp ports (reset)
PORT     STATE SERVICE REASON
3000/tcp open  ppp     syn-ack ttl 63

Read data files from: /usr/bin/../share/nmap
Nmap done: 1 IP address (1 host up) scanned in 15.67 seconds
           Raw packets sent: 81343 (3.579MB) | Rcvd: 80378 (3.215MB)
```
