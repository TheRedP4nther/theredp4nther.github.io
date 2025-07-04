---
layout: writeup
category: HTB
date: 2024-12-29
comments: false
tags: cisco router informationleakage ciscotype5 ciscotype7 guest
---

<br />

![1](../../../assets/images/Heist/1.png)

<br />

OS -> Windows.

Difficulty -> Easy.

<br />

# Introduction

<br />



<br />

# Enumeration

<br />

We begin with a standard `nmap` scan to identify open ports:

<br />

```bash
❯ nmap -p- 10.10.10.149 --open --min-rate 5000 -sS -T5 -Pn -n -sCV
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-07-04 12:58 CEST
Nmap scan report for 10.10.10.149
Host is up (0.051s latency).
Not shown: 65530 filtered tcp ports (no-response)
Some closed ports may be reported as filtered due to --defeat-rst-ratelimit
PORT      STATE SERVICE       VERSION
80/tcp    open  http          Microsoft IIS httpd 10.0
| http-title: Support Login Page
|_Requested resource was login.php
| http-cookie-flags: 
|   /: 
|     PHPSESSID: 
|_      httponly flag not set
| http-methods: 
|_  Potentially risky methods: TRACE
135/tcp   open  msrpc         Microsoft Windows RPC
445/tcp   open  microsoft-ds?
5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0
49669/tcp open  msrpc         Microsoft Windows RPC
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
|_clock-skew: -57s
| smb2-time: 
|   date: 2025-07-04T10:58:37
|_  start_date: N/A
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled but not required

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 123.29 seconds
```

<br />

Relevant open ports:

- `Port 80` -> http

- `Port 135` -> rpc 

- `Port 445` -> smb 

- `Port 5985` -> winrm

<br />

## Http Enumeration

<br />

The website hosted on port 80 displays a login panel:

<br />

![2](../../../assets/images/Heist/2.png)

<br />

Although we don't have any credentials, clicking on `Login as guest` grants access to the following interface:

<br />

![3](../../../assets/images/Heist/3.png)

<br />

There is a user named `Hazard` who is having a discussion with a Support Admin about a problem with a `Cisco router`.

In the user's first message, we can find a button with an `attachment`.

Clicking on this button reveals an interesting `config.txt` file:

<br />

```bash
version 12.2
no service pad
service password-encryption
!
isdn switch-type basic-5ess
!
hostname ios-1
!
security passwords min-length 12
enable secret 5 $1$pdQG$o8nrSzsGXeaduXrjlvKc91
!
username rout3r password 7 0242114B0E143F015F5D1E161713
username admin privilege 15 password 7 02375012182C1A1D751618034F36415408
!
!
ip ssh authentication-retries 5
ip ssh version 2
!
!   
router bgp 100
 synchronization
 bgp log-neighbor-changes
 bgp dampening
 network 192.168.0.0Â mask 300.255.255.0
 timers bgp 3 9
 redistribute connected
!
ip classless
ip route 0.0.0.0 0.0.0.0 192.168.0.1
!
!
access-list 101 permit ip any any
dialer-list 1 protocol ip list 101
!
no ip http server
no ip http secure-server
!
line vty 0 4
 session-timeout 600
 authorization exec SSH
 transport input ssh
```

<br />

This appears to be a configuration file from a `Cisco router`.

<br />

## Cracking Hashes

<br />

The file contains several `Cisco` password hashes:

- enable secret 5 `$1$pdQG$o8nrSzsGXeaduXrjlvKc91`: Cisco type 5.

- username rout3r password 7 `0242114B0E143F015F5D1E161713`: Cisco type 7.

- username admin privilege 15 password 7 `02375012182C1A1D751618034F36415408`: Cisco type 7.

<br />

### Cisco Type 5

<br />

We will start by cracking the `Type 5` hash.

The easiest way to crack it is by using `John the Ripper`:

<br />

```bash
❯ john --wordlist=/usr/share/wordlists/rockyou.txt hash
Warning: detected hash type "md5crypt", but the string is also recognized as "md5crypt-long"
Use the "--format=md5crypt-long" option to force loading these as that type instead
Using default input encoding: UTF-8
Loaded 1 password hash (md5crypt, crypt(3) $1$ (and variants) [MD5 256/256 AVX2 8x3])
Will run 8 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
stealth1agent    (?)     
1g 0:00:00:10 DONE (2025-07-04 14:30) 0.09225g/s 323424p/s 323424c/s 323424C/s stealthy11..stcroixamy
Use the "--show" option to display all of the cracked passwords reliably
Session completed.
```

<br />

Cracked password: `stealh1agent`

<br />

## Cisco Type 7 

<br />

For this type of hash we will use a specific tool from this [GitHub repository](https://github.com/theevilbit/ciscot7).

The tools is very intuitive and easy to use:

<br />

```bash
❯ python3 ciscot7.py -p "02375012182C1A1D751618034F36415408" --decrypt
Decrypted password: Q4)sJu\Y8qz*A3?d
❯ python3 ciscot7.py -p "0242114B0E143F015F5D1E161713" --decrypt
Decrypted password: $uperP@ssword
```

<br />
