---
layout: writeup
category: HTB
date: 2024-12-29
comments: false
tags: 
---

<br />

![1](../../../assets/images/Forest/1.png)

<br />

OS -> Windows.

Difficulty -> Easy.

<br />

# Introduction:

<br />



<br />

# Enumeration:

<br />

We start by running a typical `nmap` scan to see which ports are open:

<br />

```bash
❯ nmap -p- 10.10.10.161 --open --min-rate 5000 -sS -T5 -Pn -n -sCV
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-06-07 11:59 CEST
Nmap scan report for 10.10.10.161
Host is up (0.044s latency).
Not shown: 65239 closed tcp ports (reset), 272 filtered tcp ports (no-response)
Some closed ports may be reported as filtered due to --defeat-rst-ratelimit
PORT      STATE SERVICE      VERSION
53/tcp    open  domain       Simple DNS Plus
88/tcp    open  kerberos-sec Microsoft Windows Kerberos (server time: 2025-06-07 10:08:28Z)
135/tcp   open  msrpc        Microsoft Windows RPC
139/tcp   open  netbios-ssn  Microsoft Windows netbios-ssn
389/tcp   open  ldap         Microsoft Windows Active Directory LDAP (Domain: htb.local, Site: Default-First-Site-Name)
445/tcp   open  microsoft-ds Windows Server 2016 Standard 14393 microsoft-ds (workgroup: HTB)
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http   Microsoft Windows RPC over HTTP 1.0
636/tcp   open  tcpwrapped
3268/tcp  open  ldap         Microsoft Windows Active Directory LDAP (Domain: htb.local, Site: Default-First-Site-Name)
3269/tcp  open  tcpwrapped
5985/tcp  open  http         Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0
9389/tcp  open  mc-nmf       .NET Message Framing
47001/tcp open  http         Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
49664/tcp open  msrpc        Microsoft Windows RPC
49665/tcp open  msrpc        Microsoft Windows RPC
49666/tcp open  msrpc        Microsoft Windows RPC
49668/tcp open  msrpc        Microsoft Windows RPC
49671/tcp open  msrpc        Microsoft Windows RPC
49676/tcp open  ncacn_http   Microsoft Windows RPC over HTTP 1.0
49677/tcp open  msrpc        Microsoft Windows RPC
49684/tcp open  msrpc        Microsoft Windows RPC
49706/tcp open  msrpc        Microsoft Windows RPC
49966/tcp open  msrpc        Microsoft Windows RPC
Service Info: Host: FOREST; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled and required
| smb2-time: 
|   date: 2025-06-07T10:09:21
|_  start_date: 2025-06-07T10:00:26
| smb-security-mode: 
|   account_used: guest
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: required
| smb-os-discovery: 
|   OS: Windows Server 2016 Standard 14393 (Windows Server 2016 Standard 6.3)
|   Computer name: FOREST
|   NetBIOS computer name: FOREST\x00
|   Domain name: htb.local
|   Forest name: htb.local
|   FQDN: FOREST.htb.local
|_  System time: 2025-06-07T03:09:20-07:00
|_clock-skew: mean: 2h28m11s, deviation: 4h02m31s, median: 8m10s

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 79.43 seconds
```

<br />

Relevant open ports:

- `Port 53`   -> dns

- `Port 88`   -> kerberos

- `Port 135`  -> rpc

- `Port 139`  -> netbios

- `Port 389`  -> ldap

- `Port 445`  -> smb

- `Port 464`  -> kpasswd (kerberos password change)

- `Port 593`  -> rpc over http

- `Port 636`  -> ldaps

- `Port 5985` -> winrm

<br />

The domain `htb.local` and the FQDN `FOREST.htb.local` appear across multiple services and ports, so I’ll add them to my `/etc/hosts` file:

<br />

```bash
10.10.10.161 htb.local FOREST.htb.local
```

<br />

# DNS Enumeration: -> Port 53

<br />

We can resolve `htb.local` to make a DNS consult with `dig`:

<br />

```bash
❯ dig htb.local @10.10.10.161

; <<>> DiG 9.18.33-1~deb12u2-Debian <<>> htb.local @10.10.10.161
;; global options: +cmd
;; Got answer:
;; WARNING: .local is reserved for Multicast DNS
;; You are currently testing what happens when an mDNS query is leaked to DNS
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 62451
;; flags: qr aa rd ra; QUERY: 1, ANSWER: 1, AUTHORITY: 0, ADDITIONAL: 1

;; OPT PSEUDOSECTION:
; EDNS: version: 0, flags:; udp: 4000
; COOKIE: 5b92f1f0c9eb1852 (echoed)
;; QUESTION SECTION:
;htb.local.			IN	A

;; ANSWER SECTION:
htb.local.		600	IN	A	10.10.10.161

;; Query time: 60 msec
;; SERVER: 10.10.10.161#53(10.10.10.161) (UDP)
;; WHEN: Sat Jun 07 12:08:08 CEST 2025
;; MSG SIZE  rcvd: 66
```

<br />

But we can't do a complete zone transfer:

<br />

```bash
❯ dig axfr htb.local @10.10.10.161

; <<>> DiG 9.18.33-1~deb12u2-Debian <<>> axfr htb.local @10.10.10.161
;; global options: +cmd
; Transfer failed.
```

<br />

# SMB Enumeration: -> Port 445

<br />

To start enumerating some information about the system, we will run a typical `netexec` oneliner:

<br />

```bash
❯ netexec smb htb.local
SMB         10.10.10.161    445    FOREST           [*] Windows Server 2016 Standard 14393 x64 (name:FOREST) (domain:htb.local) (signing:True) (SMBv1:True)
```

<br />

With this output, we verify the domain `htb.local`, which we discovered before with nmap.

We can verify that we're dealing with a `Windows Server 2016 Standard` and `14393` build version.

Continuing enumeration, we use a fake user and pass to get more information without success:

<br />

```bash
❯ netexec smb htb.local -u "RandomFakeUser" -p "RandomFakePass" --shares
SMB         10.10.10.161    445    FOREST           [*] Windows Server 2016 Standard 14393 x64 (name:FOREST) (domain:htb.local) (signing:True) (SMBv1:True)
SMB         10.10.10.161    445    FOREST           [-] htb.local\RandomFakeUser:RandomFakePass STATUS_LOGON_FAILURE 
```

<br />

Trying to use a null session doesn't work either.

<br />

# LDAP Enumeration: -> Port 389
