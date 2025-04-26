---
layout: writeup
category: HTB
date: 2024-12-29
comments: false
tags: 
---

<br />

![1](../../../assets/images/MonitorsThree/1.png)

<br />

OS -> Linux.

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
❯ nmap -p- 10.10.11.30 --open --min-rate 5000 -sS -T5 -Pn -n -sCV
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-04-26 18:25 CEST
Nmap scan report for 10.10.11.30
Host is up (0.045s latency).
Not shown: 65447 closed tcp ports (reset), 86 filtered tcp ports (no-response)
Some closed ports may be reported as filtered due to --defeat-rst-ratelimit
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.10 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 86:f8:7d:6f:42:91:bb:89:72:91:af:72:f3:01:ff:5b (ECDSA)
|_  256 50:f9:ed:8e:73:64:9e:aa:f6:08:95:14:f0:a6:0d:57 (ED25519)
80/tcp open  http    nginx 1.18.0 (Ubuntu)
|_http-title: Did not follow redirect to http://monitorsthree.htb/
|_http-server-header: nginx/1.18.0 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 21.61 seconds
```

<br />

Open Ports:

`Port 22` -> ssh 

`Port 80` -> http

<br />

# Http Enumeration: -> Port 80

<br />

To access the main website, first we need to add `monitorsthree.htb` to our `/etc/hosts`:

<br />

```bash
❯ echo '10.10.11.30 monitorsthree.htb' >> /etc/hosts
```

<br />

Now we can visit the page:

<br />

![2](../../../assets/images/MonitorsThree/2.png)

<br />

It has two functionalities available.

A login panel at `/login.php`:

<br />

![3](../../../assets/images/MonitorsThree/3.png)

<br />

And the typical "Forgot Password" page at `/forgot_password.php`:

<br />

![4](../../../assets/images/MonitorsThree/4.png)

<br />

## Subdomain Fuzzing:

<br />

Before testing these functionalities, we are going to perform some `fuzzing` on the main `domain`:

<br />

```bash
❯ ffuf -u http://monitorsthree.htb -H "Host: FUZZ.monitorsthree.htb" -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt -c -t 20 -fs 13560

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.1.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://monitorsthree.htb
 :: Wordlist         : FUZZ: /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt
 :: Header           : Host: FUZZ.monitorsthree.htb
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 20
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
 :: Filter           : Response size: 13560
________________________________________________

cacti                   [Status: 302, Size: 0, Words: 1, Lines: 1, Duration: 44ms]
:: Progress: [4989/4989] :: Job [1/1] :: 432 req/sec :: Duration: [0:00:12] :: Errors: 0 ::
```

<br />

Perfect! We have a new `subdomain`!

<br />

## cacti.monitorsthree.htb:

<br />

Let's add it to our `/etc/hosts`:

<br />

```bash
10.10.11.30 monitorsthree.htb cacti.monitorsthee.htb
```

<br />

Once we have added the `subdomain`, we can visit the page:

<br />



<br />
