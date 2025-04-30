---
layout: writeup
category: HTB
date: 2024-12-29
comments: false
tags: subdomainenumeration sqli blindsqlinjection webshell abusingfileupload remotecodeexecution
---

<br />

![1](../../../assets/images/Usage/1.png)

<br />

OS -> Linux.

Difficulty -> Easy.

<br />

# Introduction:

<br />



<br />

# Enumeration:

<br />

We start by running the typical `nmap` scan to see which ports are open:

<br />

```bash
❯ nmap -p- 10.10.11.18 --open --min-rate 5000 -sS -T5 -Pn -n -sCV
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-04-30 13:43 CEST
Nmap scan report for 10.10.11.18
Host is up (0.046s latency).
Not shown: 65468 closed tcp ports (reset), 65 filtered tcp ports (no-response)
Some closed ports may be reported as filtered due to --defeat-rst-ratelimit
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.6 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 a0:f8:fd:d3:04:b8:07:a0:63:dd:37:df:d7:ee:ca:78 (ECDSA)
|_  256 bd:22:f5:28:77:27:fb:65:ba:f6:fd:2f:10:c7:82:8f (ED25519)
80/tcp open  http    nginx 1.18.0 (Ubuntu)
|_http-title: Did not follow redirect to http://usage.htb/
|_http-server-header: nginx/1.18.0 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 21.49 seconds
```

<br />

Open Ports:

- `Port 22` -> ssh

- `Port 80` -> http

<br />

# Http Enumeration: -> Port 80

<br />

When visiting the website, it redirects us to -> `usage.htb`

So we add this domain to our `/etc/hosts`:

<br />

```bash
echo "10.10.11.18 usage.htb" >> /etc/hosts
```

<br />

Now we can load the page:

<br />

![2](../../../assets/images/Usage/2.png)

<br />

On the main page, we find a standard `login` panel. Default credentials don't work.

<br />

### /registration:

<br />

Clicking on `"Register"` (top right), takes us to the `/registration` page.

We can create an account:

<br />

![3](../../../assets/images/Usage/3.png)

<br />

And access it:

<br />

![4](../../../assets/images/Usage/4.png)

<br />

But nothing interesting or helpful is available within the application.

<br />

### admin.usage.htb:

<br />

Another relevant thing of the main page is the top right button `"Admin"`.

If we make hovering, it shows the subdomain -> `http://admin.usage.htb/`.

So, we can add it to `/etc/hosts`:

<br />

```bash
10.10.11.18 usage.htb admin.usage.htb
```

<br />

If we access this subdomain, we will see an admin login panel:

<br />

![5](../../../assets/images/Usage/5.png)

<br />

We test default credentials without success.

### /forget-password:

<br />

Returning to the main page, there is one more functionality.

The `"Reset Password"` link, that takes us to `/forget-password`:

<br />

![6](../../../assets/images/Usage/6.png)

<br />
