---
layout: writeup
category: HTB
date: 2024-12-29
comments: false
tags: sandbox library scripting bash hash cracking bruteforce sqlite3 sudoers reverseshell bcrypt blowfish 
---

<br />

![Icon-Image](../../../assets/images/Stratosphere/1.png)

<br />

# Introduction:

<br />


 
<br />

# Enumeration:

<br />

As always we are going to start with a nmap scan:

<br />

```bash
❯ nmap -p- 10.10.10.64 --open --min-rate 5000 -sS -T5 -Pn -n -sCV
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-01-08 22:17 CET
Nmap scan report for 10.10.10.64
Host is up (0.057s latency).
Not shown: 65533 filtered tcp ports (no-response)
Some closed ports may be reported as filtered due to --defeat-rst-ratelimit
PORT     STATE SERVICE    VERSION
22/tcp   open  ssh        OpenSSH 7.9p1 Debian 10+deb10u3 (protocol 2.0)
| ssh-hostkey: 
|   2048 5b:16:37:d4:3c:18:04:15:c4:02:01:0d:db:07:ac:2d (RSA)
|   256 e3:77:7b:2c:23:b0:8d:df:38:35:6c:40:ab:f6:81:50 (ECDSA)
|_  256 d7:6b:66:9c:19:fc:aa:66:6c:18:7a:cc:b5:87:0e:40 (ED25519)
8080/tcp open  http-proxy
|_http-open-proxy: Proxy might be redirecting requests
|_http-title: Stratosphere
| fingerprint-strings: 
|   GetRequest: 
|     HTTP/1.1 200 
|     Accept-Ranges: bytes
|     ETag: W/"1708-1519762495651"
|     Last-Modified: Tue, 27 Feb 2018 20:14:55 GMT
|     Content-Type: text/html
|     Content-Length: 1708
|     Date: Wed, 08 Jan 2025 19:18:36 GMT
|     Connection: close
|     <!DOCTYPE html>
|     <html>
|     <head>
|     <meta charset="utf-8"/>
|     <title>Stratosphere</title>
|     <link rel="stylesheet" type="text/css" href="main.css">
|     </head>
|     <body>
|     <div id="background"></div>
|     <header id="main-header" class="hidden">
|     <div class="container">
|     <div class="content-wrap">
|     <p><i class="fa fa-diamond"></i></p>
|     <nav>
|     class="btn" href="GettingStarted.html">Get started</a>
|     </nav>
|     </div>
|     </div>
|     </header>
|     <section id="greeting">
|     <div class="container">
|     <div class="content-wrap">
|     <h1>Stratosphere<br>We protect your credit.</h1>
|     class="btn" href="GettingStarted.html">Get started now</a>
|     <p><i class="ar
|   HTTPOptions: 
|     HTTP/1.1 200 
|     Allow: OPTIONS, GET, HEAD, POST
|     Content-Length: 0
|     Date: Wed, 08 Jan 2025 19:18:36 GMT
|     Connection: close
|   RTSPRequest: 
|     HTTP/1.1 400 
|     Content-Type: text/html;charset=utf-8
|     Content-Language: en
|     Content-Length: 1874
|     Date: Wed, 08 Jan 2025 19:18:36 GMT
|     Connection: close
|     <!doctype html><html lang="en"><head><title>HTTP Status 400 
|     Request</title><style type="text/css">body {font-family:Tahoma,Arial,sans-serif;} h1, h2, h3, b {color:white;background-color:#525D76;} h1 {font-size:22px;} h2 {font-size:16px;} h3 {font-size:14px;} p {font-size:12px;} a {color:black;} .line {height:1px;background-color:#525D76;border:none;}</style></head><body><h1>HTTP Status 400 
|_    Request</h1><hr class="line" /><p><b>Type</b> Exception Report</p><p><b>Message</b> Invalid character found in the HTTP protocol</p><p><b>Description</b> The server cannot or will not process the request due to something that is perceived to be a client error (e.g., malformed request syntax, invalid request message framing, or decept
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port8080-TCP:V=7.94SVN%I=7%D=1/8%Time=677EEB97%P=x86_64-pc-linux-gnu%r(
SF:GetRequest,786,"HTTP/1\.1\x20200\x20\r\nAccept-Ranges:\x20bytes\r\nETag
SF::\x20W/\"1708-1519762495651\"\r\nLast-Modified:\x20Tue,\x2027\x20Feb\x2
SF:02018\x2020:14:55\x20GMT\r\nContent-Type:\x20text/html\r\nContent-Lengt
SF:h:\x201708\r\nDate:\x20Wed,\x2008\x20Jan\x202025\x2019:18:36\x20GMT\r\n
SF:Connection:\x20close\r\n\r\n<!DOCTYPE\x20html>\n<html>\n<head>\n\x20\x2
SF:0\x20\x20<meta\x20charset=\"utf-8\"/>\n\x20\x20\x20\x20<title>Stratosph
SF:ere</title>\n\x20\x20\x20\x20<link\x20rel=\"stylesheet\"\x20type=\"text
SF:/css\"\x20href=\"main\.css\">\n</head>\n\n<body>\n<div\x20id=\"backgrou
SF:nd\"></div>\n<header\x20id=\"main-header\"\x20class=\"hidden\">\n\x20\x
SF:20<div\x20class=\"container\">\n\x20\x20\x20\x20<div\x20class=\"content
SF:-wrap\">\n\x20\x20\x20\x20\x20\x20<p><i\x20class=\"fa\x20fa-diamond\"><
SF:/i></p>\n\x20\x20\x20\x20\x20\x20<nav>\n\x20\x20\x20\x20\x20\x20\x20\x2
SF:0<a\x20class=\"btn\"\x20href=\"GettingStarted\.html\">Get\x20started</a
SF:>\n\x20\x20\x20\x20\x20\x20</nav>\n\x20\x20\x20\x20</div>\n\x20\x20</di
SF:v>\n</header>\n\n<section\x20id=\"greeting\">\n\x20\x20<div\x20class=\"
SF:container\">\n\x20\x20\x20\x20<div\x20class=\"content-wrap\">\n\x20\x20
SF:\x20\x20\x20\x20<h1>Stratosphere<br>We\x20protect\x20your\x20credit\.</
SF:h1>\n\x20\x20\x20\x20\x20\x20<a\x20class=\"btn\"\x20href=\"GettingStart
SF:ed\.html\">Get\x20started\x20now</a>\n\x20\x20\x20\x20\x20\x20<p><i\x20
SF:class=\"ar")%r(HTTPOptions,7D,"HTTP/1\.1\x20200\x20\r\nAllow:\x20OPTION
SF:S,\x20GET,\x20HEAD,\x20POST\r\nContent-Length:\x200\r\nDate:\x20Wed,\x2
SF:008\x20Jan\x202025\x2019:18:36\x20GMT\r\nConnection:\x20close\r\n\r\n")
SF:%r(RTSPRequest,7EE,"HTTP/1\.1\x20400\x20\r\nContent-Type:\x20text/html;
SF:charset=utf-8\r\nContent-Language:\x20en\r\nContent-Length:\x201874\r\n
SF:Date:\x20Wed,\x2008\x20Jan\x202025\x2019:18:36\x20GMT\r\nConnection:\x2
SF:0close\r\n\r\n<!doctype\x20html><html\x20lang=\"en\"><head><title>HTTP\
SF:x20Status\x20400\x20\xe2\x80\x93\x20Bad\x20Request</title><style\x20typ
SF:e=\"text/css\">body\x20{font-family:Tahoma,Arial,sans-serif;}\x20h1,\x2
SF:0h2,\x20h3,\x20b\x20{color:white;background-color:#525D76;}\x20h1\x20{f
SF:ont-size:22px;}\x20h2\x20{font-size:16px;}\x20h3\x20{font-size:14px;}\x
SF:20p\x20{font-size:12px;}\x20a\x20{color:black;}\x20\.line\x20{height:1p
SF:x;background-color:#525D76;border:none;}</style></head><body><h1>HTTP\x
SF:20Status\x20400\x20\xe2\x80\x93\x20Bad\x20Request</h1><hr\x20class=\"li
SF:ne\"\x20/><p><b>Type</b>\x20Exception\x20Report</p><p><b>Message</b>\x2
SF:0Invalid\x20character\x20found\x20in\x20the\x20HTTP\x20protocol</p><p><
SF:b>Description</b>\x20The\x20server\x20cannot\x20or\x20will\x20not\x20pr
SF:ocess\x20the\x20request\x20due\x20to\x20something\x20that\x20is\x20perc
SF:eived\x20to\x20be\x20a\x20client\x20error\x20\(e\.g\.,\x20malformed\x20
SF:request\x20syntax,\x20invalid\x20request\x20message\x20framing,\x20or\x
SF:20decept");
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 47.13 seconds
```

<br />

We have two open ports:

<br />

- Port 22 -> ssh 
- Port 8080 -> http 

<br />

# Web Enumeration: -> Port 8080

<br />

We proceed to list the website and it seems that it is still being developed since there are not many things:

<br />


