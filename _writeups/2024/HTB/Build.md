---
layout: writeup
category: HTB
date: 2024-12-29
comments: false
tags: 
---

<br />

![1](../../../assets/images/Build/1.png)

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
❯ nmap -p- 10.129.234.169 --open --min-rate 5000 -sS -T5 -Pn -n -sCV
Starting Nmap 7.94SVN ( https://nmap.org ) at 2026-01-08 17:56 CET
Nmap scan report for 10.129.234.169
Host is up (0.047s latency).
Not shown: 65489 closed tcp ports (reset), 39 filtered tcp ports (no-response)
Some closed ports may be reported as filtered due to --defeat-rst-ratelimit
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.13 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 47:21:73:e2:6b:96:cd:f9:13:11:af:40:c8:4d:d6:7f (ECDSA)
|_  256 2b:5e:ba:f3:72:d3:b3:09:df:25:41:29:09:f4:7b:f5 (ED25519)
53/tcp   open  domain  PowerDNS
| dns-nsid: 
|   NSID: pdns (70646e73)
|_  id.server: pdns
512/tcp  open  exec    netkit-rsh rexecd
513/tcp  open  login?
514/tcp  open  shell   Netkit rshd
873/tcp  open  rsync   (protocol version 31)
3000/tcp open  ppp?
| fingerprint-strings: 
|   GenericLines, Help, RTSPRequest: 
|     HTTP/1.1 400 Bad Request
|     Content-Type: text/plain; charset=utf-8
|     Connection: close
|     Request
|   GetRequest: 
|     HTTP/1.0 200 OK
|     Cache-Control: max-age=0, private, must-revalidate, no-transform
|     Content-Type: text/html; charset=utf-8
|     Set-Cookie: i_like_gitea=d42d59cd04fd9e30; Path=/; HttpOnly; SameSite=Lax
|     Set-Cookie: _csrf=BVCyVt7uKyFUp1jqpX5H-PWvcFQ6MTc2Nzg5MTM4MDM0OTMyMzg5NA; Path=/; Max-Age=86400; HttpOnly; SameSite=Lax
|     X-Frame-Options: SAMEORIGIN
|     Date: Thu, 08 Jan 2026 16:56:20 GMT
|     <!DOCTYPE html>
|     <html lang="en-US" class="theme-auto">
|     <head>
|     <meta name="viewport" content="width=device-width, initial-scale=1">
|     <title>Gitea: Git with a cup of tea</title>
|     <link rel="manifest" href="data:application/json;base64,eyJuYW1lIjoiR2l0ZWE6IEdpdCB3aXRoIGEgY3VwIG9mIHRlYSIsInNob3J0X25hbWUiOiJHaXRlYTogR2l0IHdpdGggYSBjdXAgb2YgdGVhIiwic3RhcnRfdXJsIjoiaHR0cDovL2J1aWxkLnZsOjMwMDAvIiwiaWNvbnMiOlt7InNyYyI6Imh0dHA6Ly9idWlsZC52bDozMDAwL2Fzc2V0cy9pbWcvbG9nby5wbmciLCJ0eXBlIjoiaW1hZ2UvcG5nIiwic2l6ZXMiOiI1MTJ
|   HTTPOptions: 
|     HTTP/1.0 405 Method Not Allowed
|     Allow: HEAD
|     Allow: GET
|     Cache-Control: max-age=0, private, must-revalidate, no-transform
|     Set-Cookie: i_like_gitea=2dbe926108bf86ec; Path=/; HttpOnly; SameSite=Lax
|     Set-Cookie: _csrf=OhAgaBmtJ4dlgmOykPiT6YzEy9k6MTc2Nzg5MTM4NjUzNTU2NTY4OQ; Path=/; Max-Age=86400; HttpOnly; SameSite=Lax
|     X-Frame-Options: SAMEORIGIN
|     Date: Thu, 08 Jan 2026 16:56:26 GMT
|_    Content-Length: 0
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port3000-TCP:V=7.94SVN%I=7%D=1/8%Time=695FE1B4%P=x86_64-pc-linux-gnu%r(
SF:GenericLines,67,"HTTP/1\.1\x20400\x20Bad\x20Request\r\nContent-Type:\x2
SF:0text/plain;\x20charset=utf-8\r\nConnection:\x20close\r\n\r\n400\x20Bad
SF:\x20Request")%r(GetRequest,383A,"HTTP/1\.0\x20200\x20OK\r\nCache-Contro
SF:l:\x20max-age=0,\x20private,\x20must-revalidate,\x20no-transform\r\nCon
SF:tent-Type:\x20text/html;\x20charset=utf-8\r\nSet-Cookie:\x20i_like_gite
SF:a=d42d59cd04fd9e30;\x20Path=/;\x20HttpOnly;\x20SameSite=Lax\r\nSet-Cook
SF:ie:\x20_csrf=BVCyVt7uKyFUp1jqpX5H-PWvcFQ6MTc2Nzg5MTM4MDM0OTMyMzg5NA;\x2
SF:0Path=/;\x20Max-Age=86400;\x20HttpOnly;\x20SameSite=Lax\r\nX-Frame-Opti
SF:ons:\x20SAMEORIGIN\r\nDate:\x20Thu,\x2008\x20Jan\x202026\x2016:56:20\x2
SF:0GMT\r\n\r\n<!DOCTYPE\x20html>\n<html\x20lang=\"en-US\"\x20class=\"them
SF:e-auto\">\n<head>\n\t<meta\x20name=\"viewport\"\x20content=\"width=devi
SF:ce-width,\x20initial-scale=1\">\n\t<title>Gitea:\x20Git\x20with\x20a\x2
SF:0cup\x20of\x20tea</title>\n\t<link\x20rel=\"manifest\"\x20href=\"data:a
SF:pplication/json;base64,eyJuYW1lIjoiR2l0ZWE6IEdpdCB3aXRoIGEgY3VwIG9mIHRl
SF:YSIsInNob3J0X25hbWUiOiJHaXRlYTogR2l0IHdpdGggYSBjdXAgb2YgdGVhIiwic3RhcnR
SF:fdXJsIjoiaHR0cDovL2J1aWxkLnZsOjMwMDAvIiwiaWNvbnMiOlt7InNyYyI6Imh0dHA6Ly
SF:9idWlsZC52bDozMDAwL2Fzc2V0cy9pbWcvbG9nby5wbmciLCJ0eXBlIjoiaW1hZ2UvcG5nI
SF:iwic2l6ZXMiOiI1MTJ")%r(Help,67,"HTTP/1\.1\x20400\x20Bad\x20Request\r\nC
SF:ontent-Type:\x20text/plain;\x20charset=utf-8\r\nConnection:\x20close\r\
SF:n\r\n400\x20Bad\x20Request")%r(HTTPOptions,197,"HTTP/1\.0\x20405\x20Met
SF:hod\x20Not\x20Allowed\r\nAllow:\x20HEAD\r\nAllow:\x20GET\r\nCache-Contr
SF:ol:\x20max-age=0,\x20private,\x20must-revalidate,\x20no-transform\r\nSe
SF:t-Cookie:\x20i_like_gitea=2dbe926108bf86ec;\x20Path=/;\x20HttpOnly;\x20
SF:SameSite=Lax\r\nSet-Cookie:\x20_csrf=OhAgaBmtJ4dlgmOykPiT6YzEy9k6MTc2Nz
SF:g5MTM4NjUzNTU2NTY4OQ;\x20Path=/;\x20Max-Age=86400;\x20HttpOnly;\x20Same
SF:Site=Lax\r\nX-Frame-Options:\x20SAMEORIGIN\r\nDate:\x20Thu,\x2008\x20Ja
SF:n\x202026\x2016:56:26\x20GMT\r\nContent-Length:\x200\r\n\r\n")%r(RTSPRe
SF:quest,67,"HTTP/1\.1\x20400\x20Bad\x20Request\r\nContent-Type:\x20text/p
SF:lain;\x20charset=utf-8\r\nConnection:\x20close\r\n\r\n400\x20Bad\x20Req
SF:uest");
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 111.96 seconds
```

<br />

Open Ports:

- `Port 22` -> SSH

- `Port 53` -> DNS

- `Port 512` -> Rexec 

- `Port 153` -> Rlogin 

- `Port 514` -> Rsh

- `Port 873` -> Rsync

- `Port 3000` -> HTTP


<br />

# Http Enumeration: Port -> 3000 

<br />



