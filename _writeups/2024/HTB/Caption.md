---
layout: writeup
category: HTB
date: 2024-12-29
comments: false
tags: 
---

<br />

![1](../../../assets/images/Caption/1.png)

<br />

OS -> Linux.

Difficulty -> Hard.

<br />

# Introduction:

<br />



<br />

# Enumeration:

<br />

We begin with a standard `nmap` scan to identify open ports:

<br />

```bash
❯ nmap -p- 10.10.11.33 --open --min-rate 5000 -sS -T5 -Pn -n -sCV
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-06-30 11:26 CEST
Nmap scan report for 10.10.11.33
Host is up (0.042s latency).
Not shown: 65481 closed tcp ports (reset), 51 filtered tcp ports (no-response)
Some closed ports may be reported as filtered due to --defeat-rst-ratelimit
PORT     STATE SERVICE    VERSION
22/tcp   open  ssh        OpenSSH 8.9p1 Ubuntu 3ubuntu0.10 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 3e:ea:45:4b:c5:d1:6d:6f:e2:d4:d1:3b:0a:3d:a9:4f (ECDSA)
|_  256 64:cc:75:de:4a:e6:a5:b4:73:eb:3f:1b:cf:b4:e3:94 (ED25519)
80/tcp   open  http
|_http-title: Did not follow redirect to http://caption.htb
| fingerprint-strings: 
|   DNSStatusRequestTCP, DNSVersionBindReqTCP, Help, RPCCheck, RTSPRequest, X11Probe: 
|     HTTP/1.1 400 Bad request
|     Content-length: 90
|     Cache-Control: no-cache
|     Connection: close
|     Content-Type: text/html
|     <html><body><h1>400 Bad request</h1>
|     Your browser sent an invalid request.
|     </body></html>
|   FourOhFourRequest, GetRequest, HTTPOptions: 
|     HTTP/1.1 301 Moved Permanently
|     content-length: 0
|     location: http://caption.htb
|_    connection: close
8080/tcp open  http-proxy
|_http-title: GitBucket
| fingerprint-strings: 
|   FourOhFourRequest: 
|     HTTP/1.1 404 Not Found
|     Date: Mon, 30 Jun 2025 09:26:01 GMT
|     Set-Cookie: JSESSIONID=node0mrmflj29qv1x1fb73scwwnycp4.node0; Path=/; HttpOnly
|     Expires: Thu, 01 Jan 1970 00:00:00 GMT
|     Content-Type: text/html;charset=utf-8
|     Content-Length: 5916
|     <!DOCTYPE html>
|     <html prefix="og: http://ogp.me/ns#" lang="en">
|     <head>
|     <meta charset="UTF-8" />
|     <meta name="viewport" content="width=device-width, initial-scale=1.0, maximum-scale=5.0" />
|     <meta http-equiv="X-UA-Compatible" content="IE=edge" />
|     <title>Error</title>
|     <meta property="og:title" content="Error" />
|     <meta property="og:type" content="object" />
|     <meta property="og:url" content="http://10.10.11.33:8080/nice%20ports%2C/Tri%6Eity.txt%2ebak" />
|     <meta property="og:image" content="http://10.10.11.33:8080/assets/common/images/gitbucket_ogp.png" />
|     <link rel="icon" href="/assets/common/images/gi
|   GetRequest: 
|     HTTP/1.1 200 OK
|     Date: Mon, 30 Jun 2025 09:26:01 GMT
|     Set-Cookie: JSESSIONID=node01s5sz94d5atb2778ruxss898c2.node0; Path=/; HttpOnly
|     Expires: Thu, 01 Jan 1970 00:00:00 GMT
|     Content-Type: text/html;charset=utf-8
|     Content-Length: 8628
|     <!DOCTYPE html>
|     <html prefix="og: http://ogp.me/ns#" lang="en">
|     <head>
|     <meta charset="UTF-8" />
|     <meta name="viewport" content="width=device-width, initial-scale=1.0, maximum-scale=5.0" />
|     <meta http-equiv="X-UA-Compatible" content="IE=edge" />
|     <title>GitBucket</title>
|     <meta property="og:title" content="GitBucket" />
|     <meta property="og:type" content="object" />
|     <meta property="og:url" content="http://10.10.11.33:8080/" />
|     <meta property="og:image" content="http://10.10.11.33:8080/assets/common/images/gitbucket_ogp.png" />
|     <link rel="icon" href="/assets/common/images/gitbucket.png?20250630092430" type="
|   HTTPOptions: 
|     HTTP/1.1 200 OK
|     Date: Mon, 30 Jun 2025 09:26:01 GMT
|     Set-Cookie: JSESSIONID=node01jdrq8a4kds2e1ofe86ytscj3l3.node0; Path=/; HttpOnly
|     Expires: Thu, 01 Jan 1970 00:00:00 GMT
|     Content-Type: text/html;charset=utf-8
|     Allow: GET,HEAD,POST,OPTIONS
|     Content-Length: 0
|   RTSPRequest: 
|     HTTP/1.1 505 HTTP Version Not Supported
|     Content-Type: text/html;charset=iso-8859-1
|     Content-Length: 58
|     Connection: close
|_    <h1>Bad Message 505</h1><pre>reason: Unknown Version</pre>
2 services unrecognized despite returning data. If you know the service/version, please submit the following fingerprints at https://nmap.org/cgi-bin/submit.cgi?new-service :
==============NEXT SERVICE FINGERPRINT (SUBMIT INDIVIDUALLY)==============
SF-Port80-TCP:V=7.94SVN%I=7%D=6/30%Time=6862585C%P=x86_64-pc-linux-gnu%r(G
SF:etRequest,66,"HTTP/1\.1\x20301\x20Moved\x20Permanently\r\ncontent-lengt
SF:h:\x200\r\nlocation:\x20http://caption\.htb\r\nconnection:\x20close\r\n
SF:\r\n")%r(HTTPOptions,66,"HTTP/1\.1\x20301\x20Moved\x20Permanently\r\nco
SF:ntent-length:\x200\r\nlocation:\x20http://caption\.htb\r\nconnection:\x
SF:20close\r\n\r\n")%r(RTSPRequest,CF,"HTTP/1\.1\x20400\x20Bad\x20request\
SF:r\nContent-length:\x2090\r\nCache-Control:\x20no-cache\r\nConnection:\x
SF:20close\r\nContent-Type:\x20text/html\r\n\r\n<html><body><h1>400\x20Bad
SF:\x20request</h1>\nYour\x20browser\x20sent\x20an\x20invalid\x20request\.
SF:\n</body></html>\n")%r(X11Probe,CF,"HTTP/1\.1\x20400\x20Bad\x20request\
SF:r\nContent-length:\x2090\r\nCache-Control:\x20no-cache\r\nConnection:\x
SF:20close\r\nContent-Type:\x20text/html\r\n\r\n<html><body><h1>400\x20Bad
SF:\x20request</h1>\nYour\x20browser\x20sent\x20an\x20invalid\x20request\.
SF:\n</body></html>\n")%r(FourOhFourRequest,66,"HTTP/1\.1\x20301\x20Moved\
SF:x20Permanently\r\ncontent-length:\x200\r\nlocation:\x20http://caption\.
SF:htb\r\nconnection:\x20close\r\n\r\n")%r(RPCCheck,CF,"HTTP/1\.1\x20400\x
SF:20Bad\x20request\r\nContent-length:\x2090\r\nCache-Control:\x20no-cache
SF:\r\nConnection:\x20close\r\nContent-Type:\x20text/html\r\n\r\n<html><bo
SF:dy><h1>400\x20Bad\x20request</h1>\nYour\x20browser\x20sent\x20an\x20inv
SF:alid\x20request\.\n</body></html>\n")%r(DNSVersionBindReqTCP,CF,"HTTP/1
SF:\.1\x20400\x20Bad\x20request\r\nContent-length:\x2090\r\nCache-Control:
SF:\x20no-cache\r\nConnection:\x20close\r\nContent-Type:\x20text/html\r\n\
SF:r\n<html><body><h1>400\x20Bad\x20request</h1>\nYour\x20browser\x20sent\
SF:x20an\x20invalid\x20request\.\n</body></html>\n")%r(DNSStatusRequestTCP
SF:,CF,"HTTP/1\.1\x20400\x20Bad\x20request\r\nContent-length:\x2090\r\nCac
SF:he-Control:\x20no-cache\r\nConnection:\x20close\r\nContent-Type:\x20tex
SF:t/html\r\n\r\n<html><body><h1>400\x20Bad\x20request</h1>\nYour\x20brows
SF:er\x20sent\x20an\x20invalid\x20request\.\n</body></html>\n")%r(Help,CF,
SF:"HTTP/1\.1\x20400\x20Bad\x20request\r\nContent-length:\x2090\r\nCache-C
SF:ontrol:\x20no-cache\r\nConnection:\x20close\r\nContent-Type:\x20text/ht
SF:ml\r\n\r\n<html><body><h1>400\x20Bad\x20request</h1>\nYour\x20browser\x
SF:20sent\x20an\x20invalid\x20request\.\n</body></html>\n");
==============NEXT SERVICE FINGERPRINT (SUBMIT INDIVIDUALLY)==============
SF-Port8080-TCP:V=7.94SVN%I=7%D=6/30%Time=6862585C%P=x86_64-pc-linux-gnu%r
SF:(GetRequest,22A1,"HTTP/1\.1\x20200\x20OK\r\nDate:\x20Mon,\x2030\x20Jun\
SF:x202025\x2009:26:01\x20GMT\r\nSet-Cookie:\x20JSESSIONID=node01s5sz94d5a
SF:tb2778ruxss898c2\.node0;\x20Path=/;\x20HttpOnly\r\nExpires:\x20Thu,\x20
SF:01\x20Jan\x201970\x2000:00:00\x20GMT\r\nContent-Type:\x20text/html;char
SF:set=utf-8\r\nContent-Length:\x208628\r\n\r\n<!DOCTYPE\x20html>\n<html\x
SF:20prefix=\"og:\x20http://ogp\.me/ns#\"\x20lang=\"en\">\n\x20\x20<head>\
SF:n\x20\x20\x20\x20<meta\x20charset=\"UTF-8\"\x20/>\n\x20\x20\x20\x20<met
SF:a\x20name=\"viewport\"\x20content=\"width=device-width,\x20initial-scal
SF:e=1\.0,\x20maximum-scale=5\.0\"\x20/>\n\x20\x20\x20\x20<meta\x20http-eq
SF:uiv=\"X-UA-Compatible\"\x20content=\"IE=edge\"\x20/>\n\x20\x20\x20\x20<
SF:title>GitBucket</title>\n\x20\x20\x20\x20<meta\x20property=\"og:title\"
SF:\x20content=\"GitBucket\"\x20/>\n\x20\x20\x20\x20<meta\x20property=\"og
SF::type\"\x20content=\"object\"\x20/>\n\x20\x20\x20\x20<meta\x20property=
SF:\"og:url\"\x20content=\"http://10\.10\.11\.33:8080/\"\x20/>\n\x20\x20\x
SF:20\x20\n\x20\x20\x20\x20\x20\x20<meta\x20property=\"og:image\"\x20conte
SF:nt=\"http://10\.10\.11\.33:8080/assets/common/images/gitbucket_ogp\.png
SF:\"\x20/>\n\x20\x20\x20\x20\n\x20\x20\x20\x20\n\x20\x20\x20\x20<link\x20
SF:rel=\"icon\"\x20href=\"/assets/common/images/gitbucket\.png\?2025063009
SF:2430\"\x20type=\"")%r(HTTPOptions,109,"HTTP/1\.1\x20200\x20OK\r\nDate:\
SF:x20Mon,\x2030\x20Jun\x202025\x2009:26:01\x20GMT\r\nSet-Cookie:\x20JSESS
SF:IONID=node01jdrq8a4kds2e1ofe86ytscj3l3\.node0;\x20Path=/;\x20HttpOnly\r
SF:\nExpires:\x20Thu,\x2001\x20Jan\x201970\x2000:00:00\x20GMT\r\nContent-T
SF:ype:\x20text/html;charset=utf-8\r\nAllow:\x20GET,HEAD,POST,OPTIONS\r\nC
SF:ontent-Length:\x200\r\n\r\n")%r(RTSPRequest,B8,"HTTP/1\.1\x20505\x20HTT
SF:P\x20Version\x20Not\x20Supported\r\nContent-Type:\x20text/html;charset=
SF:iso-8859-1\r\nContent-Length:\x2058\r\nConnection:\x20close\r\n\r\n<h1>
SF:Bad\x20Message\x20505</h1><pre>reason:\x20Unknown\x20Version</pre>")%r(
SF:FourOhFourRequest,1810,"HTTP/1\.1\x20404\x20Not\x20Found\r\nDate:\x20Mo
SF:n,\x2030\x20Jun\x202025\x2009:26:01\x20GMT\r\nSet-Cookie:\x20JSESSIONID
SF:=node0mrmflj29qv1x1fb73scwwnycp4\.node0;\x20Path=/;\x20HttpOnly\r\nExpi
SF:res:\x20Thu,\x2001\x20Jan\x201970\x2000:00:00\x20GMT\r\nContent-Type:\x
SF:20text/html;charset=utf-8\r\nCont
```

<br />

Open Ports:

`Port 22` -> ssh 

`Port 80` -> http 

`Port 8080` -> http

<br />

# Http Enumeration: -> Port 80 

<br />

When we try to load the website, it redirects to -> `http://caption.htb`.

So we proceed to add this domain to our `/etc/hosts`:

<br />

```bash
10.10.11.33 caption.htb
```

<br />

This website shows a login page:

<br />

![2](../../../assets/images/Caption/2.png)

<br />

We try default credentials and some SQL Injection bypass (' or 1=1-- -'), but without success.

<br />

## Tech Stack:

<br />

From the server response, we can gather some technology information:

<br />

```bash
HTTP/1.1 200 OK
server: Werkzeug/3.0.1 Python/3.10.12
date: Mon, 16 Sep 2024 21:31:47 GMT
content-type: text/html; charset=utf-8
content-length: 4412
x-varnish: 32784
age: 0
via: 1.1 varnish (Varnish/6.6)
x-cache: MISS
accept-ranges: bytes
```

<br />

As we can see, we're dealing with a `Werkzeug 3.0.1`, so it seems that the application backend is written in Python.

Some other interesting headers are:

`x-varnish`:  Header added because a Varnish cache server is present (website booster).

`age`: Time elapsed since the resource was last cached.

`via`: Indicates that the response has been processed by a Varnish cache server

`x-cache: MISS`: Indicates that the resource was not found in the cache and had to be retrieved directly from the server.

<br />

## Fuzzing:

<br />

We continue enumeration by applying path fuzzing over the domain with `Wfuzz`:

<br />

```bash
❯ wfuzz -c -t 50 --hc=404 -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt http://caption.htb/FUZZ
 /usr/lib/python3/dist-packages/wfuzz/__init__.py:34: UserWarning:Pycurl is not compiled against Openssl. Wfuzz might not work correctly when fuzzing SSL sites. Check Wfuzz's documentation for more information.
********************************************************
* Wfuzz 3.1.0 - The Web Fuzzer                         *
********************************************************

Target: http://caption.htb/FUZZ
Total requests: 220565

=====================================================================
ID           Response   Lines    Word       Chars       Payload                                                                                                               
=====================================================================

...[snip]...
000000017:   403        4 L      8 W        94 Ch       "download"                                                                                                            
000000013:   200        197 L    320 W      4316 Ch     "#"                                                                                                                   
000000004:   200        197 L    320 W      4316 Ch     "#"                                                                                                                   
000000002:   200        197 L    320 W      4316 Ch     "#"                                                                                                                   
000000006:   200        197 L    320 W      4316 Ch     "# Attribution-Share Alike 3.0 License. To view a copy of this"                                                       
000000005:   200        197 L    320 W      4316 Ch     "# This work is licensed under the Creative Commons"                                                                  
000000010:   200        197 L    320 W      4316 Ch     "#"                                                                                                                   
000000009:   200        197 L    320 W      4316 Ch     "# Suite 300, San Francisco, California, 94105, USA."                                                                 
000000008:   200        197 L    320 W      4316 Ch     "# or send a letter to Creative Commons, 171 Second Street,"                                                          
000000852:   403        4 L      8 W        94 Ch       "Download"                                                                                                            
000002276:   403        4 L      8 W        94 Ch       "logs"                                                                                                                
000003795:   403        4 L      8 W        94 Ch       "%20"                                                                                                                 
000001312:   302        5 L      22 W       189 Ch      "firewalls"                                                                                                           
000001230:   302        5 L      22 W       189 Ch      "logout" 
```

<br />

There are some juicy endpoints in the output:

`/home`: 302 redirect -> Typical home page path.

`/firewalls`: 302 redirect ->  Uncommon path that might disclose information about the application's purpose.

`/logout`: 302 redirect. -> Typical logout path.

`/download`: 403 forbidden -> Private endpoint that can be related to file downloads.

`/logs`: 403 forbidden -> Interesting restricted endpoint.

All 302 redirects (such as /firewalls) point to the login page, suggesting that authentication is required.

<br />

# Http Enumeration: -> Port 8080

<br />

The service on port 8080 is a `GitBucket` instance.

<br />

![3](../../../assets/images/Caption/3.png)

<br />

As we can see, there are two public repositories.

Apparently, the `Caption-Portal` one seems to be related to the login page.

Let's start enumerating it:

<br />

![4](../../../assets/images/Caption/4.png)]

<br />

The repository include two folders and famous `README.MD` file.

The `/app` folder contains the `index.html` of the login page and a `/static/css` directory:

<br />

![5](../../../assets/images/Caption/5.png)

<br />
