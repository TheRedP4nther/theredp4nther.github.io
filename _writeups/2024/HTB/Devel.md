---
layout: writeup
category: HTB
date: 2024-12-29
comments: false
tags: 
---

<br />

![1](../../../assets/images/Devel/1.png)

<br />

OS -> Windows.

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
❯ nmap -p- 10.10.10.5 --open --min-rate 5000 -sS -T5 -Pn -n -sCV
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-04-07 12:52 CEST
Nmap scan report for 10.10.10.5
Host is up (0.042s latency).
Not shown: 65533 filtered tcp ports (no-response)
Some closed ports may be reported as filtered due to --defeat-rst-ratelimit
PORT   STATE SERVICE VERSION
21/tcp open  ftp     Microsoft ftpd
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
| 03-18-17  02:06AM       <DIR>          aspnet_client
| 03-17-17  05:37PM                  689 iisstart.htm
|_03-17-17  05:37PM               184946 welcome.png
| ftp-syst: 
|_  SYST: Windows_NT
80/tcp open  http    Microsoft IIS httpd 7.5
|_http-title: IIS7
|_http-server-header: Microsoft-IIS/7.5
| http-methods: 
|_  Potentially risky methods: TRACE
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 38.71 seconds
```

<br />

Open Ports:

- `Port 21` -> ftp

- `Port 80` -> http

<br />

## Http Enumeration: -> Port 80

<br />

When we access the website, the `IIS` default page is displayed:

<br />

![2](../../../assets/images/Devel/2.png)

<br />

Since this is the default `IIS` page, we can infer that the system behind the website is running `Windows`.

<br />

## Ftp Enumeration: -> Port 21 

<br />

As we see in the previous nmap scan, `anonymous` FTP login is allowed.

So we proceed to log into the server:

<br />

```bash
❯ ftp 10.10.10.5
Connected to 10.10.10.5.
220 Microsoft FTP Service
Name (10.10.10.5:theredp4nther): anonymous 
331 Anonymous access allowed, send identity (e-mail name) as password.
Password: 
230 User logged in.
Remote system type is Windows_NT.
```

<br />

Once in, we `enumerate` the server to see if we can find something relevant:

<br />

```bash
ftp> ls
229 Entering Extended Passive Mode (|||49158|)
125 Data connection already open; Transfer starting.
03-18-17  02:06AM       <DIR>          aspnet_client
03-17-17  05:37PM                  689 iisstart.htm
03-17-17  05:37PM               184946 welcome.png
226 Transfer complete.
```

<br />

This appears to be the typical `IIS` structure, with its `default` files and directories.

This strongly suggests the `FTP` server is directly `linked` to the web root directory.

So if we try to `upload` a simple txt `file` to the server, we should be able to access it via the website:

<br />

```bash
ftp> put testing.txt
local: testing.txt remote: testing.txt
229 Entering Extended Passive Mode (|||49160|)
125 Data connection already open; Transfer starting.
100% |******************************************************************************************************************************************|    47      685.05 KiB/s    --:-- ETA
226 Transfer complete.
47 bytes sent in 00:00 (1.12 KiB/s)
```

<br />

The file was successfully upload.

This confirms that the FTP server has `write` permissions to the web `root` directory, opening the door for uploading `malicious` payloads such as web shells.

Now we can check if there is in the website too, adding "testing.txt" to the base URL:

<br />

![3](../../../assets/images/Devel/3.png)

<br />

This confirms that the FTP server has `write` permissions to the web `root` directory, opening the door for uploading `malicious` payloads such as web shells.

