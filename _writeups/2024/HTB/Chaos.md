---
layout: writeup
category: HTB
date: 2024-12-29
comments: false
tags: webmin roundcube imap pop3 python3 decryptor firefox bash restrictedshell
---

<br />

![Machine-Icon](../../../assets/images/Chaos/1.png)

<br />

OS -> Linux.

Difficulty -> Medium.

<br />

# Introduction:
<br />



<br />

# Enumeration:

<br />

We start by running the typical nmap scan to see which ports are open:

<br />

```bash
❯ nmap -p- 10.10.10.120 --open --min-rate 5000 -sS -T5 -Pn -n -sCV
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-01-16 11:43 CET
Nmap scan report for 10.10.10.120
Host is up (0.066s latency).
Not shown: 64947 closed tcp ports (reset), 582 filtered tcp ports (no-response)
Some closed ports may be reported as filtered due to --defeat-rst-ratelimit
PORT      STATE SERVICE  VERSION
80/tcp    open  http     Apache httpd 2.4.34 ((Ubuntu))
|_http-server-header: Apache/2.4.34 (Ubuntu)
|_http-title: Site doesn't have a title (text/html).
110/tcp   open  pop3     Dovecot pop3d
|_pop3-capabilities: STLS CAPA RESP-CODES SASL PIPELINING UIDL TOP AUTH-RESP-CODE
| ssl-cert: Subject: commonName=chaos
| Subject Alternative Name: DNS:chaos
| Not valid before: 2018-10-28T10:01:49
|_Not valid after:  2028-10-25T10:01:49
|_ssl-date: TLS randomness does not represent time
143/tcp   open  imap     Dovecot imapd (Ubuntu)
|_imap-capabilities: Pre-login capabilities LOGIN-REFERRALS post-login LOGINDISABLEDA0001 listed OK LITERAL+ have IMAP4rev1 more SASL-IR IDLE STARTTLS ID ENABLE
| ssl-cert: Subject: commonName=chaos
| Subject Alternative Name: DNS:chaos
| Not valid before: 2018-10-28T10:01:49
|_Not valid after:  2028-10-25T10:01:49
|_ssl-date: TLS randomness does not represent time
993/tcp   open  ssl/imap Dovecot imapd (Ubuntu)
|_imap-capabilities: Pre-login capabilities LOGIN-REFERRALS post-login listed OK LITERAL+ have IMAP4rev1 more SASL-IR AUTH=PLAINA0001 ID IDLE ENABLE
|_ssl-date: TLS randomness does not represent time
| ssl-cert: Subject: commonName=chaos
| Subject Alternative Name: DNS:chaos
| Not valid before: 2018-10-28T10:01:49
|_Not valid after:  2028-10-25T10:01:49
995/tcp   open  ssl/pop3 Dovecot pop3d
| ssl-cert: Subject: commonName=chaos
| Subject Alternative Name: DNS:chaos
| Not valid before: 2018-10-28T10:01:49
|_Not valid after:  2028-10-25T10:01:49
|_pop3-capabilities: USER CAPA RESP-CODES SASL(PLAIN) PIPELINING UIDL TOP AUTH-RESP-CODE
|_ssl-date: TLS randomness does not represent time
10000/tcp open  http     MiniServ 1.890 (Webmin httpd)
|_http-title: Site doesn't have a title (text/html; Charset=iso-8859-1).
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 61.54 seconds
```

<br />

Open Ports:

- `Port 80` -> http 

- `Ports 110` -> pop3 

- `Port 143` -> imap

- `Port 993` -> imap (SSL)

- `Port 995` -> pop3 (SSL)

- `Port 10000` -> webmin 

<br />

# Http Enumeration: -> Port 80:

<br />

At listing the website we see the following message:

<br />

![2](../../../assets/images/Chaos/2.png)

<br />

Proceed to add chaos.htb to our /etc/hosts pointing to the 10.10.10.120 and list again:

<br />

![3](../../../assets/images/Chaos/3.png)

<br />

The page has several sections but nothing relevant.

<br />

# Webmin Enumeration: -> Port 10000

<br />

As we know, there is a webmin running on the port 10000, so we list it and try defaul credentials like admin:admin, but didn't work:

<br />

![4](../../../assets/images/Chaos/4.png)

<br />

## Fuzzing:

<br /> 

Do some fuzzing and on the first website we list we find some interesting things:

<br />

```bash
❯ wfuzz -c -t 50 --hc=404 -w /usr/share/SecLists/Discovery/Web-Content/directory-list-2.3-medium.txt http://10.10.10.120/FUZZ
 /usr/lib/python3/dist-packages/wfuzz/__init__.py:34: UserWarning:Pycurl is not compiled against Openssl. Wfuzz might not work correctly when fuzzing SSL sites. Check Wfuzz's documentation for more information.
********************************************************
* Wfuzz 3.1.0 - The Web Fuzzer                         *
********************************************************

Target: http://10.10.10.120/FUZZ
Total requests: 220560

=====================================================================
ID           Response   Lines    Word       Chars       Payload                                                                                                                
=====================================================================

000000001:   200        1 L      5 W        73 Ch       "# directory-list-2.3-medium.txt"                                                                                      
000000007:   200        1 L      5 W        73 Ch       "# license, visit http://creativecommons.org/licenses/by-sa/3.0/"                                                      
000000003:   200        1 L      5 W        73 Ch       "# Copyright 2007 James Fisher"                                                                                        
000000009:   200        1 L      5 W        73 Ch       "# Suite 300, San Francisco, California, 94105, USA."                                                                  
000000005:   200        1 L      5 W        73 Ch       "# This work is licensed under the Creative Commons"                                                                   
000000002:   200        1 L      5 W        73 Ch       "#"                                                                                                                    
000000008:   200        1 L      5 W        73 Ch       "# or send a letter to Creative Commons, 171 Second Street,"                                                           
000000010:   200        1 L      5 W        73 Ch       "#"                                                                                                                    
000000011:   200        1 L      5 W        73 Ch       "# Priority ordered case-sensitive list, where entries were found"                                                     
000000012:   200        1 L      5 W        73 Ch       "# on at least 2 different hosts"                                                                                      
000000014:   200        1 L      5 W        73 Ch       "http://10.10.10.120/"                                                                                                 
000000013:   200        1 L      5 W        73 Ch       "#"                                                                                                                    
000000006:   200        1 L      5 W        73 Ch       "# Attribution-Share Alike 3.0 License. To view a copy of this"                                                        
000000004:   200        1 L      5 W        73 Ch       "#"                                                                                                                    
000000793:   301        9 L      28 W       309 Ch      "wp"                                                                                                                   
000001073:   301        9 L      28 W       317 Ch      "javascript"
```

<br />

## /wp/wordpress:

<br />

When listing this route we find a folder that takes us to a wordpress with a post password protected:

<br />

![5](../../../assets/images/Chaos/5.png)

<br />

Click on the post and we see the author, human:

<br />

![6](../../../assets/images/Chaos/6.png)

<br />

Sometimes users use their own password name, so we try entering human and voila!!

<br />

![7](../../../assets/images/Chaos/7.png)

<br />

The post contains a user and some credentials for "webmail".

<br />

# Webmail:

<br />

We start fuzzing to see if we can find any subdomains where "webmail" is hosted and enumerate the following:

<br />

```bash
❯ ffuf -u http://chaos.htb -H "Host: FUZZ.chaos.htb" -w /usr/share/SecLists/Discovery/DNS/subdomains-top1million-5000.txt -c -t 20 -fs 73

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.1.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://chaos.htb
 :: Wordlist         : FUZZ: /usr/share/SecLists/Discovery/DNS/subdomains-top1million-5000.txt
 :: Header           : Host: FUZZ.chaos.htb
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 20
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
 :: Filter           : Response size: 73
________________________________________________

webmail                 [Status: 200, Size: 5607, Words: 649, Lines: 121, Duration: 67ms]
```

<br />

Perfect, we have a new subdomain!! So enter it in the /etc/hosts and proceed to list the website:

<br />

![8](../../../assets/images/Chaos/8.png)

<br />

As we can see, is a roundcube login panel.

Log in with the Wordpress post credentials successfully and once in, the mailbox appears to be empty:

<br />

![9](../../../assets/images/Chaos/9.png)

<br />

But checking the drafts we find a message with 2 attachments:

<br />

![10](../../../assets/images/Chaos/10.png)

<br />

Bring the files to our machine.

<br />

# File Decrypt:

<br />

We have two files, `en.py` & `enim_msg.txt`.

<br />

## en.py:

<br />

This file is a Python Script to encrypt files:

<br />

```python
def encrypt(key, filename):
    chunksize = 64*1024
    outputFile = "en" + filename
    filesize = str(os.path.getsize(filename)).zfill(16)
    IV =Random.new().read(16)

    encryptor = AES.new(key, AES.MODE_CBC, IV)

    with open(filename, 'rb') as infile:
        with open(outputFile, 'wb') as outfile:
            outfile.write(filesize.encode('utf-8'))
            outfile.write(IV)

            while True:
                chunk = infile.read(chunksize)

                if len(chunk) == 0:
                    break
                elif len(chunk) % 16 != 0:
                    chunk += b' ' * (16 - (len(chunk) % 16))

                outfile.write(encryptor.encrypt(chunk))

def getKey(password):
            hasher = SHA256.new(password.encode('utf-8'))
            return hasher.digest()
```

<br />

## enim_msg.txt:

<br />

And this other file, is a file that seems to be encrypted with the en.py script:

<br />

```bash
❯ /usr/bin/cat enim_msg.txt
0000000000000234��z�سpK8�ZC����^9�kW����&w�9ܾ����E��'q�[���9�Z��⑿3����.�C�������;��3������6���R`n⑿
                                                                                                 퍦3�>�}3A����d��FY
                                                                                                                   ��YDo!�R#~�[��8����a4❄��á>)K�M^�z�I���,��ݨB���qݕYqˏR���q�M�ߟ.w�ʢF�@m�9
 �JD����(�^�7�5~�"���}��0�?�U�qX(��r�]�w���zGO
```

<br />


