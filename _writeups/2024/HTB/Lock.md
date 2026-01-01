---
layout: writeup
category: HTB
date: 2024-12-29
comments: false
tags: 
---

<br />

![1](../../../assets/images/Lock/lock.png)

<br />

OS -> Windows.

Difficulty -> Easy.

<br />

# Introduction:

<br />



<br />

# Enumeration:

<br />

We start by running an `nmap` scan to see which ports are open:

<br />

```bash

```

<br />

Relevant open ports:

- `Port 53`   -> dns

- `Port 88`   -> kerberos

- `Port 135`  -> rpc

- `Port 139`  -> netbios

- `Port 389`  -> ldap

- `Port 445`  -> smb

- `Port 464`  -> kpasswd (kerberos password change)

- `Port 593`  -> rpc over http

- `Port 636`  -> ldaps

- `Port 3389` -> rdp

- `Port 5985` -> winrm

<br />

The domain `lock.vl` and the hostname `DC.lock.vl` appear across multiple services and ports, so I’ll add them to my `/etc/hosts` file:

<br />

```bash

```

<br />

# SMB Enumeration: -> Port 445 

<br />

To start enumerating this service, we'll run a basic [NetExec](https://github.com/Pennyw0rth/NetExec) oneliner to gather some information about the Windows system that we're auditing:

<br />

```bash

```

<br />

The null session did not allow us to enumerate shares:

<br />

```bash

```

<br />

However, by using a random username we obtain a guest session:

<br />

```bash
  
```

