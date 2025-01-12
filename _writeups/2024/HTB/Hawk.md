---
layout: writeup
category: HTB
date: 2024-12-29
comments: false
tags: 
---

<br />

![Machine-Icon](../../../assets/images/Hawk/1.png)

<br />

OS -> Linux.

Difficulty -> Medium.

<br />

# Introduction:
<br />

Hello hackers! Today we’ll tackle the Hawk Machine, a medium-difficulty Linux challenge. We’ll start by retrieving an OpenSSL-encoded file from an FTP server with anonymous login enabled. After brute-forcing it using a custom Bash utility we create ourselves, we’ll obtain credentials to access a Drupal site where we can execute PHP code and gain system access. Once inside, we’ll retrieve credentials from a configuration file to pivot to another user. Finally, we’ll exploit a vulnerable internal service to escalate privileges and become root.

<br />

# Enumeration:

<br />

We start by running the typical nmap scan to see which ports are open:

<br />


