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

At this point we should list the available API functionalities by navigating to the `/api/swagger` default Gitea endpoint:

<br />

![6](../../../assets/images/Lock/6.png)

<br />+

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
