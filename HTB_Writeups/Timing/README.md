---
title: Timing
date: 2021-03-24
tags:
  - HTB Writeup
---
![Timing](./timing.png)

### Scanning and Enumeration of Open Ports (Using Nmap)

##### Nmap

Nmap (or network mapper) is a open source tool for Network exploitation and security analysis. Using Nmap, you can scan
one or several hosts for different services running on different ports.
For installing and more info on Nmap , use

```noLineNumbers
sudo apt install nmap
man nmap
```

##### Service Scanning

```noLineNumbers
nmap -Pn -sV -sC 10.10.11.135
```

-sV: Probe open ports to determine service/version info

-sC: equivalent to --script=default

-Pn: Treat all hosts as online -- skip host discovery

```
➜  Timing git:(master) ✗ nmap -Pn -sV -sC 10.10.11.135  

Starting Nmap 7.60 ( https://nmap.org ) at 2022-03-17 11:56 IST
Nmap scan report for 10.10.11.135
Host is up (0.20s latency).
Not shown: 998 closed ports
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.5 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 d2:5c:40:d7:c9:fe:ff:a8:83:c3:6e:cd:60:11:d2:eb (RSA)
|   256 18:c9:f7:b9:27:36:a1:16:59:23:35:84:34:31:b3:ad (ECDSA)
|_  256 a2:2d:ee:db:4e:bf:f9:3f:8b:d4:cf:b4:12:d8:20:f2 (EdDSA)
80/tcp open  http    Apache httpd 2.4.29 ((Ubuntu))
| http-cookie-flags: 
|   /: 
|     PHPSESSID: 
|_      httponly flag not set
|_http-server-header: Apache/2.4.29 (Ubuntu)
| http-title: Simple WebApp
|_Requested resource was ./login.php
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 32.32 seconds
```

```
sudo nano /etc/hosts

Add 10.10.11.135   timing.htb
```

Did a directory scan on http://timing.htb and got the following results

```➜  Timing git:(master) ✗ ffuf -w /opt/SecLists/Discovery/Web-Content/raft-small-files.txt -u http://timing.htb/FUZZ  -mc all -fc 404,400


        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v1.3.1-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://timing.htb/FUZZ
 :: Wordlist         : FUZZ: /opt/SecLists/Discovery/Web-Content/raft-small-files.txt
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: all
 :: Filter           : Response status: 404,400
________________________________________________

footer.php              [Status: 200, Size: 3937, Words: 1307, Lines: 116]
header.php              [Status: 302, Size: 0, Words: 1, Lines: 1]
image.php               [Status: 200, Size: 0, Words: 1, Lines: 1]
logout.php              [Status: 302, Size: 0, Words: 1, Lines: 1]
.htaccess               [Status: 403, Size: 275, Words: 20, Lines: 10]
login.php               [Status: 200, Size: 5609, Words: 1755, Lines: 178]
.                       [Status: 302, Size: 0, Words: 1, Lines: 1]
upload.php              [Status: 302, Size: 0, Words: 1, Lines: 1]
.html                   [Status: 403, Size: 275, Words: 20, Lines: 10]
profile.php             [Status: 302, Size: 0, Words: 1, Lines: 1]
index.php               [Status: 302, Size: 0, Words: 1, Lines: 1]
.php                    [Status: 403, Size: 275, Words: 20, Lines: 10]
.htpasswd               [Status: 403, Size: 275, Words: 20, Lines: 10]
.htm                    [Status: 403, Size: 275, Words: 20, Lines: 10]
.htpasswds              [Status: 403, Size: 275, Words: 20, Lines: 10]
.htgroup                [Status: 403, Size: 275, Words: 20, Lines: 10]
wp-forum.phps           [Status: 403, Size: 275, Words: 20, Lines: 10]
.htaccess.bak           [Status: 403, Size: 275, Words: 20, Lines: 10]
.htuser                 [Status: 403, Size: 275, Words: 20, Lines: 10]
```
