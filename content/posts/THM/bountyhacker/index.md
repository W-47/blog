---
title: "Bounty Hacker"
date: 2023-12-31
layout: "simple"
categories: [TryHackme]
tags: [Boot2root]
image: https://i.ibb.co/cgYN2Kr/th-3134630742.jpg
---

Hello guys and welcome to another writeup featuring linux priviledge escalation. This is an easy box on tryhackme and you can access it [here](https://tryhackme.com/room/cowboyhacker)

## OVERVIEW

Okay quick overview, so we will be trying to bruteforce ssh and get some credentials for the box. I had fun on it and I hope you will to so lets get to it.

## NMAP SCAN
First things first a quick nmap scan to check on the open ports. 

![1](https://i.ibb.co/4TvVRM9/nmap.png)

From the results we can see some ports open. For example; port 21, 22 and port 80.

## FTP SERVICE.
Let us try and use the FTP service to  get into the machine since we can login as Anonymous. 

![2](https://i.ibb.co/1rw7023/ftp.png) 

Aah yes we can see some files on the system. We will use get to well get the files to our own machine. 

## BRUTEFORCING.
So next we will view the page that is hosted on port 80.

![3](https://i.ibb.co/hDNQpc3/web.png)

We don't get a lot here but maybe we can use the names here as a users.txt and maybe bruteforce a username.
We will also cat out the two file swe got. we can see that the locks.txt is actually a password list. The task.txt also gives us another name that can be the user.

So using hydra we can actually run **hydra ssh://ip -L users.txt -P locks.txt**

![4](https://i.ibb.co/PGJPzTJ/creds.png)

Boom! We have a hit!

## PRIVILEDGE ESCALATION.
So next we should try and get root priviledges. so first we shall do **sudo -l** and we see that we can run (/var/tar) as root.

So we shall hop over to [GTFO bins](https://gtfobins.github.io/gtfobins/tar/#Sudo) and copy that command out to our machine.

![5](https://i.ibb.co/G9t21vZ/privesc.png)


And there we have it. We are root.
