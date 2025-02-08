---
title: "Alice in Wonderland"
date: 2023-12-31
layout: "simple"
categories: [TryHackMe]
tags: [Boot2root, python library hijacking, privesc]
image: https://i.ibb.co/cgYN2Kr/th-3134630742.jpg
---
Hello and welcome to the tryhack me writeup [Alice on wonderland](https://tryhackme.com/room/wonderland).
# OVERVIEW
So we will be trying to get some credentials and log in as a particular user and then try to escalate our priviledges to root and get the flag. With that said lets get to it

# NMAP SCAN

After a quick nmap scan we can see that the port 22 and port 80 are open.
![1](https://i.ibb.co/QpsyvgL/nmap.png)

# WEB ENUMARATION

From the previous nmap scan we can see that a web server is hosted on port 80 and we can use the IP to see it 

This is what we see 

![2](https://i.ibb.co/7vp566b/web1.png)

Here we can use gobuster in an effort to find any directories that may be hidden.

![3](https://i.ibb.co/SN7d9Dr/go1.png)

From the results of the first gobuster we see a hidden directory ```/r```. When we go to the directory this is what we see

![4](https://i.ibb.co/MRH7n2J/web2.png)

Frome the title we see that we are told to keep going. So we use gobuster on the directory again discovering more directories which make up the word ```rabbit``` (Follow the white rabbit)
![5](https://i.ibb.co/sPrf17g/web7.png)

We can view the page source on this.

![6](https://i.ibb.co/QdyXz9f/creds.png)

Aah yes we get a username and maybe a password and we shall try to ssh to this user using the creds.
![7](https://i.ibb.co/3YVrnbK/ssh.png)


Yes we are able to login as alice.
# USER.TXT
Let us try to get the user.txt flag.

![8](https://i.ibb.co/Lz8ptfC/user.png)

# PRIVILEDGE ESCALATION 
We notice that the user Alice cannot do much on this machine so we can try and escalate our priviledges in order to get the root.txt flag. 
We then see a python file on it and when we open it we notice that the script is trying to import a file called random 

![9](https://i.ibb.co/bbW46jt/walrusnano.png)

Here we can try and use python library hijacking. First we need to get the path followed when the script is importing random 

![10](https://i.ibb.co/KGx8LX4/syspath.png)

We then can create our own python script that will enable us to switch users to rabbit.

![11](https://i.ibb.co/gFrLxzW/os.png)

Then we can run the command ```sudo -u rabbit /usr/bin/python3.6 /home/alice/walrus_and_the_carpenter.py```. And we succesfully change to rabbit user 
![12](https://i.ibb.co/VVGrXMb/changetorabbit.png)

Here we can see a binary called ```teaParty``` and when we try and run it we see that we can actually hijack the date binary to give us acces as another user.

![13](https://i.ibb.co/TL7fTj1/teaparty.png)

First we will create another file like so:

![14](https://i.ibb.co/QpdBXTy/date.png)

Then we will change the mode to execute and export the binary to PATH then we will run ```./teaParty``` again.
And we ara able to change to hatter 
![15](https://i.ibb.co/BV9wX5p/hatter.png)

We can then cd into ```/home/hatter``` directory and find a password 
![16](https://i.ibb.co/2cj3Tty/password.png)

We can use this password to ssh into the machine as hatter. And we got a succesful login 
![18](https://i.ibb.co/ZXKsQvs/sshhatter.png)

## GETTING ROOT.TXT

Here we can use ```getcap -r /``` in order to get the enabled capabilities, and we find out that the ```setuid+ep``` has been enabled on pearl.

![19](https://i.ibb.co/F8kxG8f/getcap.png)

From here we can use some help from [GTFO bins](https://gtfobins.github.io/gtfobins/perl/#capabilities) and we find a way to abuse pearl and get escalate to root ```/usr/bin/perl -e 'use POSIX qw(setuid); POSIX::setuid(0); exec "/bin/sh";'```.
Then it is possible to cd into alice and get the root.txt

![20](https://i.ibb.co/k5X4QpL/roottxt.png)











