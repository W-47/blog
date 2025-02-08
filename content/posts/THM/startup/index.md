---
title: "Startup"
date: 2024-01-05
layout: "simple"
categories: [Tryhackme, Easy]
tags: [revshell, privesc, ftp]
---
Hello guys and welcome to another writeup which features an easy tryhackme box accessible [here](https://tryhackme.com/room/startup)

## INTRODUCTION

Okay so first things first we obviously try and scan for open ports using `nmap` 

![1](https://i.ibb.co/S7GVM8H/nmap.png)

We can note down a few things and maybe get an idea of how we would attack the box.

We see that the ports: 21(ftp), 22(ssh), 80(http), are open. Well we can use port 22(ssh) for later since we have no credentials. Then we see that we can connect to the port 21(ftp server) and login as `Anonymous`. We then see two files on the server and we we can use get to load them into our machine. 

![2](https://i.ibb.co/bmHJ693/ftp.png)


## ENUMARATION
Well after downloading the two files into our machines we don't get a lot of information out of it and we then can check out the web page hosted on port 80. Where we do not see a lot of information but we can actually use a directory brute force attack to discover hidden directories. 

![3](https://i.ibb.co/w4Crpkd/gobuster.png)

And we get a hit on `/files`. When we visit the page it looks something like this. 

![4](https://i.ibb.co/XS4yF8k/filecheck.png)

So looking closely we can see that we have a directory `ftp`, which would mean we can upload stuff, including a reverse shell. 

## REVERSE SHELL

So logging back in the ftp server, we then can prepare a reverse shell on our machine, you can find it [here](https://github.com/pentestmonkey/php-reverse-shell)

On our ftp server we can use the command `put revshell.php`. Remember the file should be within the same directory you are on for this to work. 

Then checking our ftp directory on our web page we can see that the file has been uploaded. 

![5](https://i.ibb.co/HFCbXkr/files.png). 

Then all we need to do is start a listener on our machine and click the file, easy peasy 

![6](https://i.ibb.co/QksJc28/initial.png)

## USER

So next what we need to do is try and login as one of the users, since as we are we cannot do alot on the machine. After some time of digging around I saw a `/incidents` directory which contained a pcap file. Which we could analyze using wireshark and maybe find something good.

So on the machine we could setup a python server, and since the python version here is 2 we can use: `python -m SimpleHTTPServer port` to get it running 

Then on our machine we could use the `wget` to download the pcap file

Now that we have the file we can fire up wireshark and start analyzing.
We see a bunch of stuff but can then follow the TCP stream for better analysis, until we come across a very interesting stream. 

![7](https://i.ibb.co/whV5W6M/wireshark.png)

Here we can see a password, my guess is that is lennie's password. Let us try and ssh as Lennie

![8](https://i.ibb.co/MSHzhBY/lennie.png)
And we are in as Lennie 

## PRIVILEGE ESCALATION

So ideally next we would try and escalate our privileges to root. When we look at the files here we can see that we have some scripts, interesting 
![9](https://i.ibb.co/9ZMHLQ5/esca.png)

So basically `planner.sh` creates a list and outputs them to `startup list`. Well you cannot edit this script but, keen eye we see that there is also another script that runs `print.sh`. Maybe we can edit that and try and exploit that

![10](https://i.ibb.co/9gxVj5G/privesc.png)

Yes we can edit that. So next would be to start up a listener on our machine and wait for a minute. Hopefully we get a shell.

![11](https://i.ibb.co/WBXr1dC/root.png)

Ahuh and we are root!


