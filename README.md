# Calling-Conventions

The binary is compiled without any flag using `gcc`, to display the dump we will use `objdump`.

```shell
$ obdjump -M intel -D a
```

When we dump the binary we can see the following in the main function.

```asm
0000000000001183 <main>:
    1183:       f3 0f 1e fa             endbr64
    1187:       55                      push   rbp
    1188:       48 89 e5                mov    rbp,rsp
    118b:       41 b9 12 00 00 00       mov    r9d,0x12
    1191:       41 b8 0f 00 00 00       mov    r8d,0xf
    1197:       b9 0c 00 00 00          mov    ecx,0xc
    119c:       ba 09 00 00 00          mov    edx,0x9
    11a1:       be 06 00 00 00          mov    esi,0x6
    11a6:       bf 03 00 00 00          mov    edi,0x3
    11ab:       e8 99 ff ff ff          call   1149 <sum_three_numbers>
    11b0:       89 c6                   mov    esi,eax
    11b2:       48 8d 05 4b 0e 00 00    lea    rax,[rip+0xe4b]        # 2004 <_IO_stdin_used+0x4>
    11b9:       48 89 c7                mov    rdi,rax
    11bc:       b8 00 00 00 00          mov    eax,0x0
    11c1:       e8 8a fe ff ff          call   1050 <printf@plt>
    11c6:       b8 00 00 00 00          mov    eax,0x0
    11cb:       5d                      pop    rbp
    11cc:       c3                      ret
```

Strange? it is not like that... because in the code first pass the number 3, and in the code you see the number 18. This is due to the call conventions, you must have clear the following order of records.

- `rdi`: First argument
- `rsi`: Second argument
- `rdx`: Third argument
- `rcx`: Fourth argument
- `r8`: Fifth argument
- `r9`: Sixth argument

The reason it appears to “pass 9 first” is that the registers are loaded in the order specified in the assembly code, but the numbers correspond to the arguments you have provided.
