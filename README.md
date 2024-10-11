# Calling Conventions

Este repositorio se enfoca en el estudio de las convenciones de llamada en arquitecturas de 64 bits, un aspecto esencial en la programación y la explotación binaria. Estas convenciones definen las reglas para el paso de parámetros a las funciones y la gestión de las pilas de llamadas. Comprender estas normas es fundamental para quienes desean adentrarse en la ingeniería inversa y la explotación de vulnerabilidades en sistemas de bajo nivel. A través de este repositorio, se pretende facilitar el aprendizaje de estos conceptos.

Comenzaremos compilando y analizando el siguiente codigo.

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

Vemos que define una funcion `vuln` con un condicional if, que chequea si los primeros tres parametros ingresados son iguales a `0xdeadbeef`, `0xdeadc0de`, `0xc0ded00d`. Si la condicion anterior se cumple muestra `Nice!` por pantalla, de lo contrario muestra `Not nice!`. Luego define la funcion `main` que llama a la funcion `vuln` dos veces seguidas, una con los parametros esperados y otra con parametros no esperamos. Para probar este codigo lo compilaremos utilizando las siguientes flags.

```shell
$ gcc source.c -o vuln-64 -no-pie -fno-stack-protector
```

Al ejecutar el binario vemos que por pantalla muestra `Nice` y `Not nice!`. Era el resultado que nos esperabamos.

```shell
$ ./vuln-64
Nice!
Not nice!
```

Utilizando `radare2` vamos a imprimir el desensamblado de la funcion `main`, tenemos lo siguiente.

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
