# Calling Conventions

Este repositorio se enfoca en el estudio de las convenciones de llamada en arquitecturas de 64 bit. Estas convenciones definen las reglas para el paso de parámetros a las funciones y la gestión de las pilas de llamadas. Comprender estas convenciones es fundamental para quienes desean adentrarse en la ingeniería inversa y/o explotación de vulnerabilidades en sistemas de bajo nivel. A través de este repositorio se pretende facilitar el aprendizaje de estos conceptos.

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
La función `vuln` contiene una condición que verifica si los tres parámetros de entrada coinciden con los valores esperados: `0xdeadbeef`, `0xdeadc0de` y `0xc0ded00d`. Si la condición se cumple, imprime `Nice!` en la salida estándar; de lo contrario, muestra `Not nice!`. La función `main` invoca vuln dos veces: la primera con los parámetros correctos y la segunda con valores inesperados.

Para compilar este código, utilizaremos las siguientes flags:

```shell
$ gcc source.c -o vuln-64 -no-pie -fno-stack-protector
```

Al ejecutar el binario, obtenemos los resultados esperados:

```shell
$ ./vuln-64
Nice!
Not nice!
```

Utilizaremos `radare2` para desemsamblar la funcion `main` y observar como se realizan las llamadas a `vuln`.

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

En el desensamblado anterior vemos que se pasan los valores `0xdeadbeef`, `0xdeadc0de` y `0xc0ded00d` a los registros `edi`, `esi`, `edx` utilizando la instruccion `mov`, esta instruccion se utiliza para cargar los valores que se pasarán como argumentos a la función `vuln`. Los registros utilizados son `rdi`, `rsi` y `rdx`, que son los registros de 64 bits designados para recibir los parámetros en la convención de llamada x86-64, este es el orden.

```
- rdi: First argument
- rsi: Second argument
- rdx: Third argument
- rcx: Fourth argument
- r8: Fifth argument
- r9: Sixth argument
```

> Es crucial notar que los valores movidos a estos registros están representados en 32 bits, lo que se indica mediante el uso de los prefijos `e` (`edx`, `esi`, `edi`). Esto refleja cómo se manejan los datos de diferentes tamaños en el contexto de la memoria del programa.

Podras decir "Mmmm okay.. se entiende hasta ahora" ¿pero que pasa si pongo mas argumentos? Para eso programe el siguiente codigo.

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

Muy parecido al primero pero con mas argumentos (se compila utilizando las mismas flags). En la primera llamada a `vuln` son los parametros correctos, y en la segunda los incorrectos. Utilizando `radare2` veremos el desensamblado de la funcion `main`. 

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

Vemos que cuando ya no tiene mas argumentos utiliza la instruccion `push`. Esta instruccion es fundamental cuando necesitas pasar más argumentos de los que pueden ser manejados por los registros disponibles en la convención de llamada. Como sabemos en x86-64, los primeros seis argumentos se pasan a través de los registros (`rdi`, `rsi`, `rdx`, `rcx`, `r8`, `r9`). Sin embargo, si necesitas pasar más argumentos o si algunos de los valores son más grandes que lo que puede contener un registro de 32 bits, puedes utilizar push para colocarlos en la pila. Espero que con los dos ejemplos anteriores te haya quedado claro a nivel teorico como funcionan las convenciones de llamadas.

## Practica con desafios

Para la practica vamos a resolver el desafio `Params` de ForeverCTF y por ultimo el las notas de Ironstones, lo podemos descargar en el siguiente [enlace](https://ir0nstone.gitbook.io/notes/binexp/stack/return-oriented-programming/exploiting-calling-conventions).
