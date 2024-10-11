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

En el desensamblado anterior, la instrucción `mov` se utiliza para cargar los valores que se pasarán como argumentos a la función `vuln`. Los registros utilizados son `rdi`, `rsi` y `rdx`, que son los registros de 64 bits designados para recibir los parámetros en la convención de llamada x86-64:

```
- rdi: First argument
- rsi: Second argument
- rdx: Third argument
- rcx: Fourth argument
- r8: Fifth argument
- r9: Sixth argument
```

Es crucial notar que los valores movidos a estos registros están representados en 32 bits, lo que se indica mediante el uso de los prefijos `e` (`edx`, `esi`, `edi`). Esto refleja cómo se manejan los datos de diferentes tamaños en el contexto de la memoria del programa.
