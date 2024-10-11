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
