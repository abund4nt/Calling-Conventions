#include <stdio.h>

int sum_three_numbers(int a1, int a2, int a3, int a4, int a5, int a6)
{
    return a1 + a2 + a3 + a4 + a5 + a6;
}

int main()
{
    printf("%d", sum_three_numbers(3, 6, 9, 12, 15, 18));
}
