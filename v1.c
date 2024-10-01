#include <stdio.h>

int sum_three_numbers(int a1, int a2, int a3)
{
    return a1 + a2 + a3;
}

int main()
{
    printf("%d", sum_three_numbers(3, 6, 9));
}
