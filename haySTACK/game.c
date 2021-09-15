#include <stdio.h>
#include <stdlib.h>

int main() {
    int temp = 0;
    srand(time(NULL));
    temp = rand() % 0x100000;
    printf("%d", temp);
    return 0;
}
