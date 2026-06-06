#include <stdio.h>

int main() {
    int numbers[5] = {1, 2, 3, 4, 5};

    int index = 10;
    if (index >= 0 && index < sizeof(numbers) / sizeof(numbers[0])) {
        int value = numbers[index];
        printf("Value: %d\n", value);
    } else {
        printf("Index out of bounds\n");
    }

    return 0;
}
