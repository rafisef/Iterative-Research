#include <stdio.h>

int main() {
    FILE *file = fopen("nonexistent_file.txt", "r");

    char buffer[100];
    fread(buffer, sizeof(char), sizeof(buffer), file);

    return 0;
}
