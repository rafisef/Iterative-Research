#include <stdio.h>

int main() {
    FILE *file = fopen("nonexistent_file.txt", "r");

    if (file == NULL) {
        perror("Error opening file");
        return 1;  // Exit the program with an error code
    }

    // Read from the file
    char buffer[100];
    size_t bytesRead = fread(buffer, sizeof(char), sizeof(buffer), file);

    // Check for read errors
    if (ferror(file)) {
        perror("Error reading from file");
        fclose(file);
        return 1;
    }

    fclose(file);

    return 0;
}
