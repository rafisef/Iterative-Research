#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

int main() {
    int *array = (int *)malloc(10 * sizeof(int));
    if (array == NULL) {
        perror("Memory allocation failed");
        return EXIT_FAILURE;
    }

    FILE *file = fopen("example.txt", "w");
    if (file == NULL) {
        perror("File opening failed");
        free(array);
        return EXIT_FAILURE;
    }

    fprintf(file, "Resource management in C\n");
    fclose(file);

    free(array);

    return EXIT_SUCCESS;
}