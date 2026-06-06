#include <stdio.h>
#include <string.h>

void unsafe_function(const char *input) {
    char buffer[10];
    strcpy(buffer, input);
    printf("Buffer contains: %s\n", buffer);
}

int main() {
    char large_input[] = "This is a long string that exceeds buffer size!";
    unsafe_function(large_input); // Potential buffer overflow
    return 0;
}