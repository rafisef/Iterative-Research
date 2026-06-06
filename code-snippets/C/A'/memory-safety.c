void safe_function(const char *input) {
    char buffer[10];
    strncpy(buffer, input, sizeof(buffer) - 1);
    buffer[sizeof(buffer) - 1] = '\0'; 
    printf("Buffer contains: %s\n", buffer);
}