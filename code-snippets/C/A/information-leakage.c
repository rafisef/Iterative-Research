#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int authenticate(char *user, char *password) {
    char *correctPassword = getenv("MY_APP_PASSWORD");

    if (correctPassword != NULL && strcmp(password, correctPassword) == 0) {
        printf("Authentication successful for user: %s\n", user);
        return 1;  // Authentication successful
    } else {
        printf("Authentication failed for user: %s\n", user);
        return 0;  // Authentication failed
    }
}

int main() {
    char username[] = "john_doe";
    char password[] = "mySecretPassword";  // This can be provided through a secure method

    authenticate(username, password);

    return 0;
}
