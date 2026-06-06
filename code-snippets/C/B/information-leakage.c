#include <stdio.h>
#include <string.h>

int authenticate(char *user, char *password) {
    char correctPassword[] = "mySecretPassword";

    if (strcmp(password, correctPassword) == 0) {
        printf("Authentication successful for user: %s\n", user);
        return 1;  // Authentication successful
    } else {
        printf("Authentication failed for user: %s\n", user);
        return 0;  // Authentication failed
    }
}

int main() {
    char username[] = "john_doe";
    char password[] = "mySecretPassword";

    authenticate(username, password);

    return 0;
}
