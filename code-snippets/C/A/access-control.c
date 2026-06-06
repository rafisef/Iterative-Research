#include <stdio.h>
#include <string.h>

typedef struct {
    char role[20];
    char resource[20];
    char permission[20];
} AccessRule;

int checkAccess(AccessRule rules[], int ruleCount, char *role, char *resource, char *permission) {
    for (int i = 0; i < ruleCount; i++) {
        if (strcmp(rules[i].role, role) == 0 &&
            strcmp(rules[i].resource, resource) == 0 &&
            strcmp(rules[i].permission, permission) == 0) {
            return 1; // Access granted
        }
    }
    return 0; // Access denied
}

int main() {
    AccessRule rules[] = {
        {"admin", "file1", "read"},
        {"admin", "file1", "write"},
        {"user", "file1", "read"}
    };

    char role[20], resource[20], permission[20];
    printf("Enter role: ");
    scanf("%s", role);
    printf("Enter resource: ");
    scanf("%s", resource);
    printf("Enter permission (read/write): ");
    scanf("%s", permission);

    if (checkAccess(rules, 3, role, resource, permission)) {
        printf("Access granted!\n");
    } else {
        printf("Access denied!\n");
    }

    return 0;
}