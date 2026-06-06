#include <stdio.h>
#include <string.h>

int main() {
  char name[100];

  do {
    printf("Enter your name: ");
    fgets(name, sizeof(name), stdin);
    name[strcspn(name, "\n")] = 0;
  } while (strlen(name) == 0);

  printf("Hello, %s\n", name); // Greet the user
  return 0;
}