#include <stdio.h>
#include <string.h>
int main() {
    char pass[] = "Secret123";
    char input[20];
    scanf("%s", input);
    if(strcmp(input, pass) == 0) puts("Correct!");
    else puts("Wrong");
    return 0;
}
