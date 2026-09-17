#include <stdio.h>
#include <string.h>

int main(void) {
    char word[32];
    printf("Key: ");
    if (scanf("%31s", word) != 1) {
        puts("Wrong");
        return 1;
    }
    size_t length = strlen(word);
    for (size_t i = 0; i < length; i++) {
        word[i] = (char)(word[i] + (i % 3) - 1);
    }
    if (strcmp(word, "s3`hs`euo^ol") == 0) {
        puts("Unlocked");
        return 0;
    }
    puts("Wrong");
    return 1;
}
