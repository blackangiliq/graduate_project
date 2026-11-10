/* Safe counterpart of parser.c. Every finding here is a false positive. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void read_name(void) {
    char name[32];
    if (fgets(name, sizeof(name), stdin) != NULL) {
        printf("Hello %s\n", name);
    }
}

void copy_input(const char *input) {
    char buffer[64];
    snprintf(buffer, sizeof(buffer), "%s", input);
    printf("%s", buffer);
}

void set_default(char *dst, size_t size) {
    strncpy(dst, "fixed", size - 1);
    dst[size - 1] = '\0';
}

void clear_screen(void) {
    system("clear");
}

void read_word(void) {
    char word[16];
    scanf("%15s", word);
}

int roll_dice(void) {
    return rand() % 6 + 1;
}
