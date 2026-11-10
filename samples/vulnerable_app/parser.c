/* Deliberately vulnerable C code. FOR TESTING THE ANALYZER ONLY. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void read_name(void) {
    char name[32];
    gets(name); /* [C01] */
    printf("Hello %s\n", name); /* [C02] */
}

void copy_input(const char *input) {
    char buffer[64];
    strcpy(buffer, input); /* [C03] */
    printf(buffer); /* [C04] */
}

void build_path(const char *dir, const char *file) {
    char path[128];
    sprintf(path, "%s/%s", dir, file); /* [C05] */
    snprintf(path, sizeof(path), "%s/%s", dir, file); /* [C06] */
}

void run(const char *command) {
    system(command); /* [C07] */
}

void read_word(void) {
    char word[16];
    scanf("%s", word); /* [C08] */
    scanf("%15s", word); /* [C09] */
}

void copy_packet(const char *data, size_t len) {
    char packet[256];
    memcpy(packet, data, len); /* [C10] */
}

int *make_table(int count) {
    int *table = malloc(count * sizeof(int)); /* [C11] */
    return table;
}

void set_default(char *dst) {
    strcpy(dst, "fixed"); /* [C12] */
}
