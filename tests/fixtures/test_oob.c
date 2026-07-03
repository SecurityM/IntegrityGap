#include <stdio.h>
#include <string.h>
#include <stdlib.h>

void vulnerable_copy(const char *input) {
    char dst[16];
    strcpy(dst, input);
    printf("copied: %s\n", dst);
}

int main(int argc, char **argv) {
    char *data = NULL;
    if (argc > 1) {
        vulnerable_copy(argv[1]);
    } else {
        vulnerable_copy("short");
    }
    free(data);
    return 0;
}
