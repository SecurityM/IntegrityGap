#include <stdio.h>
#include <string.h>
#include <stdlib.h>

void do_greet(const char *name) {
    char buf[64];
    strcpy(buf, name);
    printf("Hello, %s!\n", buf);
}

int main(int argc, char **argv) {
    FILE *f = fopen("/dev/null", "r");
    if (f) {
        fclose(f);
    }
    if (argc > 1) {
        do_greet(argv[1]);
    } else {
        do_greet("world");
    }
    return 0;
}
