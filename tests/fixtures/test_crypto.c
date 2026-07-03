#include <stdio.h>
#include <string.h>
#include <stdlib.h>

void xor_encrypt(unsigned char *data, int len, const unsigned char *key) {
    for (int i = 0; i < len; i++) {
        data[i] ^= key[i % 16];
    }
}

int main(int argc, char **argv) {
    unsigned char buffer[256] = "sensitive data";
    const unsigned char key[16] = {0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,
                                   0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f,0x10};
    xor_encrypt(buffer, 16, key);
    printf("encrypted: %s\n", buffer);
    return 0;
}
