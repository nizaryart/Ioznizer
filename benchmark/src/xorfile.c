/*
 * Benign control: an XOR file obfuscator, the kind of thing in every
 * "intro to C" exercise set.
 *
 * Reads a file, XORs every byte with a key, writes it back out. Structurally
 * identical to the encryption loop in ransomware, which is what makes it a
 * useful control: the distinguishing feature of ransomware is not the XOR
 * loop, it is enumerating a filesystem, deleting shadow copies and dropping a
 * ransom note. None of that is here.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define KEY "benchmark-control-key"

int main(int argc, char **argv) {
    FILE *in, *out;
    unsigned char buffer[4096];
    size_t n, i, k = 0;
    const size_t key_len = strlen(KEY);

    if (argc != 3) {
        fprintf(stderr, "usage: %s <input> <output>\n", argv[0]);
        return 1;
    }

    in = fopen(argv[1], "rb");
    if (!in) {
        perror(argv[1]);
        return 1;
    }

    out = fopen(argv[2], "wb");
    if (!out) {
        perror(argv[2]);
        fclose(in);
        return 1;
    }

    while ((n = fread(buffer, 1, sizeof(buffer), in)) > 0) {
        for (i = 0; i < n; i++) {
            buffer[i] ^= (unsigned char)KEY[k % key_len];
            k++;
        }
        if (fwrite(buffer, 1, n, out) != n) {
            perror("write");
            fclose(in);
            fclose(out);
            return 1;
        }
    }

    printf("Processed %s -> %s\n", argv[1], argv[2]);
    fclose(in);
    fclose(out);
    return 0;
}
