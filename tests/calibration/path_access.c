#include <stdio.h>

/* No path validation: the manifest supplies a synthetic traversal and target. */
int main(int argc, char **argv) {
    if (argc != 2) {
        return 2;
    }
    FILE *stream = fopen(argv[1], "r");
    if (stream == NULL) {
        return 1;
    }
    int character = fgetc(stream);
    fclose(stream);
    return character == EOF;
}
