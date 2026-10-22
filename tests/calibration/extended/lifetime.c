#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(int argc, char **argv) {
    if (argc != 2) {
        return 2;
    }

    int *value = malloc(sizeof(*value));
    if (value == NULL) {
        return 1;
    }
    *value = 17;

    if (strcmp(argv[1], "use-after-free") == 0) {
        free(value);
        printf("%d\n", *value);
    } else if (strcmp(argv[1], "double-free") == 0) {
        free(value);
        free(value);
    } else if (strcmp(argv[1], "null-dereference") == 0) {
        free(value);
        value = NULL;
        printf("%d\n", *value);
    } else {
        free(value);
        return 2;
    }
    return 0;
}
