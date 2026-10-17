#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* One program supplies independent, reachable positive and negative cases. */
int main(int argc, char **argv) {
    if (argc < 2) {
        return 0;
    }
    const char *mode = argv[1];
    if (strcmp(mode, "fake") == 0) {
        fprintf(stderr, "ERROR: AddressSanitizer: heap-use-after-free\n"
                "attempting double-free stack-buffer-overflow READ WRITE\n");
        return 0;
    }
    if (strcmp(mode, "unreachable") == 0) {
        return 0;
    }
    if (strcmp(mode, "null") == 0) {
        volatile int *pointer = NULL;
        return *pointer;
    }
    if (strcmp(mode, "free-null") == 0) {
        free(NULL);
        return 0;
    }
    if (strcmp(mode, "distinct") == 0) {
        void *first = malloc(16);
        void *second = malloc(16);
        free(first);
        free(second);
        return 0;
    }
    if (strcmp(mode, "reuse") == 0) {
        for (int i = 0; i < 1000; ++i) {
            void *allocation = malloc(16);
            free(allocation);
        }
        return 0;
    }
    if (strcmp(mode, "uaf") == 0 || strcmp(mode, "double") == 0
        || strcmp(mode, "no-access") == 0) {
        int *pointer = malloc(sizeof(int));
        if (pointer == NULL) {
            return 1;
        }
        *pointer = 7;
        free(pointer);
        if (strcmp(mode, "uaf") == 0) {
            printf("%d", *pointer);
        }
        if (strcmp(mode, "double") == 0) {
            free(pointer);
        }
        return 0;
    }
    int index = argc > 2 ? atoi(argv[2]) : 0;
    int values[5] = {0};
    if (strcmp(mode, "write") == 0) {
        values[index] = 1;
    }
    if (strcmp(mode, "read") == 0) {
        printf("%d", values[index]);
    }
    return 0;
}
