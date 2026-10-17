#include <limits.h>
#include <stdio.h>
#include <string.h>

/* Intentional defects; select one operation so each finding is attributable. */
int main(int argc, char **argv) {
    if (argc != 2) {
        return 2;
    }
    if (strcmp(argv[1], "overflow") == 0) {
        volatile unsigned int value = UINT_MAX;
        printf("%u\n", value + 1U);
    } else if (strcmp(argv[1], "underflow") == 0) {
        volatile unsigned int value = 0U;
        printf("%u\n", value - 1U);
    } else if (strcmp(argv[1], "divide") == 0) {
        volatile int divisor = 0;
        printf("%d\n", 42 / divisor);
    } else if (strcmp(argv[1], "null") == 0) {
        int *pointer = NULL;
        printf("%d\n", *pointer);
    } else {
        return 2;
    }
    return 0;
}
