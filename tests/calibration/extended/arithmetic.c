#include <limits.h>
#include <stdio.h>
#include <string.h>

int main(int argc, char **argv) {
    if (argc != 2) {
        return 2;
    }

    volatile int left;
    volatile int right;
    volatile int result;
    if (strcmp(argv[1], "overflow") == 0) {
        left = INT_MAX;
        right = 1;
        result = left + right;
    } else if (strcmp(argv[1], "underflow") == 0) {
        left = INT_MIN;
        right = 1;
        result = left - right;
    } else if (strcmp(argv[1], "divide") == 0) {
        left = 42;
        right = 0;
        result = left / right;
    } else {
        return 2;
    }
    printf("%d\n", result);
    return 0;
}
