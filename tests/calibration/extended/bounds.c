#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(int argc, char **argv) {
    if (argc != 3) {
        return 2;
    }

    int values[2] = {11, 22};
    int index = atoi(argv[2]);
    if (strcmp(argv[1], "read") == 0) {
        printf("%d\n", values[index]);
    } else if (strcmp(argv[1], "write") == 0) {
        values[index] = 33;
        printf("%d\n", values[0]);
    } else {
        return 2;
    }
    return 0;
}
