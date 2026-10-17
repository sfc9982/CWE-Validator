#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(void) {
    char *record = malloc(64);
    if (record == NULL) {
        return 1;
    }
    strcpy(record, "order ready");
    printf("Order status: %s", record);
    free(record);
    return 0;
}
