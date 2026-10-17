#include <stdio.h>
#include <string.h>

/* The undersized destination deliberately exercises the copy observer. */
int main(void) {
    char destination[8];
    const char *input = "synthetic-overflow";
    strcpy(destination, input);
    puts(destination);
    return 0;
}
