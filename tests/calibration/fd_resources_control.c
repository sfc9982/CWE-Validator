#include <fcntl.h>
#include <string.h>
#include <unistd.h>

int main(int argc, char **argv) {
    if (argc < 2 || strncmp(argv[1], "file-", 5) != 0) return 0;
    int descriptor = open("/dev/null", O_RDONLY);
    if (descriptor < 0) return 1;
    return close(descriptor) != 0;
}
