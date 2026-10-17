#include <fcntl.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

int main(int argc, char **argv) {
    if (argc < 2) return 0;
    int descriptors[2] = {-1, -1};
    if (strncmp(argv[1], "file-", 5) == 0) {
        descriptors[0] = open("/dev/null", O_RDONLY);
    } else if (strncmp(argv[1], "socket-", 7) == 0) {
        if (socketpair(AF_UNIX, SOCK_STREAM, 0, descriptors) != 0) return 1;
    } else if (strncmp(argv[1], "pipe-", 5) == 0) {
        if (pipe(descriptors) != 0) return 1;
    }
    if (strstr(argv[1], "closed") != NULL) {
        if (descriptors[0] >= 0) close(descriptors[0]);
        if (descriptors[1] >= 0) close(descriptors[1]);
    }
    return descriptors[0] < 0;
}
