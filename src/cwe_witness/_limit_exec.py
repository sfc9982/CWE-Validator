"""Single-process Linux resource-limit launcher; uses exec, never a shell."""

import os
import resource
import sys

if __name__ == "__main__":
    limit, timeout = int(sys.argv[1]), int(sys.argv[2])
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    resource.setrlimit(resource.RLIMIT_FSIZE, (limit, limit))
    resource.setrlimit(resource.RLIMIT_NOFILE, (128, 128))
    resource.setrlimit(resource.RLIMIT_CPU, (timeout + 1, timeout + 2))
    os.execvpe(sys.argv[3], sys.argv[3:], os.environ)
