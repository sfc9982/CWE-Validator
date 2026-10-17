import os
import re
import shutil
import subprocess
from pathlib import Path

from .manifest import digest
from .models import AllocationFailure, Build, FunctionFailure, NullContract


def required_link_flags(sources: list[Path]) -> list[str]:
    """Return system-library flags implied by the source includes.

    OpenSSL headers are shipped by ``libssl-dev`` but the symbols used by
    samples are provided by libcrypto, so those programs must be linked with
    ``-lcrypto``.  Detection is deliberately limited to an explicit OpenSSL
    include; ordinary C/POSIX samples keep the existing command unchanged.
    """
    openssl_include = re.compile(r"^\s*#\s*include\s*[<\"]openssl/", re.MULTILINE)
    if any(
        openssl_include.search(source.read_text(encoding="utf-8", errors="replace"))
        for source in sources
    ):
        return ["-lcrypto"]
    return []


def clean_environment() -> dict[str, str]:
    return {"PATH": os.defpath, "LANG": "C", "LC_ALL": "C"}


def compile_sources(
    sources: list[Path],
    directory: Path,
    build_id: str,
    preset: str = "clang-asan-debug",
    allocation_failure: AllocationFailure | None = None,
    function_failure: FunctionFailure | None = None,
    null_contract: NullContract | None = None,
    copy_observer: bool | None = None,
) -> Build:
    directory.mkdir(parents=True, exist_ok=True)
    compiler = shutil.which("clang")
    if not compiler:
        raise FileNotFoundError("clang is not available")
    compiler = str(Path(compiler).resolve())
    version = subprocess.run(
        [compiler, "--version"],
        capture_output=True,
        text=True,
        timeout=10,
        env=clean_environment(),
        check=True,
    ).stdout
    binary = directory / "sample"
    instrumentation = {
        "clang-asan-debug": ["-fsanitize=address", "-fno-omit-frame-pointer"],
        "clang-asan-recover-debug": [
            "-fsanitize=address",
            "-fsanitize-recover=address",
            "-fno-omit-frame-pointer",
        ],
        "clang-asan-copy-debug": ["-fsanitize=address", "-fno-omit-frame-pointer"],
        "clang-asan-bounds-debug": [
            "-fsanitize=address,bounds",
            "-fno-sanitize-recover=bounds",
            "-fno-omit-frame-pointer",
        ],
        "clang-debug": ["-gdwarf-4", "-fno-omit-frame-pointer", "-fno-inline"],
        "clang-ubsan-debug": [
            "-fsanitize=undefined,signed-integer-overflow,unsigned-integer-overflow",
            "-fno-sanitize-recover=all",
            "-fno-omit-frame-pointer",
        ],
        "clang-ubsan-float-debug": [
            "-fsanitize=undefined,signed-integer-overflow,unsigned-integer-overflow,"
            "float-divide-by-zero",
            "-fno-sanitize-recover=all",
            "-fno-omit-frame-pointer",
        ],
        "clang-asan-ubsan-debug": [
            "-fsanitize=address,undefined,signed-integer-overflow,unsigned-integer-overflow",
            "-fno-sanitize-recover=all",
            "-fno-omit-frame-pointer",
        ],
    }[preset]
    from .runner import execute

    common = [compiler, "-std=c11", "-O0", "-g", "-Wall", "-Wextra", "-D_DEFAULT_SOURCE"]
    commands: list[list[str]] = []
    source_hashes = {str(source): digest(source) for source in sources}
    if copy_observer is None:
        copy_observer = preset == "clang-asan-copy-debug"
    if allocation_failure is None and function_failure is None and not copy_observer:
        argv = [
            *common,
            *instrumentation,
            *map(str, sources),
            *required_link_flags(sources),
            "-o",
            str(binary),
        ]
        commands.append(argv)
        result = execute(argv, directory, b"", clean_environment(), 60, 67108864)
        exit_code = result["exit_code"]
        stdout = str(directory / "stdout.txt")
        stderr = str(directory / "stderr.txt")
        launch_argv = result["launch_argv"]
    else:
        shim = directory / (
            "allocation-failure-shim.c"
            if allocation_failure
            else "null-contract-shim.c"
            if function_failure
            else "copy-observer-shim.c"
        )
        if allocation_failure:
            wrapper_name = f"cwe_witness_injected_{allocation_failure.function}"
        if allocation_failure and allocation_failure.function == "malloc":
            signature = "void *{name}(size_t size)".format(name=wrapper_name)
            passthrough = "return malloc(size);"
        elif allocation_failure:
            signature = "void *{name}(size_t count, size_t size)".format(name=wrapper_name)
            passthrough = "return calloc(count, size);"
        if allocation_failure:
            shim.write_text(
                "#include <stddef.h>\n"
                "#include <stdio.h>\n"
                "#include <stdlib.h>\n\n"
                f"static size_t cwe_witness_calls;\n"
                f"{signature} {{\n"
                "    ++cwe_witness_calls;\n"
                f"    if (cwe_witness_calls == {allocation_failure.call_index}u) {{\n"
                '        const char *path = getenv("CWE_WITNESS_ALLOCATION_FAILURE_LOG");\n'
                '        FILE *log = path ? fopen(path, "a") : NULL;\n'
                f'        if (log) {{ fprintf(log, "inject|{allocation_failure.function}|{allocation_failure.call_index}\\n"); fflush(log); fclose(log); }}\n'
                "        return NULL;\n"
                "    }\n"
                f"    {passthrough}\n"
                "}\n",
                encoding="utf-8",
            )
            source_flags = [f"-D{allocation_failure.function}={wrapper_name}"]
        elif function_failure:
            if null_contract is None:
                raise ValueError("function_failure requires null_contract")
            header = directory / "null-contract-header.h"
            header.write_text(
                "#include <stdio.h>\n"
                "FILE *cwe_witness_fopen(const char *, const char *, const char *, int);\n"
                "int cwe_witness_fprintf(FILE *, const char *, int, const char *, ...);\n"
                "size_t cwe_witness_fread(void *, size_t, size_t, FILE *, const char *, int);\n"
                "#define fopen(path, mode) cwe_witness_fopen((path), (mode), __FILE__, __LINE__)\n"
                + (
                    "#define fprintf(stream, ...) cwe_witness_fprintf((stream), __FILE__, __LINE__, __VA_ARGS__)\n"
                    if null_contract.function == "fprintf"
                    else "#define fread(ptr, size, count, stream) cwe_witness_fread((ptr), (size), (count), (stream), __FILE__, __LINE__)\n"
                ),
                encoding="utf-8",
            )
            shim.write_text(
                "#include <stdarg.h>\n#include <stdio.h>\n#include <stdlib.h>\n"
                "static unsigned calls;\n"
                "static void log_event(const char *kind, const char *file, int line) {\n"
                ' const char *p=getenv("CWE_WITNESS_NULL_CONTRACT_LOG"); if(!p)return; FILE *f=fopen(p,"a"); if(f){fprintf(f,"%s|%s|%d\\n",kind,file,line);fflush(f);fclose(f);}\n}\n'
                f'FILE *cwe_witness_fopen(const char *p,const char *m,const char *f,int l){{ if(++calls=={function_failure.call_index}u){{log_event("failure",f,l);return NULL;}} return fopen(p,m);}}\n'
                'int cwe_witness_fprintf(FILE *s,const char *f,int l,const char *fmt,...){va_list a;va_start(a,fmt);if(!s)log_event("null_sink",f,l);int r=vfprintf(s,fmt,a);va_end(a);return r;}\n',
                encoding="utf-8",
            )
            if null_contract.function == "fread":
                with shim.open("a", encoding="utf-8") as shim_file:
                    shim_file.write(
                        "size_t cwe_witness_fread(void *p,size_t z,size_t n,FILE *s,const char *f,int l){"
                        'if(!s)log_event("null_sink",f,l);return fread(p,z,n,s);}\n'
                    )
            source_hashes[str(header)] = digest(header)
            source_flags = ["-include", str(header)]
        else:
            header = directory / "copy-observer-header.h"
            header.write_text(
                "#ifndef CWE_WITNESS_COPY_HEADER\n"
                "#define CWE_WITNESS_COPY_HEADER\n"
                "#include <stdio.h>\n"
                "#include <string.h>\n"
                "void *cwe_witness_memcpy(void *, const void *, size_t, size_t, const char *, int);\n"
                "void *cwe_witness_memmove(void *, const void *, size_t, size_t, const char *, int);\n"
                "char *cwe_witness_strcpy(char *, const char *, size_t, const char *, int);\n"
                "char *cwe_witness_strcat(char *, const char *, size_t, const char *, int);\n"
                "char *cwe_witness_strncpy(char *, const char *, size_t, size_t, const char *, int);\n"
                "char *cwe_witness_strncat(char *, const char *, size_t, size_t, const char *, int);\n"
                "int cwe_witness_sprintf(char *, size_t, const char *, int, const char *, ...);\n"
                "char *cwe_witness_gets(char *, size_t, const char *, int);\n"
                "#define memcpy(d,s,n) cwe_witness_memcpy((d),(s),(n),__builtin_dynamic_object_size((d),1),__FILE__,__LINE__)\n"
                "#define memmove(d,s,n) cwe_witness_memmove((d),(s),(n),__builtin_dynamic_object_size((d),1),__FILE__,__LINE__)\n"
                "#define strcpy(d,s) cwe_witness_strcpy((d),(s),__builtin_dynamic_object_size((d),1),__FILE__,__LINE__)\n"
                "#define strcat(d,s) cwe_witness_strcat((d),(s),__builtin_dynamic_object_size((d),1),__FILE__,__LINE__)\n"
                "#define strncpy(d,s,n) cwe_witness_strncpy((d),(s),(n),__builtin_dynamic_object_size((d),1),__FILE__,__LINE__)\n"
                "#define strncat(d,s,n) cwe_witness_strncat((d),(s),(n),__builtin_dynamic_object_size((d),1),__FILE__,__LINE__)\n"
                "#define sprintf(d,f,...) cwe_witness_sprintf((d),__builtin_dynamic_object_size((d),1),__FILE__,__LINE__,(f),##__VA_ARGS__)\n"
                "#define gets(d) cwe_witness_gets((d),__builtin_dynamic_object_size((d),1),__FILE__,__LINE__)\n"
                "#endif\n",
                encoding="utf-8",
            )
            shim.write_text(
                "#include <stdarg.h>\n"
                "#include <stdio.h>\n"
                "#include <stdlib.h>\n"
                "#include <string.h>\n"
                "static void cwe_witness_log(const char *op, const char *file, int line, size_t cap, size_t actual) {\n"
                ' const char *p=getenv("CWE_WITNESS_COPY_LOG"); if(!p)return; FILE *f=fopen(p,"a"); if(f){fprintf(f,"%s|%s|%d|%zu|%zu\\n",op,file,line,cap,actual);fflush(f);fclose(f);}\n'
                "}\n"
                "static size_t cwe_witness_src_size(const char *s) { return s ? strlen(s) : 0; }\n"
                'void *cwe_witness_memcpy(void *d,const void *s,size_t n,size_t c,const char *f,int l){cwe_witness_log("memcpy",f,l,c,n);return memcpy(d,s,n);}\n'
                'void *cwe_witness_memmove(void *d,const void *s,size_t n,size_t c,const char *f,int l){cwe_witness_log("memmove",f,l,c,n);return memmove(d,s,n);}\n'
                'char *cwe_witness_strcpy(char *d,const char *s,size_t c,const char *f,int l){size_t n=cwe_witness_src_size(s)+1;cwe_witness_log("strcpy",f,l,c,n);return strcpy(d,s);}\n'
                'char *cwe_witness_strcat(char *d,const char *s,size_t c,const char *f,int l){size_t n=strlen(d)+cwe_witness_src_size(s)+1;cwe_witness_log("strcat",f,l,c,n);return strcat(d,s);}\n'
                'char *cwe_witness_strncpy(char *d,const char *s,size_t n,size_t c,const char *f,int l){cwe_witness_log("strncpy",f,l,c,n);return strncpy(d,s,n);}\n'
                'char *cwe_witness_strncat(char *d,const char *s,size_t n,size_t c,const char *f,int l){size_t w=strlen(d)+(cwe_witness_src_size(s)<n?cwe_witness_src_size(s):n)+1;cwe_witness_log("strncat",f,l,c,w);return strncat(d,s,n);}\n'
                'int cwe_witness_sprintf(char *d,size_t c,const char *f,int l,const char *fmt,...){va_list a,b;va_start(a,fmt);va_copy(b,a);int n=vsnprintf(NULL,0,fmt,b);va_end(b);cwe_witness_log("sprintf",f,l,c,n<0?0:(size_t)n+1);int r=vsprintf(d,fmt,a);va_end(a);return r;}\n'
                'extern char *cwe_witness_real_gets(char *) __asm__("gets");\n'
                'char *cwe_witness_gets(char *d,size_t c,const char *f,int l){char *r=cwe_witness_real_gets(d);size_t n=r?strlen(d)+1:0;cwe_witness_log("gets",f,l,c,n);return r;}\n',
                encoding="utf-8",
            )
            source_hashes[str(header)] = digest(header)
            source_flags = ["-include", str(header)]

        source_hashes[str(shim)] = digest(shim)
        object_directory = directory / "objects"
        object_directory.mkdir(parents=True, exist_ok=True)
        object_paths: list[Path] = []
        for index, source in enumerate(sources):
            object_path = object_directory / f"target-{index}.o"
            object_paths.append(object_path)
            command = [
                *common,
                *instrumentation,
                *source_flags,
                "-c",
                str(source),
                "-o",
                str(object_path),
            ]
            commands.append(command)
            compile_directory = directory / f"compile-target-{index}"
            compile_directory.mkdir()
            compile_result = execute(
                command, compile_directory, b"", clean_environment(), 60, 67108864
            )
            if compile_result["exit_code"] != 0:
                argv = command
                exit_code = int(compile_result["exit_code"])
                stdout = str(compile_directory / "stdout.txt")
                stderr = str(compile_directory / "stderr.txt")
                launch_argv = compile_result["launch_argv"]
                break
        else:
            shim_object = object_directory / f"{shim.stem}.o"
            shim_command = [
                *common,
                *instrumentation,
                "-c",
                str(shim),
                "-o",
                str(shim_object),
            ]
            commands.append(shim_command)
            shim_directory = directory / "compile-shim"
            shim_directory.mkdir()
            shim_result = execute(
                shim_command, shim_directory, b"", clean_environment(), 60, 67108864
            )
            if shim_result["exit_code"] != 0:
                argv = shim_command
                exit_code = int(shim_result["exit_code"])
                stdout = str(shim_directory / "stdout.txt")
                stderr = str(shim_directory / "stderr.txt")
                launch_argv = shim_result["launch_argv"]
            else:
                argv = [
                    *common,
                    *instrumentation,
                    *map(str, [*object_paths, shim_object]),
                    *required_link_flags(sources),
                    "-o",
                    str(binary),
                ]
                commands.append(argv)
                link_result = execute(argv, directory, b"", clean_environment(), 60, 67108864)
                exit_code = int(link_result["exit_code"])
                stdout = str(directory / "stdout.txt")
                stderr = str(directory / "stderr.txt")
                launch_argv = link_result["launch_argv"]
    return Build(
        build_id=build_id,
        argv=argv,
        commands=commands,
        launch_argv=launch_argv,
        compiler_version=version,
        source_hashes=source_hashes,
        binary=str(binary),
        binary_hash=digest(binary) if binary.is_file() else None,
        exit_code=exit_code,
        stdout=stdout,
        stderr=stderr,
    )
