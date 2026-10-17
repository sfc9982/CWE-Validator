# Analysis method

## Purpose and scope

CWE Witness tests whether runtime evidence from a C program supports a declared CWE under one stated entry point, input, compiler configuration, and execution environment. A filename, comment, printed error, or crash alone is not evidence of a CWE. `NOT_CONFIRMED` means the configured evidence was insufficient for that run; it does not establish that the program is safe.

The project includes 11 CWE identifiers across 12 profiles: CWE-120, CWE-125, CWE-190, CWE-191, CWE-369, CWE-415, CWE-416, CWE-476, CWE-772, CWE-787, and CWE-22. Profiles define the observer and the predicates required for a finding. Missing tools or platform support produce an explicit unsupported result.

## Evidence collection

Each YAML manifest names its C sources, claimed CWE, profile, input, optional fixtures, build preset, replay count, and optional control program. Before execution, the verifier snapshots the manifest, source files, and fixtures and records their hashes. Build output, binary hash, runtime inputs, stdout/stderr, observer logs, structured result, and Markdown report are retained under `.cwe-witness/`.

Memory profiles use Clang sanitizers and require complete reports, the expected operation and access direction, object-boundary evidence, and source attribution. CWE-772 profiles inspect POSIX descriptors with Valgrind or configured custom resource lifecycles. CWE-22 traces successful file operations with strace inside Bubblewrap. Integer, divide-by-zero, and null-pointer profiles use UBSan evidence. An optional user-supplied CWE catalog can add descriptive metadata; it does not determine the runtime result. No catalog export is bundled.

## Decisions and replay

A profile can return `CONFIRMED` only when all of its required predicates are supported by the recorded evidence. Missing or mismatched evidence yields `NOT_CONFIRMED`. `UNSUPPORTED` indicates that the profile, platform, or required observer cannot run. `ERROR` indicates verification could not complete.

By default, the same input runs twice. Each run must independently meet the profile predicates, and their semantic evidence signatures must agree. Replays compare mechanism, source location, access direction, object or resource relationships, and other profile-relevant facts while ignoring process IDs and changing addresses. Results include links through predicates and observations to raw logs, run configuration, source snapshots, and build records.

A control program is optional. When supplied, it runs with the same configured input and observer. The report records whether it built and ran successfully, avoided the target finding, and produced the expected output. A failed or missing control does not alter the target program's decision; functional equivalence remains a human-reviewed claim.

## Limits

Results apply to the declared input and execution environment. They do not prove safety for other inputs or platforms, and a confirmed weakness does not by itself prove exploitability or impact. The Linux runner uses time, output, and process limits and applies Bubblewrap for selected observers; it is designed for trusted research samples, not as a security boundary against actively malicious code. Use a disposable VM for untrusted samples.

CWE-772 covers POSIX file, socket, and pipe descriptors plus configured custom resources; it does not cover every platform handle or synchronization primitive. CWE-22 requires the declared sandbox and path-tracing tools. Windows users need WSL2 for sample execution; native Windows can handle schema and report operations only. macOS sample execution is unsupported.

## Project map

- [User guide](README.md)
- [Chinese user guide](README.zh-CN.md)
- [Calibration manifests](manifests/calibration/)
- [Profiles](src/cwe_witness/profiles/)
- [Tests and synthetic calibration programs](tests/)
