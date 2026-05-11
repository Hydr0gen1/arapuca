---
title: ARAPUCA
section: 1
header: Arapuca Manual
footer: arapuca
---

# NAME

arapuca - sandbox a command with kernel-enforced isolation

# SYNOPSIS

**arapuca** **run** [*flags*] **-\-** *command* [*args*...]

**arapuca** **-\-** *command* [*args*...]

# DESCRIPTION

**arapuca run** launches *command* in a process-level sandbox with
user-friendly CLI flags. Uses the library's platform abstraction for
cross-platform support (Landlock + seccomp on Linux, Seatbelt on
macOS, AppContainer on Windows).

**arapuca -\-** *command* (legacy mode) applies sandbox restrictions
to the current process, then replaces itself with *command* via
**execve**(2). Configured via environment variables. Used internally
by the library as a subprocess wrapper.

On Linux, **arapuca** enforces Landlock filesystem restrictions,
seccomp BPF syscall filtering, POSIX resource limits, and sets
**PR_SET_PDEATHSIG** so the subprocess is killed if the parent dies.

On macOS, **arapuca** enforces POSIX resource limits only (filesystem
and network restrictions are applied by the caller via
**sandbox-exec**(1)).

The sandbox is fail-closed: if any restriction fails to apply,
**arapuca** exits non-zero and the target command never runs.

All **ARAPUCA_\*** environment variables are stripped before exec so
the sandboxed process cannot inspect its own configuration.
Non-**ARAPUCA** variables (e.g., **AGENT_NETWORK_PROXY**) are
preserved.

# OPTIONS (arapuca run)

**-v** *path*[**:ro**]
:   Allow access to *path*. Read-write by default; append **:ro** for
    read-only. Repeatable. Paths must be absolute. Default system paths
    (*/usr*, */lib*, */bin*, */etc/ssl*, device nodes) are always
    included. */proc*, */sys*, and blanket */dev* are NOT included by
    default.

**-\-env** *KEY*=*VALUE*
:   Pass an environment variable to the sandboxed process. Dangerous
    variables (**LD_PRELOAD**, **ARAPUCA_\***, **DYLD_\***, interpreter
    injection vectors) are rejected. Sandbox-managed variables (**HOME**,
    **TMPDIR**, **PATH**, **LANG**) cannot be overridden. Repeatable.

**-\-timeout** *N*
:   Kill the process after *N* seconds. Sends **SIGTERM** first, then
    **SIGKILL** after a 5-second grace period. *N* must be greater
    than 0.

**-\-memory** *N*
:   Memory limit in megabytes. Enforced via cgroups v2 on Linux, RSS
    polling on macOS, Job Objects on Windows.

**-\-cpus** *N*
:   CPU limit as a percentage of a single core. 200 means 2 cores.

**-\-pids** *N*
:   Maximum number of PIDs (cgroups v2 on Linux, Job Objects on Windows).

**-\-task-id** *NAME*
:   Identifier for cgroup directory and audit events. Must match
    **[a-zA-Z0-9-]+**, max 128 characters. Defaults to **run-***pid*.

**-\-allow-host** *host*:*port*
:   Allow HTTPS traffic to *host*:*port* via a CONNECT proxy tunnel.
    Repeatable. When specified, the sandboxed process runs in a network
    namespace with no direct network access. A CONNECT proxy on the
    host network tunnels traffic only to listed hosts. DNS resolution
    happens in the proxy with IP validation (loopback, RFC 1918,
    link-local, and cloud metadata addresses are rejected to prevent
    DNS rebinding SSRF). Exact hostname match only (no wildcards).
    Linux only.

# ENVIRONMENT (legacy mode)

The following variables configure the legacy **arapuca -\-** mode.
They are not used by **arapuca run** (which uses CLI flags instead).

**ARAPUCA_READ_PATHS**

:   Colon-separated list of paths the subprocess may read. Each path
    and everything below it is readable.

        ARAPUCA_READ_PATHS=/usr:/lib:/lib64:/bin:/etc:/dev

**ARAPUCA_WRITE_PATHS**

:   Colon-separated list of paths the subprocess may read and write.

        ARAPUCA_WRITE_PATHS=/tmp/workspace

**ARAPUCA_RLIMIT_AS**

:   Maximum virtual memory size in bytes. Enforced via **setrlimit**(2)
    (**RLIMIT_AS**). Set to 0 or omit to leave unlimited.

    On Apple Silicon, **RLIMIT_AS** should not be set -- macOS
    aggressively maps virtual memory and setting this limit causes
    immediate **SIGKILL**.

**ARAPUCA_RLIMIT_NPROC**

:   Maximum number of processes for the user. Enforced via
    **setrlimit**(2) (**RLIMIT_NPROC**). Set to 0 or omit to leave
    unlimited.

**ARAPUCA_RLIMIT_CPU**

:   Maximum CPU time in seconds. Enforced via **setrlimit**(2)
    (**RLIMIT_CPU**). The kernel sends **SIGXCPU** when the soft limit
    is reached and **SIGKILL** at the hard limit. Set to 0 or omit to
    leave unlimited.

**ARAPUCA_RLIMIT_FSIZE**

:   Maximum file size in bytes. Enforced via **setrlimit**(2)
    (**RLIMIT_FSIZE**). Writes that would exceed the limit receive
    **SIGXFSZ**. Set to 0 or omit to leave unlimited.

# EXIT STATUS

**0**
:   The target command exited successfully.

**1**
:   Usage error in legacy mode (no **-\-** separator, command not found,
    or sandbox setup failed). A diagnostic is printed to stderr.

**>1**
:   The target command exited with a non-zero status. The exit code is
    passed through.

**125**
:   Sandbox infrastructure error (**arapuca run** only). Invalid flags,
    sandbox setup failure, or CONNECT proxy failure.

**137**
:   The target command was killed by **SIGKILL** (e.g., parent died and
    **PR_SET_PDEATHSIG** fired, cgroup OOM kill, or timeout SIGKILL).

**143**
:   The target command was killed by **SIGTERM** (e.g., timeout fired).

# SECURITY

## Linux

On Linux (kernel 5.13+), **arapuca** enforces:

**Landlock**
:   Restricts filesystem access to the paths listed in
    **ARAPUCA_READ_PATHS** and **ARAPUCA_WRITE_PATHS**. All other
    paths are inaccessible. Supports ABI versions 1 through 6.

**Seccomp BPF**
:   Installs a syscall filter with two tiers:

    *KILL_PROCESS*: ptrace, mount, chroot, unshare, setns, clone3,
    memfd_create, io_uring, bpf, kexec, kernel module loading.

    *EPERM*: symlink, link, socket(AF_INET), socket(AF_INET6),
    perf_event_open.

    **socket**(AF_UNIX) is allowed -- it is needed for IPC with the
    host (JSON-RPC control socket, LLM proxy).

**PR_SET_NO_NEW_PRIVS**
:   Set before Landlock and seccomp. Prevents privilege escalation via
    setuid binaries.

**PR_SET_PDEATHSIG**
:   Sends **SIGKILL** to the subprocess if the parent process dies.
    Prevents orphaned sandboxed processes.

## macOS

On macOS, **arapuca** enforces only POSIX resource limits. Filesystem
and network restrictions are applied externally by **sandbox-exec**(1)
using a Seatbelt profile generated by the arapuca library.

## Both Platforms

**POSIX resource limits**
:   **RLIMIT_AS**, **RLIMIT_NPROC**, **RLIMIT_CPU**, and
    **RLIMIT_FSIZE** are set as both soft and hard limits, so the
    subprocess cannot raise them.

**Environment stripping**
:   All **ARAPUCA_\*** variables are removed. The subprocess cannot
    discover its own sandbox configuration.

# EXAMPLES

## arapuca run

Run a command with default sandboxing:

    arapuca run -- /bin/echo hello

Grant read-only access to a project directory:

    arapuca run -v /home/user/project:ro -- ls /home/user/project

Sandbox a Claude Code agent with selective HTTPS access:

    arapuca run \
      -v /home/user/repo \
      --allow-host us-east5-aiplatform.googleapis.com:443 \
      --allow-host oauth2.googleapis.com:443 \
      --env VERTEXAI_PROJECT=my-project \
      --timeout 600 --memory 3072 \
      -- claude --bare -p --model claude-sonnet-4-6

## Legacy mode (arapuca -\-)

Run a Python script with read access to system paths and write access
to a workspace directory:

    ARAPUCA_READ_PATHS=/usr:/lib:/lib64:/bin:/etc:/dev \
    ARAPUCA_WRITE_PATHS=/tmp/workspace \
    arapuca -- python3 agent.py

Run a command with resource limits (2 GB memory, 256 processes, 1 hour
CPU, 1 GB max file size):

    ARAPUCA_RLIMIT_AS=2147483648 \
    ARAPUCA_RLIMIT_NPROC=256 \
    ARAPUCA_RLIMIT_CPU=3600 \
    ARAPUCA_RLIMIT_FSIZE=1073741824 \
    arapuca -- ./run-tests.sh

Run with no filesystem restrictions (seccomp + rlimits only on Linux,
rlimits only on macOS):

    arapuca -- /bin/echo "sandboxed"

# SEE ALSO

**landlock**(7), **seccomp**(2), **setrlimit**(2), **sandbox-exec**(1),
**prctl**(2), **execve**(2), **unshare**(1)

# AUTHORS

Sergio Correia \<scorreia@redhat.com\>
