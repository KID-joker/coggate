/*
 * Coggate single-request worker. MIT licensed.
 *
 * Protocol, all lengths unsigned big-endian:
 * request:  "CGW1", source_len:u32, source, count:u32,
 *           repeated (input_len:u32, JSON input).
 * response: "CGR1", count:u32,
 *           repeated (status:u8, payload_len:u32, payload).
 * status: 0 = JSON result, 1 = submission failure, 2 = resource limit,
 *         3 = internal/protocol/unsupported failure.
 *
 * The caller must treat nonzero exit, truncated/extra output, wrong count,
 * or any nonzero status as a failure. A preflight failure has count=1,
 * status=3 and exit code 2. The worker never receives expected answers.
 */
#include <errno.h>
#include <limits.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <signal.h>
#include <sys/resource.h>
#include <sys/time.h>

#include "mquickjs.h"
#include "coggate_stdlib.h"

#if defined(__linux__) && !defined(COGGATE_ENGINE_TEST_ONLY)
#include <fcntl.h>
#include <linux/audit.h>
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <sys/prctl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#endif

#define SOURCE_LIMIT 65536
#define INPUT_LIMIT 4096
#define OUTPUT_LIMIT 65536
#define CASE_LIMIT 32
#define ARENA_SIZE (2 * 1024 * 1024)
#define CPU_BUDGET_NS UINT64_C(200000000)
#define WALL_BUDGET_NS UINT64_C(500000000)

static union {
    uint64_t alignment;
    unsigned char bytes[ARENA_SIZE];
} arena;
static char source[SOURCE_LIMIT + 1];
static char input[INPUT_LIMIT + 1];
static uint64_t start_cpu, start_wall;
static int interrupted;

static uint64_t now_ns(clockid_t clock)
{
    struct timespec t;
    if (clock_gettime(clock, &t) != 0)
        return UINT64_MAX;
    return (uint64_t)t.tv_sec * UINT64_C(1000000000) + (uint64_t)t.tv_nsec;
}

static int over_budget(void)
{
    uint64_t cpu = now_ns(CLOCK_PROCESS_CPUTIME_ID);
    uint64_t wall = now_ns(CLOCK_MONOTONIC);
    if (cpu == UINT64_MAX || wall == UINT64_MAX ||
        cpu - start_cpu >= CPU_BUDGET_NS || wall - start_wall >= WALL_BUDGET_NS) {
        interrupted = 1;
        return 1;
    }
    return 0;
}

static int interrupt_handler(JSContext *ctx, void *opaque)
{
    (void)ctx;
    (void)opaque;
    return over_budget();
}

static int read_exact(void *buffer, size_t length)
{
    unsigned char *p = buffer;
    while (length) {
        ssize_t n = read(STDIN_FILENO, p, length);
        if (n < 0 && errno == EINTR)
            continue;
        if (n <= 0)
            return -1;
        p += n;
        length -= (size_t)n;
    }
    return 0;
}

static int write_exact(const void *buffer, size_t length)
{
    const unsigned char *p = buffer;
    while (length) {
        ssize_t n = write(STDOUT_FILENO, p, length);
        if (n < 0 && errno == EINTR)
            continue;
        if (n <= 0)
            return -1;
        p += n;
        length -= (size_t)n;
    }
    return 0;
}

static int read_u32(uint32_t *value)
{
    unsigned char b[4];
    if (read_exact(b, 4))
        return -1;
    *value = ((uint32_t)b[0] << 24) | ((uint32_t)b[1] << 16) |
        ((uint32_t)b[2] << 8) | (uint32_t)b[3];
    return 0;
}

static int write_u32(uint32_t value)
{
    unsigned char b[4] = {
        (unsigned char)(value >> 24), (unsigned char)(value >> 16),
        (unsigned char)(value >> 8), (unsigned char)value
    };
    return write_exact(b, 4);
}

static int response_header(uint32_t count)
{
#ifdef COGGATE_ENGINE_TEST_ONLY
    /* A production caller must reject development-engine responses, even if
       the wrong binary is accidentally deployed at the worker path. */
    return write_exact("CGE1", 4) || write_u32(count);
#else
    return write_exact("CGR1", 4) || write_u32(count);
#endif
}

static int response_item(unsigned char status, const char *payload, size_t length)
{
    return write_exact(&status, 1) || write_u32((uint32_t)length) ||
        write_exact(payload, length);
}

static int preflight_failure(const char *reason)
{
    response_header(1);
    response_item(3, reason, strlen(reason));
    return 2;
}

static int set_limit(int resource, rlim_t value)
{
    struct rlimit limit = {value, value};
    return setrlimit(resource, &limit);
}

static int install_timers(void)
{
    /* Native parser and regexp work must also be bounded, independently of
       interpreter interrupt polling. The parent enforces its own deadline. */
    struct itimerval wall = {{0, 0}, {0, 500000}};
    struct itimerval cpu = {{0, 0}, {0, 200000}};
    if (signal(SIGALRM, SIG_DFL) == SIG_ERR ||
        signal(SIGPROF, SIG_DFL) == SIG_ERR ||
        signal(SIGPIPE, SIG_DFL) == SIG_ERR)
        return -1;
    sigset_t unblocked;
    sigemptyset(&unblocked);
    sigaddset(&unblocked, SIGALRM);
    sigaddset(&unblocked, SIGPROF);
    if (sigprocmask(SIG_UNBLOCK, &unblocked, NULL))
        return -1;
    return setitimer(ITIMER_REAL, &wall, NULL) ||
        setitimer(ITIMER_PROF, &cpu, NULL);
}

#if defined(__linux__) && !defined(COGGATE_ENGINE_TEST_ONLY)
#if defined(__x86_64__)
#define EXPECTED_ARCH AUDIT_ARCH_X86_64
#elif defined(__aarch64__)
#define EXPECTED_ARCH AUDIT_ARCH_AARCH64
#endif

static int install_filter(void)
{
#ifndef EXPECTED_ARCH
    return -1;
#else
    /* No opens, sockets, process creation, exec, ptrace, descriptor passing,
       arbitrary reads/writes, or memory mappings are needed after startup.
       An engine exploit may write this worker's response pipe, so expected
       outputs and all application secrets must remain in the parent. */
    struct sock_filter rules[] = {
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, arch)),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, EXPECTED_ARCH, 1, 0),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_KILL_PROCESS),
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, nr)),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_read, 0, 4),
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, args[0])),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, STDIN_FILENO, 0, 1),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | EPERM),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_write, 0, 4),
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, args[0])),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, STDOUT_FILENO, 0, 1),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | EPERM),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_clock_gettime, 0, 1),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_exit, 0, 1),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_exit_group, 0, 1),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_rt_sigreturn, 0, 1),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | EPERM),
    };
    struct sock_fprog program = {
        (unsigned short)(sizeof(rules) / sizeof(rules[0])), rules
    };
    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0))
        return -1;
    return prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &program);
#endif
}

static int isolate(void)
{
    extern char **environ;
    struct stat in, out;
    struct rlimit descriptors;
    /* Restrict stdin/stdout to anonymous pipe capabilities. In particular,
       a caller must not pass a sensitive regular file as either descriptor. */
    if (fstat(0, &in) || fstat(1, &out) ||
        !S_ISFIFO(in.st_mode) || !S_ISFIFO(out.st_mode))
        return -1;
    if (environ) {
        for (char **entry = environ; *entry; ++entry)
            memset(*entry, 0, strlen(*entry));
    }
    if (clearenv())
        return -1;
    if (getrlimit(RLIMIT_NOFILE, &descriptors))
        return -1;
#ifdef SYS_close_range
    if (syscall(SYS_close_range, 2u, ~0u, 0u) < 0)
#endif
    {
        if (descriptors.rlim_cur == RLIM_INFINITY ||
            descriptors.rlim_cur > 1048576)
            return -1;
        for (rlim_t fd = 2; fd < descriptors.rlim_cur; ++fd)
            close((int)fd);
    }
    if (set_limit(RLIMIT_CORE, 0) ||
        set_limit(RLIMIT_AS, 32 * 1024 * 1024) ||
        set_limit(RLIMIT_STACK, 1024 * 1024) ||
        set_limit(RLIMIT_CPU, 1) ||
        set_limit(RLIMIT_FSIZE, 0) ||
        set_limit(RLIMIT_NOFILE, 2) ||
        set_limit(RLIMIT_NPROC, 0))
        return -1;
    if (prctl(PR_SET_DUMPABLE, 0, 0, 0, 0) || install_timers())
        return -1;
    return install_filter();
}

static int isolation_self_test(void)
{
    int failures = 0;
    errno = 0;
    failures += syscall(SYS_openat, AT_FDCWD, "/etc/passwd", O_RDONLY, 0) != -1 ||
        errno != EPERM;
    errno = 0;
    failures += syscall(SYS_socket, AF_INET, SOCK_STREAM, 0) != -1 || errno != EPERM;
    errno = 0;
    failures += syscall(SYS_execve, "/bin/true", NULL, NULL) != -1 || errno != EPERM;
    errno = 0;
    failures += syscall(SYS_dup, STDIN_FILENO) != -1 || errno != EPERM;
    errno = 0;
    failures += syscall(SYS_write, 2, "", 0) != -1 || errno != EPERM;
    response_header(1);
    response_item(failures ? 3 : 0, failures ? "failed" : "isolated",
                  failures ? 6 : 8);
    return failures ? 2 : 0;
}
#endif

static int execute_case(uint32_t source_length, uint32_t input_length)
{
    JSContext *ctx = JS_NewContext(arena.bytes, sizeof(arena.bytes), &js_stdlib);
    JSGCRef parsed, stringify, result;
    JSValue value, global, json;
    int status = 1, io_status;
    const char *message = "javascript exception";
    const char *output = NULL;
    size_t output_length = 0;
    JSCStringBuf output_buffer;
    JS_SetInterruptHandler(ctx, interrupt_handler);

    /* Capture roots before submitted code can change global JSON or GC move
       the input. JS_EVAL_JSON parses data; no input is interpolated into JS. */
    *JS_AddGCRef(ctx, &parsed) = JS_UNDEFINED;
    *JS_AddGCRef(ctx, &stringify) = JS_UNDEFINED;
    *JS_AddGCRef(ctx, &result) = JS_UNDEFINED;
    global = JS_GetGlobalObject(ctx);
    json = JS_GetPropertyStr(ctx, global, "JSON");
    stringify.val = JS_GetPropertyStr(ctx, json, "stringify");
    if (!JS_IsFunction(ctx, stringify.val)) {
        status = 3;
        message = "engine initialization failed";
        goto done;
    }
    /* JSON-mode Parse returns the value directly. Eval would incorrectly
       attempt to execute that value as a bytecode function. */
    parsed.val = JS_Parse(ctx, input, input_length, "<input>", JS_EVAL_JSON);
    if (JS_IsException(parsed.val)) {
        status = 3;
        message = "invalid input JSON";
        goto done;
    }
    if (over_budget()) {
        status = 2;
        message = "request budget exceeded";
        goto done;
    }
    value = JS_Eval(ctx, source, source_length, "<submission>", JS_EVAL_STRIP_COL);
    if (JS_IsException(value))
        goto js_failure;
    result.val = JS_GetPropertyStr(ctx, JS_GetGlobalObject(ctx), "solve");
    if (!JS_IsFunction(ctx, result.val)) {
        message = "solve must be a function";
        goto done;
    }
    if (JS_StackCheck(ctx, 3))
        goto js_failure;
    JS_PushArg(ctx, parsed.val);
    JS_PushArg(ctx, result.val);
    JS_PushArg(ctx, JS_UNDEFINED);
    result.val = JS_Call(ctx, 1);
    if (JS_IsException(result.val))
        goto js_failure;
    /* MicroQuickJS serializes top-level undefined/functions as null. Reject
       these explicitly instead of accepting an unintended null answer. */
    if (JS_IsUndefined(result.val) || JS_IsFunction(ctx, result.val)) {
        message = "solve must return a JSON value";
        goto done;
    }
    if (JS_StackCheck(ctx, 3))
        goto js_failure;
    JS_PushArg(ctx, result.val);
    JS_PushArg(ctx, stringify.val);
    JS_PushArg(ctx, JS_UNDEFINED);
    result.val = JS_Call(ctx, 1);
    if (JS_IsException(result.val))
        goto js_failure;
    if (!JS_IsString(ctx, result.val)) {
        message = "solve must return a JSON value";
        goto done;
    }
    output = JS_ToCStringLen(ctx, &output_length, result.val, &output_buffer);
    if (!output)
        goto js_failure;
    if (output_length > OUTPUT_LIMIT) {
        status = 2;
        message = "output limit exceeded";
        goto done;
    }
    if (over_budget()) {
        status = 2;
        message = "request budget exceeded";
        goto done;
    }
    status = 0;
    goto done;

js_failure:
    value = JS_GetException(ctx);
    if (interrupted || JS_GetClassID(ctx, value) == JS_CLASS_INTERNAL_ERROR) {
        status = 2;
        message = "engine resource limit";
    }
done:
    if (status)
        io_status = response_item((unsigned char)status, message, strlen(message));
    else
        io_status = response_item(0, output, output_length);
    JS_DeleteGCRef(ctx, &result);
    JS_DeleteGCRef(ctx, &stringify);
    JS_DeleteGCRef(ctx, &parsed);
    JS_FreeContext(ctx);
    /* Avoid retaining previous hidden input or program state in the arena. */
    memset(arena.bytes, 0, sizeof(arena.bytes));
    return io_status;
}

int main(int argc, char **argv)
{
    uint32_t source_length, count, input_length;
    char magic[4], trailing;
    int self_test = argc == 2 && !strcmp(argv[1], "--isolation-self-test");
    if (argc != 1 && !self_test)
        return preflight_failure("invalid worker arguments");

#if defined(COGGATE_ENGINE_TEST_ONLY)
    if (self_test)
        return preflight_failure("UNSANDBOXED engine test cannot test isolation");
    if (install_timers())
        return preflight_failure("engine test timer setup failed");
#elif defined(__linux__)
    if (isolate())
        return preflight_failure("Linux isolation unavailable");
    if (self_test)
        return isolation_self_test();
#else
    return preflight_failure("sandbox requires Linux");
#endif

    start_cpu = now_ns(CLOCK_PROCESS_CPUTIME_ID);
    start_wall = now_ns(CLOCK_MONOTONIC);
    if (start_cpu == UINT64_MAX || start_wall == UINT64_MAX)
        return preflight_failure("clock unavailable");
    if (read_exact(magic, 4) || memcmp(magic, "CGW1", 4) ||
        read_u32(&source_length) || !source_length || source_length > SOURCE_LIMIT ||
        read_exact(source, source_length) || read_u32(&count) ||
        !count || count > CASE_LIMIT)
        return preflight_failure("invalid request");
    source[source_length] = '\0';
    if (JS_IsBytecode((const uint8_t *)source, source_length) ||
        memchr(source, '\0', source_length))
        return preflight_failure("source text required");
    if (response_header(count))
        return 2;
    for (uint32_t i = 0; i < count; ++i) {
        if (read_u32(&input_length) || !input_length || input_length > INPUT_LIMIT ||
            read_exact(input, input_length))
            return 2;
        input[input_length] = '\0';
        if (memchr(input, '\0', input_length) ||
            execute_case(source_length, input_length))
            return 2;
        memset(input, 0, sizeof(input));
    }
    /* EOF is required so that appended frames cannot be silently ignored. */
    ssize_t extra;
    do {
        extra = read(STDIN_FILENO, &trailing, 1);
    } while (extra < 0 && errno == EINTR);
    return extra == 0 ? 0 : 2;
}
