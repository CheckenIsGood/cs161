#ifndef CHICKADEE_U_LIB_HH
#define CHICKADEE_U_LIB_HH
#include "lib.hh"
#include "x86-64.h"
#if CHICKADEE_KERNEL
#error "u-lib.hh should not be used by kernel code."
#endif

// u-lib.hh
//
//    Support code for Chickadee user-level code.


// make_syscall, access_memory, clobber_memory
//    These functions define the Chickadee system call calling convention.

__always_inline uintptr_t make_syscall(int syscallno) {
    register uintptr_t rax asm("rax") = syscallno;
    asm volatile ("syscall"
            : "+a" (rax)
            : /* all input registers are also output registers */
            : "cc", "rcx", "rdx", "rsi", "rdi", "r8", "r9", "r10", "r11");
    return rax;
}

__always_inline uintptr_t make_syscall(int syscallno, uintptr_t arg0) {
    register uintptr_t rax asm("rax") = syscallno;
    asm volatile ("syscall"
            : "+a" (rax), "+D" (arg0)
            :
            : "cc", "rcx", "rdx", "rsi", "r8", "r9", "r10", "r11");
    return rax;
}

__always_inline uintptr_t make_syscall(int syscallno, uintptr_t arg0,
                                       uintptr_t arg1) {
    register uintptr_t rax asm("rax") = syscallno;
    asm volatile ("syscall"
            : "+a" (rax), "+D" (arg0), "+S" (arg1)
            :
            : "cc", "rcx", "rdx", "r8", "r9", "r10", "r11");
    return rax;
}

__always_inline uintptr_t make_syscall(int syscallno, uintptr_t arg0,
                                       uintptr_t arg1, uintptr_t arg2) {
    register uintptr_t rax asm("rax") = syscallno;
    asm volatile ("syscall"
            : "+a" (rax), "+D" (arg0), "+S" (arg1), "+d" (arg2)
            :
            : "cc", "rcx", "r8", "r9", "r10", "r11");
    return rax;
}

__always_inline uintptr_t make_syscall(int syscallno, uintptr_t arg0,
                                       uintptr_t arg1, uintptr_t arg2,
                                       uintptr_t arg3) {
    register uintptr_t rax asm("rax") = syscallno;
    register uintptr_t r10 asm("r10") = arg3;
    asm volatile ("syscall"
            : "+a" (rax), "+D" (arg0), "+S" (arg1), "+d" (arg2), "+r" (r10)
            :
            : "cc", "rcx", "r8", "r9", "r11");
    return rax;
}

__always_inline void clobber_memory(void* ptr) {
    asm volatile ("" : "+m" (*(char*) ptr));
}

__always_inline void access_memory(const void* ptr) {
    asm volatile ("" : : "m" (*(const char*) ptr));
}


// sys_getpid
//    Return current process ID.
inline pid_t sys_getpid() {
    return make_syscall(SYSCALL_GETPID);
}

// sys_yield
//    Yield control of the CPU to the kernel. The kernel will pick another
//    process to run, if possible.
inline void sys_yield() {
    make_syscall(SYSCALL_YIELD);
}

// sys_pause()
//    A version of `sys_yield` that spins in the kernel long enough
//    for kernel timer interrupts to occur.
inline void sys_pause() {
    make_syscall(SYSCALL_PAUSE);
}

// sys_consoletype(type)
//    Set the type of console display (CONSOLE_NORMAL or CONSOLE_MEMVIEWER).
inline int sys_consoletype(int type) {
    return make_syscall(SYSCALL_CONSOLETYPE, type);
}

// sys_panic(msg)
//    Panic.
[[noreturn]] inline void sys_panic(const char* msg) {
    make_syscall(SYSCALL_PANIC, reinterpret_cast<uintptr_t>(msg));
    while (true) {
    }
}

// sys_page_alloc(addr)
//    Allocate a page of memory at address `addr`. `Addr` must be page-aligned
//    (i.e., a multiple of PAGESIZE == 4096). Return 0 on success or an error
//    code on failure, such as E_NOMEM on out of memory and E_FAULT on invalid
//    `addr`.
inline int sys_page_alloc(void* addr) {
    return make_syscall(SYSCALL_PAGE_ALLOC, reinterpret_cast<uintptr_t>(addr));
}

// sys_fork()
//    Fork the current process. On success, return the child's process ID to
//    the parent, and return 0 to the child. On failure, return E_NOMEM on out
//    of memory, E_AGAIN if the process table is full.
inline pid_t sys_fork() {
    return make_syscall(SYSCALL_FORK);
}

// sys_exit(status)
//    Exit this process. Does not return.
[[noreturn]] inline void sys_exit(int status) {
    make_syscall(SYSCALL_EXIT, status);
    assert(false);
}

// sys_msleep(msec)
//    Block for approximately `msec` milliseconds.
inline int sys_msleep(unsigned msec) {
    return make_syscall(SYSCALL_SLEEP, msec);
}

// sys_getppid()
//    Return parent process ID.
inline pid_t sys_getppid() {
    return make_syscall(SYSCALL_GETPPID);
}

// sys_waitpid(pid, status, options)
//    Wait until process `pid` exits and report its status. The status
//    is stored in `*status`, if `status != nullptr`. If `pid == 0`,
//    waits for any child. If `options == W_NOHANG`, returns immediately.
inline pid_t sys_waitpid(pid_t pid, int* status = nullptr,
                         int options = 0) {
    pid_t result = make_syscall(SYSCALL_WAITPID, pid, (uintptr_t)status, options);
    if (status) {
        asm volatile("" : "=m" (*status) : : "memory");
    }
    return result;
}

// sys_read(fd, buf, sz)
//    Read bytes from `fd` into `buf`. Read at most `sz` bytes. Return
//    the number of bytes read, which is 0 at EOF.
inline ssize_t sys_read(int fd, char* buf, size_t sz) {
    clobber_memory(buf);
    return make_syscall(SYSCALL_READ, fd,
                        reinterpret_cast<uintptr_t>(buf), sz);
}

// sys_write(fd, buf, sz)
//    Write bytes to `fd` from `buf`. Write at most `sz` bytes. Return
//    the number of bytes written.
inline ssize_t sys_write(int fd, const char* buf, size_t sz) {
    access_memory(buf);
    return make_syscall(SYSCALL_WRITE, fd,
                        reinterpret_cast<uintptr_t>(buf), sz);
}

// sys_dup2(oldfd, newfd)
//    Make `newfd` a reference to the same file structure as `oldfd`.
inline int sys_dup2(int oldfd, int newfd) {
    return make_syscall(SYSCALL_DUP2, oldfd, newfd);
}

// sys_close(fd)
//    Close `fd`.
inline int sys_close(int fd) {
    return make_syscall(SYSCALL_CLOSE, fd);
}

// sys_open(path, flags)
//    Open a new file descriptor for pathname `path`. `flags` should
//    contain at least one of `OF_READ` and `OF_WRITE`.
inline int sys_open(const char* path, int flags) {
    access_memory(path);
    return make_syscall(SYSCALL_OPEN, reinterpret_cast<uintptr_t>(path),
                        flags);
}

// sys_pipe(pfd)
//    Create a pipe.
inline int sys_pipe(int pfd[2]) {
    uintptr_t r = make_syscall(SYSCALL_PIPE);
    if (!is_error(r)) {
        pfd[0] = r;
        pfd[1] = r >> 32;
        r = 0;
    }
    return r;
}

// sys_execv(program_name, argv, argc)
//    Replace this process image with a new image running `program_name`
//    with `argc` arguments, stored in argument array `argv`. Returns
//    only on failure.
inline int sys_execv(const char* program_name, const char* const* argv,
                     size_t argc) {
    access_memory(program_name);
    access_memory(argv);
    return make_syscall(SYSCALL_EXECV,
                        reinterpret_cast<uintptr_t>(program_name),
                        reinterpret_cast<uintptr_t>(argv), argc);
}

// sys_execv(program_name, argv)
//    Replace this process image with a new image running `program_name`
//    with arguments `argv`. `argv` is a null-terminated array. Returns
//    only on failure.
inline int sys_execv(const char* program_name, const char* const* argv) {
    size_t argc = 0;
    while (argv && argv[argc] != nullptr) {
        ++argc;
    }
    return sys_execv(program_name, argv, argc);
}

// sys_unlink(pathname)
//    Remove the file named `pathname`.
inline int sys_unlink(const char* pathname) {
    access_memory(pathname);
    return make_syscall(SYSCALL_UNLINK, reinterpret_cast<uintptr_t>(pathname));
}

// sys_readdiskfile(pathname, buf, sz, off)
//    Read bytes from disk file `pathname` into `buf`. Read at most `sz`
//    bytes starting at file offset `off`. Return the number of bytes
//    read, which is 0 at EOF.
inline ssize_t sys_readdiskfile(const char* pathname,
                                char* buf, size_t sz, off_t off) {
    access_memory(pathname);
    clobber_memory(buf);
    return make_syscall(SYSCALL_READDISKFILE,
                        reinterpret_cast<uintptr_t>(pathname),
                        reinterpret_cast<uintptr_t>(buf), sz, off);
}

// sys_sync(drop)
//    Synchronize all modified buffer cache contents to disk.
//    If `drop == 1`, then additionally clear the buffer cache so that
//    future reads start from an empty cache.
//    If `drop == 2`, then assert that the process has no open files and
//    that no data blocks are referenced.
inline int sys_sync(int drop = 0) {
    return make_syscall(SYSCALL_SYNC, drop);
}

// sys_lseek(fd, offset, origin)
//    Set the current file position for `fd` to `off`, relative to
//    `origin` (one of the `LSEEK_` constants). Returns the new file
//    position (or, for `LSEEK_SIZE`, the file size).
inline ssize_t sys_lseek(int fd, off_t off, int origin) {
    return make_syscall(SYSCALL_LSEEK, fd, off, origin);
}

// sys_ftruncate(fd, len)
//    Set the size of file `fd` to `len`. If the file was previously
//    larger, the extra data is lost; if it was shorter, it is extended
//    with zero bytes.
inline int sys_ftruncate(int fd, off_t len) {
    return make_syscall(SYSCALL_FTRUNCATE, fd, len);
}

// sys_rename(oldpath, newpath)
//    Rename the file with name `oldpath` to `newpath`.
inline int sys_rename(const char* oldpath, const char* newpath) {
    access_memory(oldpath);
    access_memory(newpath);
    return make_syscall(SYSCALL_RENAME, reinterpret_cast<uintptr_t>(oldpath),
                        reinterpret_cast<uintptr_t>(newpath));
}

// sys_gettid()
//    Return the current thread ID.
inline pid_t sys_gettid() {
    return make_syscall(SYSCALL_GETTID);
}

// sys_nasty()
//    Breaks kernel by overallocating
[[noreturn]] inline void sys_nasty() {
    make_syscall(SYSCALL_NASTY);
    assert(false);
}

// sys_testbuddy()
//    Tests buddy allocation
inline int sys_testbuddy() {
    make_syscall(SYSCALL_TESTBUDDY);
    return 1;
}

inline int sys_vga_test() {
    make_syscall(SYSCALL_VGA_TEST);
    return 1;
}

inline int sys_display(int fd) {
    make_syscall(SYSCALL_DISPLAY);
    return 1;
}

// sys_clone(function, arg, stack_top)
//    Create a new thread running `function` with `arg`, starting at
//    stack address `stack_top`. Returns the new thread's thread ID.
//
//    In the context of the new thread, when the `function` returns,
//    the thread should call `sys_texit`.
//
//    We recommend you implement `sys_clone` in `u-lib.cc`, not this
//    header file.
pid_t sys_clone(void (*function)(void*), void* arg, char* stack_top);
// {

    
// }

// sys_texit()
//    Exit the current thread. If this is the last thread in a process,
//    then exit the process with status 0.
[[noreturn]] inline void sys_texit() {
    make_syscall(SYSCALL_TEXIT);
    assert(false);
}

// sys_getusage(usage* u)
//     Updates the given usage object by setting u->time to the current
//     value of ticks, settingu->free_pages to the number of allocatable 
//     pages that remain free, set u->allocated_pages to the number of 
//     allocatable pages that have been allocated so far; and return 0

inline int sys_getusage(usage* u) 
{
    return make_syscall(SYSCALL_GETUSAGE, reinterpret_cast<uintptr_t>(u));
}



// dprintf(fd, format, ...)
//    Construct a string from `format` and pass it to `sys_write(fd)`.
//    Returns the number of characters printed, or E_2BIG if the string
//    could not be constructed.
int dprintf(int fd, const char* format, ...);

// printf(format, ...)
//    Like `dprintf(1, format, ...)`.
int printf(const char* format, ...);

#endif
