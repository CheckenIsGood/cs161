#define CHICKADEE_OPTIONAL_PROCESS 1
#include "u-lib.hh"
#include <atomic>

extern uint8_t end[];

pid_t my_pid;
std::atomic_flag message_lock;
std::atomic<int> phase = 0;
int pfd[2] = {-1, -1};
const char* gstring;
int gints[10];
bool waitpid_blocking = false;

static void message(const char* x) {
    while (message_lock.test_and_set()) {
        pause();
    }
    int tid = sys_gettid();
    int pid = sys_getpid();
    assert(tid > 0 && pid > 0);
    console_printf("T%d (P%d): %s\n", tid, pid, x);
    message_lock.clear();
}

static char* allocate_stack(size_t thread_index) {
    size_t offset = (thread_index + 16) * PAGESIZE;
    char* stk = reinterpret_cast<char*>(
        round_up(reinterpret_cast<uintptr_t>(end), PAGESIZE) + offset
    );
    int r = sys_page_alloc(stk);
    assert_eq(r, 0);
    return stk + PAGESIZE;  // return top of stack
}

static pid_t try_waitpid(pid_t pid, int* status_ptr) {
    size_t tries = 0;
    size_t max_tries = waitpid_blocking ? 10 : 1000;
    int wflags = waitpid_blocking ? 0 : W_NOHANG;
    int r;
    while ((r = sys_waitpid(pid, status_ptr, wflags)) == E_AGAIN
           && tries < max_tries) {
        ++tries;
        sys_yield();
    }
    return r;
}


// basic: test that threads share an address space

static void basic_thr(void* x) {
    message("starting basic_thr");
    assert_eq(sys_getpid(), my_pid);

    // wait for phase 1
    while (phase != 1) {
        sys_yield();
    }
    assert_memeq(gstring, "Message to secondary\n", 17);

    // enter phase 2
    message("sending to primary");
    gstring = "Message to primary\n";
    phase = 2;

    // wait for phase 3
    while (phase != 3) {
        sys_yield();
    }

    // read from pipe, write to pipe
    char buf[100];
    memset(buf, 0, sizeof(buf));
    ssize_t n = sys_read(pfd[0], buf, sizeof(buf));
    assert_eq(n, 2);
    assert_memeq(buf, "Yo", 2);

    phase = 4;
    message("piping to main");
    n = sys_write(pfd[1], "Hi", 2);
    assert_eq(n, 2);

    sys_texit();
}

static void basic_exiter(void*) {
    // checks that nothing goes badly wrong when a thread function
    // returns instead of calling `sys_texit`
}

[[noreturn]] static void basic() {
    my_pid = sys_getpid();

    // create thread
    message("clone");
    char* tstack = allocate_stack(0);
    pid_t t = sys_clone(basic_thr, pfd, tstack);
    assert_gt(t, 0);
    assert_ne(t, my_pid);

    // enter phase 1, prepare message to child
    message("sending to secondary (basic_thr)");
    gstring = "Message to secondary\n";
    phase = 1;

    // wait for phase 2
    while (phase != 2) {
        sys_yield();
    }
    assert_memeq(gstring, "Message to primary\n", 18);

    // enter phase 3, create pipe
    message("piping to secondary");
    int r = sys_pipe(pfd);
    assert_eq(r, 0);
    assert(pfd[0] > 2 && pfd[1] > 2);
    assert(pfd[0] != pfd[1]);
    phase = 3;

    r = sys_write(pfd[1], "Yo", 2);

    // enter phase 4
    while (phase != 4) {
        sys_yield();
    }
    char buf[100];
    memset(buf, 0, sizeof(buf));
    r = sys_read(pfd[0], buf, sizeof(buf));
    assert_eq(r, 2);
    assert_memeq(buf, "Hi", 2);

    // wait for thread to exit
    sys_msleep(10);
    message(CS_GREEN "simple thread tests succeeded!");

    // start a new thread to check thread returning doesn't go wrong
    message("checking automated texit");
    t = sys_clone(basic_exiter, pfd, tstack);
    assert_gt(t, 0);
    sys_msleep(10);

    sys_exit(0);
}


// exit_all: check that `exit` exits all threads, even threads blocked in
// `read`

static void exit_all_thr(void*) {
    // this blocks forever
    char buf[20];
    (void) sys_read(pfd[0], buf, sizeof(buf));
    assert(false);
}

[[noreturn]] static void exit_all() {
    message("checking that exit exits blocked threads");

    // create thread
    pid_t t = sys_clone(exit_all_thr, nullptr, allocate_stack(0));
    assert_gt(t, 0);

    // this should quit the other threads too
    sys_exit(161);
}


// implicit_exit: check that the last thread to `texit` exits the process

static void implicit_exit_thr(void*) {
    sys_msleep(10);
}

[[noreturn]] static void implicit_exit() {
    message("checking implicit exit via texit");

    // create thread
    pid_t t = sys_clone(implicit_exit_thr, nullptr, allocate_stack(0));
    assert_gt(t, 0);

    // this exits the main thread, but `implicit_exit_thr` continues;
    // the eventual exit status should be `implicit_exit_thr`'s
    sys_texit();
}


// many_threads: check that we can create at least 500 threads

static void many_threads_thr(void*) {
    assert_eq(sys_getpid(), my_pid);
    sys_yield();
}

[[noreturn]] static void many_threads() {
    my_pid = sys_getpid();
    message("checking creation of 500 threads");

    char* stk = allocate_stack(0);
    for (int i = 0; i != 100; ++i) {
        if (i != 0) {
            sys_msleep(3);
        }
        for (int j = 0; j != 5; ++j) {
            pid_t t = sys_clone(many_threads_thr, nullptr, stk - j * 128);
            assert_gt(t, 0);
            assert_ne(t, my_pid);
        }
    }
    sys_exit(0);
}


// many_threads_series: check that we can create at least 500 threads
// in series

static void many_threads_series_thr(void*) {
    assert_eq(sys_getpid(), my_pid);
    int my_phase = ++phase;
    sys_yield();
    if (my_phase % 5 == 0 && my_phase != 500) {
        for (int i = 0; i != 5; ++i) {
            char* stk = reinterpret_cast<char*>(round_up(rdrsp(), PAGESIZE));
            pid_t t = sys_clone(many_threads_series_thr, nullptr,
                                stk - ((my_phase + i) % 32) * 128);
            assert_gt(t, 0);
            assert_ne(t, my_pid);
        }
    }
}

[[noreturn]] static void many_threads_series() {
    my_pid = sys_getpid();
    message("checking creation of 500 threads in series");

    char* stk = allocate_stack(0);
    phase = 0;
    for (int i = 0; i != 5; ++i) {
        pid_t t = sys_clone(many_threads_series_thr, nullptr, stk - i * 128);
        assert_gt(t, 0);
        assert_ne(t, my_pid);
    }
    while (phase < 500) {
        sys_msleep(3);
    }
    sys_exit(phase);
}


// waitpid_primary: check that `waitpid` in primary can collect children
// from secondary

static void waitpid_forker_thr(void* arg) {
    uintptr_t tindex = reinterpret_cast<uintptr_t>(arg);

    pid_t hp = sys_fork();
    assert_ge(hp, 0);
    if (hp == 0) {
        sys_msleep(1);
        sys_exit(161 + tindex);
    }
    gints[tindex] = hp;
    ++phase;

    sys_texit();
}

[[noreturn]] static void waitpid_primary() {
    message("checking that `waitpid` works at primary thread");

    // create threads
    phase = 0;
    pid_t t1 = sys_clone(waitpid_forker_thr, reinterpret_cast<void*>(0UL),
                         allocate_stack(0));
    assert_gt(t1, 0);
    pid_t t2 = sys_clone(waitpid_forker_thr, reinterpret_cast<void*>(1UL),
                         allocate_stack(1));
    assert_gt(t2, 0);

    pid_t hp = sys_fork();
    assert_ge(hp, 0);
    if (hp == 0) {
        sys_msleep(1);
        sys_exit(163);
    }
    gints[2] = hp;

    // reap all children (one from primary, one from each secondary)
    while (phase != 2) {
        sys_yield();
    }

    for (int i = 0; i != 3; ++i) {
        int status = 0;
        pid_t r = try_waitpid(0, &status);
        assert_gt(r, 0);
        assert_ge(status, 161);
        assert_le(status, 163);
        assert_eq(r, gints[status - 161]);
        gints[status - 161] = 0;
    }

    sys_exit(0);
}


// waitpid_secondary: check that `waitpid` works across threads (nonblocking)

static void waitpid_forker_thr1(void*) {
    // phase 1: wait for process spawned by primary thread
    while (phase != 1) {
        sys_yield();
    }

    pid_t hp = gints[0];
    int status = 0;
    pid_t r = try_waitpid(hp, &status);
    assert_gt(r, 0);
    assert_eq(r, hp);
    assert_eq(status, 161);

    // phase 2: spawn a process to be reaped by thr2, then texit
    hp = sys_fork();
    assert_ge(hp, 0);
    if (hp == 0) {
        sys_exit(162);
    }
    gints[0] = hp;
    phase = 2;

    sys_texit();
}

static void waitpid_forker_thr2(void*) {
    // phase 2: wait for process spawned by waitpid_forker_thr1
    while (phase != 2) {
        sys_yield();
    }

    pid_t hp = gints[0];
    int status = 0;
    pid_t r = try_waitpid(0, &status);
    assert_gt(r, 0);
    assert_eq(r, hp);
    assert_eq(status, 162);

    // phase 3: spawn a process to be reaped by primary
    hp = sys_fork();
    assert_ge(hp, 0);
    if (hp == 0) {
        sys_exit(163);
    }
    gints[0] = hp;
    phase = 3;

    // phase 4: wait forever
    while (true) {
        sys_yield();
    }
}

[[noreturn]] static void waitpid_full() {
    if (waitpid_blocking) {
        message("checking that blocking `waitpid` works across threads");
    } else {
        message("checking that `waitpid` works across threads");
    }

    // create threads
    phase = 0;
    pid_t t1 = sys_clone(waitpid_forker_thr1, nullptr, allocate_stack(0));
    assert_gt(t1, 0);
    pid_t t2 = sys_clone(waitpid_forker_thr2, nullptr, allocate_stack(1));
    assert_gt(t2, 0);

    // phase 1: create a helper process in primary thread
    pid_t hp = sys_fork();
    assert_ge(hp, 0);
    if (hp == 0) {
        sys_exit(161);
    }
    gints[0] = hp;
    phase = 1;

    // phase 3: reap process spawned by waitpid_forker_thr2 then exit
    while (phase != 3) {
        sys_yield();
    }

    hp = gints[0];
    int status = 0;
    pid_t r = try_waitpid(hp, &status);
    assert_gt(r, 0);
    assert_eq(r, hp);
    assert_eq(status, 163);

    sys_exit(0);
}


void process_main() {
    // basic tests
    pid_t p = sys_fork();
    assert_ge(p, 0);
    if (p == 0) {
        basic();
    }
    pid_t ch = sys_waitpid(p);
    assert_eq(ch, p);


    // exit_all tests
    int r = sys_pipe(pfd);
    assert_eq(r, 0);
    p = sys_fork();
    assert_ge(p, 0);
    if (p == 0) {
        exit_all();
    }
    int status = 0;
    ch = sys_waitpid(p, &status);
    assert_eq(ch, p);
    assert_eq(status, 161);

    // check that `exit_all_thr` really exited; if it did not, then
    // the read end of the pipe will still be open (because `exit_all_thr`
    // has the write end open)
    sys_close(pfd[1]);
    char buf[20];
    ssize_t n = sys_read(pfd[0], buf, sizeof(buf));
    assert_eq(n, 0);


    // implicit_exit tests
    p = sys_fork();
    assert_ge(p, 0);
    if (p == 0) {
        implicit_exit();
    }
    status = 0;
    ch = sys_waitpid(p, &status);
    assert_eq(ch, p);
    assert_eq(status, 0);


    // many_threads tests
    p = sys_fork();
    assert_ge(p, 0);
    if (p == 0) {
        many_threads();
    }
    status = 0;
    ch = sys_waitpid(p, &status);
    assert_eq(ch, p);
    assert_eq(status, 0);

    p = sys_fork();
    assert_ge(p, 0);
    if (p == 0) {
        many_threads_series();
    }
    status = 0;
    ch = sys_waitpid(p, &status);
    assert_eq(ch, p);
    assert_eq(status, 500);


    // waitpid_primary tests
    p = sys_fork();
    assert_ge(p, 0);
    if (p == 0) {
        waitpid_primary();
    }
    status = 0;
    ch = sys_waitpid(p, &status);
    assert_eq(ch, p);
    assert_eq(status, 0);


    // waitpid_full tests
    p = sys_fork();
    assert_ge(p, 0);
    if (p == 0) {
        waitpid_full();
    }
    status = 0;
    ch = sys_waitpid(p, &status);
    assert_eq(ch, p);
    assert_eq(status, 0);


    // waitpid_full_blocking tests
    p = sys_fork();
    assert_ge(p, 0);
    if (p == 0) {
        waitpid_blocking = true;
        waitpid_full();
    }
    status = 0;
    ch = sys_waitpid(p, &status);
    assert_eq(ch, p);
    assert_eq(status, 0);


    console_printf(CS_SUCCESS "testthread succeeded!\n");
    sys_exit(0);
}
