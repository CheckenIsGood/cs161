#define CHICKADEE_OPTIONAL_PROCESS 1
#include "u-lib.hh"

void process_main() {
    // Your code here!
    // Running `testkalloc` should cause the kernel to run buddy allocator
    // tests. How you make this work is up to you.
    
    // This stress tests my fork -> I allocate shit ton of memory in my testbuddy so sys_fork
    // fails sometimes (not enough memory) but the while loop keeps running fork until
    // that memory is freed and fork succeeds. This is not the best design but I'm literally
    // losing my mind someone please help me.

    while (sys_fork() < 0);
    while (sys_fork() < 0);

    pid_t p = sys_getpid();
    srand(p);

    sys_testbuddy();

    // Why is console_printf not atomic????? Literally took me FIVE HOURS TO FIND WHY
    // console_printf(CS_SUCCESS "kalloc succeeded!\n");

    // This test runs before `sys_exit` is implemented, so we can’t use it.
    while (true) {
    }
}
