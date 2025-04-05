#include "kernel.hh"
#include "k-ahci.hh"
#include "k-apic.hh"
#include "k-chkfs.hh"
#include "k-chkfsiter.hh"
#include "k-devices.hh"
#include "k-vmiter.hh"
#include "obj/k-firstprocess.h"

// kernel.cc
//
//    This is the kernel.


// # timer interrupts so far on CPU 0
std::atomic<unsigned long> ticks;
proc* init = nullptr;
spinlock print;
constexpr size_t TIMER_WHEEL_SIZE = 10;
wait_queue timer_wheel[TIMER_WHEEL_SIZE];
spinlock family_lock;
file_descriptor* global_fd_table[32] = {nullptr};
spinlock global_fd_table_lock;
extern spinlock initfs_lock_;

static void tick();
static void start_initial_process(pid_t pid, const char* program_name);

void init_process()
{
    sti();
    while (init->syscall_waitpid(init, 0, nullptr, W_NOHANG) != E_CHILD)
    {
        init->yield();
    }
    process_halt();
}

struct nasty
{
    void init()
    {
        volatile char nastier[PAGESIZE];
        for (size_t i = 0; i < sizeof(nastier)/sizeof(char); ++i) {
            nastier[i] = 0x9;
        }
    }
};

// kernel_start(command)
//    Initialize the hardware and processes and start running. The `command`
//    string is an optional string passed from the boot loader.

void kernel_start(const char* command) {
    init_hardware();
    consoletype = CONSOLE_NORMAL;
    console_clear();

    // set up process descriptors
    for (pid_t i = 0; i < NPROC; i++) {
        ptable[i] = nullptr;
    }

    init = knew<proc>();
    assert(init);
    init->init_kernel(init_process);
    init->ppid_ = 1;
    init->id_ = 1;
    {
        spinlock_guard guard(ptable_lock);
        assert(!ptable[1]);
        ptable[1] = init;
    }
    cpus[0].enqueue(init);

    // start first process
    start_initial_process(2, CHICKADEE_FIRST_PROCESS);

    // start running processes
    cpus[0].schedule();
}


// start_initial_process(pid, name)
//    Load application program `name` as process number `pid`.
//    This loads the application's code and data into memory, sets its
//    %rip and %rsp, gives it a stack page, and marks it as runnable.
//    Only called at initial boot time.

void start_initial_process(pid_t pid, const char* name) {
    // look up process image in initfs
    auto irqs = initfs_lock_.lock();
    int mindex = memfile::initfs_lookup(name, memfile::required);
    x86_64_pagetable* pt = knew_pagetable();
    assert(mindex >= 0 && pt);

    // load code and data into pagetable
    memfile_loader ld(mindex, pt);
    int r = proc::load(ld);
    initfs_lock_.unlock(irqs);
    assert(r >= 0);

    // allocate process, initialize registers
    proc* p = knew<proc>();
    p->id_ = pid;
    p->ppid_ = 1;
    init->children_.push_back(p);
    p->init_user(pt);
    p->regs_->reg_rip = ld.entry_rip_;

    {    
        spinlock_guard guard(global_fd_table_lock);
        global_fd_table[0] = knew<file_descriptor>();
        global_fd_table[0]->readable = true;
        global_fd_table[0]->writable = true;
        global_fd_table[0]->vnode_ = knew<vnode_kbd_cons>();
        global_fd_table[0]->vnode_->vn_refcount++;

        spinlock_guard guard2(p->fd_table_lock);

        // initialize stdin, stdout, stderr of init process
        for (int i = 0; i < 3; i++) 
        {
            p->fd_table_[i] = global_fd_table[0];
            global_fd_table[0]->ref++;
        }
    }

    // initialize stack
    void* stkpg = kalloc(PAGESIZE);
    assert(stkpg);
    vmiter(p, MEMSIZE_VIRTUAL - PAGESIZE).map(stkpg, PTE_PWU);
    p->regs_->reg_rsp = MEMSIZE_VIRTUAL;

    // map console
    vmiter(p, ktext2pa(console)).map(console, PTE_PWU);

    // add to process table (requires lock in case another CPU is already
    // running processes)
    {
        spinlock_guard guard(ptable_lock);
        assert(!ptable[pid]);
        ptable[pid] = p;
    }

    // add to run queue
    cpus[pid % ncpu].enqueue(p);
}

// free_process(process)
//    frees all the memory of a given process
void free_process(proc* proc) 
{
    pid_t pid = proc->id_;
    assert(proc);
    assert(ptable[pid]->pagetable_);

    // free the memory of the process
    for (vmiter it(proc->pagetable_, 0); it.low(); it.next()) 
    {
        if (it.user() && it.pa() != CONSOLE_ADDR)
        {
            it.kfree_page();
        }
    }

    // free the process page table
    for (ptiter it(proc->pagetable_); it.low(); it.next())
    {
        it.kfree_ptp();
    }

    // ensures that the top pagetable is freed
    kfree(proc->pagetable_);

    // free the process itself and ptable
    kfree(proc);
    ptable[pid] = nullptr;
}

void free_ptable(x86_64_pagetable* pagetable)
{
    for(ptiter it(pagetable); it.low(); it.next()) 
    {
        it.kfree_ptp();
    }
    kfree(pagetable);
}


// proc::exception(reg)
//    Exception handler (for interrupts, traps, and faults).
//
//    The register values from exception time are stored in `reg`.
//    The processor responds to an exception by saving application state on
//    the current CPU stack, then jumping to kernel assembly code (in
//    k-exception.S). That code transfers the state to the current kernel
//    task's stack, then calls proc::exception().

void proc::exception(regstate* regs) {
    // It can be useful to log events using `log_printf`.
    // Events logged this way are stored in the host's `log.txt` file.
    //log_printf("proc %d: exception %d @%p\n", id_, regs->reg_intno, regs->reg_rip);

    // Record most recent user-mode %rip.
    if ((regs->reg_cs & 3) != 0) {
        recent_user_rip_ = regs->reg_rip;
    }

    // Show the current cursor location.
    consolestate::get().cursor();


    // Actually handle the exception.
    switch (regs->reg_intno) {

    case INT_IRQ + IRQ_TIMER: 
    {
        cpustate* cpu = this_cpu();
        if (cpu->cpuindex_ == 0) 
        {
            tick();
        }
        lapicstate::get().ack();
        regs_ = regs;
        yield_noreturn();
        break;                  /* will not be reached */
    }

    case INT_PF: {              // pagefault exception
        // Analyze faulting address and access type.
        uintptr_t addr = rdcr2();
        const char* operation = regs->reg_errcode & PFERR_WRITE
                ? "write" : "read";
        const char* problem = regs->reg_errcode & PFERR_PRESENT
                ? "protection problem" : "missing page";

        if ((regs->reg_cs & 3) == 0) {
            panic_at(*regs, "Kernel page fault for %p (%s %s)!\n",
                     addr, operation, problem);
        }

        error_printf(CS_ERROR "Process %d page fault for %p (%s %s, rip=%p)!\n",
                     id_, addr, operation, problem, regs->reg_rip);
        pstate_ = proc::ps_faulted;
        yield();
        break;
    }

    case INT_IRQ + IRQ_KEYBOARD:
        keyboardstate::get().handle_interrupt();
        break;

    default:
        if (sata_disk && regs->reg_intno == INT_IRQ + sata_disk->irq_) {
            sata_disk->handle_interrupt();
        } else {
            panic_at(*regs, "Unexpected exception %d!\n", regs->reg_intno);
        }
        break;                  /* will not be reached */

    }

    // return to interrupted context
}

uintptr_t syscall_unchecked(regstate* regs, proc* p) {
    //log_printf("proc %d: syscall %ld @%p\n", id_, regs->reg_rax, regs->reg_rip);

    p->recent_user_rip_ = regs->reg_rip;
    switch (regs->reg_rax) {

    case SYSCALL_CONSOLETYPE:
        if (consoletype != (int) regs->reg_rdi) {
            console_clear();
        }
        consoletype = regs->reg_rdi;
        return 0;

    case SYSCALL_PANIC:
        panic_at(*regs, "process %d called sys_panic()", p->id_);
        break;                  // will not be reached

    case SYSCALL_KTEST:
        if (regs->reg_rdi == 1) {
            return ktest_wait_queues();
        }
        return -1;

    case SYSCALL_GETPID:
        return p->id_;

    case SYSCALL_YIELD:
        p->yield();
        return 0;

    case SYSCALL_PAGE_ALLOC: {
        uintptr_t addr = regs->reg_rdi;
        if (addr >= VA_LOWEND || addr & 0xFFF) {
            return -1;
        }
        void* pg = kalloc(PAGESIZE);
        if (!pg || vmiter(p, addr).try_map(ka2pa(pg), PTE_PWU) < 0) {
            return -1;
        }
        return 0;
    }

    case SYSCALL_PAUSE: {
        sti();
        for (uintptr_t delay = 0; delay < 1000000; ++delay) {
            pause();
        }
        return 0;
    }

    case SYSCALL_EXIT:
    {
        {
            spinlock_guard guard(ptable_lock);
            {
                auto irqs = p->fd_table_lock.lock();
                for(int fd = 0; fd < NUM_FD; fd++) 
                {
                    if (p->fd_table_[fd])
                    {
                        p->fd_table_lock.unlock(irqs);
                        p->syscall_close(fd);
                        irqs = p->fd_table_lock.lock();
                    }
                }
                p->fd_table_lock.unlock(irqs);
            }

            // set process state to zombie
            p->pstate_ = proc::ps_zombie;
            {
                // reparent the children in O(C) time
                spinlock_guard guard2(family_lock); 
                proc* child = p->children_.pop_back();
                while (child) 
                {
                    child->ppid_ = 1;
                    init->children_.push_back(child);
                    child = p->children_.pop_back();
                }
            }
            p->status_ = (int) regs->reg_rdi;

            // clean up
            for (vmiter it(p->pagetable_, 0); it.low(); it.next())
            {
                if (it.user() && it.pa() != CONSOLE_ADDR)
                {
                    it.kfree_page();
                }
            }
                
            for (ptiter it(p->pagetable_); it.low(); it.next())
            {
                it.kfree_ptp();
            }

            set_pagetable(early_pagetable);
            delete p->pagetable_;
            p->pagetable_ = nullptr;


            spinlock_guard guard2(family_lock); 
            proc* parent = ptable[p->ppid_];
            assert(parent);
            parent->interrupt_ = true;
            parent->waitq_.notify_all();
        }
        p->yield_noreturn();
    }

    case SYSCALL_SLEEP:
    {
        unsigned long time = ticks + round_up((unsigned) regs->reg_rdi, 10)/10;
        waiter w;
        p->interrupt_ = false;

        // block until time is up or interrupted
        w.wait_until(timer_wheel[time % TIMER_WHEEL_SIZE], [&] () {
            return (long(time - ticks) <= 0 || p->interrupt_);
        });

        // Child exits so parent should return E_INTR
        if (p->interrupt_) 
        {
            p->interrupt_ = false;
            return E_INTR;
        }
        return 0;
    }

    case SYSCALL_FORK:
        return p->syscall_fork(regs);

    case SYSCALL_READ:
        return p->syscall_read(regs);

    case SYSCALL_WRITE:
        return p->syscall_write(regs);

    case SYSCALL_GETUSAGE:
        return p->syscall_getusage(regs);

    case SYSCALL_READDISKFILE:
        return p->syscall_readdiskfile(regs);

    case SYSCALL_SYNC: {
        int drop = regs->reg_rdi;
        // `drop > 1` asserts that no data blocks are referenced (except
        // possibly superblock and FBB blocks). This can only be ensured on
        // tests that run as the first process.
        if (drop > 1 && strncmp(CHICKADEE_FIRST_PROCESS, "test", 4) != 0) {
            drop = 1;
        }
        return bufcache::get().sync(drop);
    }

    case SYSCALL_EXECV:
    {
        const char* pathname = (const char*) regs->reg_rdi;
        const char* const* argv = (const char* const*) regs->reg_rsi;
        int argc = (int) regs->reg_rdx;
        return p->syscall_execv(pathname, argv, argc);
    }

    case SYSCALL_NASTY: 
    {
        nasty leak;
        leak.init();
        return 0;
    }

    case SYSCALL_TESTBUDDY:
    {
        p->syscall_testbuddy(regs);
        return 0;
    }

    case SYSCALL_GETPPID:
    {
        spinlock_guard guard2(family_lock);
        return p->ppid_;
    }

    case SYSCALL_WAITPID:
    {
        pid_t pid = (pid_t) regs->reg_rdi;
        int* status = reinterpret_cast<int*>(regs->reg_rsi);
        int options = (int) regs->reg_rdx;
        return p->syscall_waitpid(p, pid, status, options);
    }

    case SYSCALL_DUP2: 
    {
        return p->syscall_dup2(regs->reg_rdi, regs->reg_rsi);
    }
 
    case SYSCALL_CLOSE: 
    {
        return p->syscall_close(regs->reg_rdi);
    }

    case SYSCALL_PIPE: 
    {
        return p->syscall_pipe();
    }

    case SYSCALL_OPEN: 
    {
        const char* pathname = (const char*) regs->reg_rdi;
        int flags = (int) regs->reg_rsi;
        return p->syscall_open(pathname, flags);
    }

    default:
        // no such system call
        log_printf("%d: no such system call %u\n", p->id_, regs->reg_rax);
        return E_NOSYS;

    }
}

// proc::syscall(regs)
//    System call handler.
//
//    The register values from system call time are stored in `regs`.
//    The return value from `proc::syscall()` is returned to the user
//    process in `%rax`.

uintptr_t proc::syscall(regstate* regs)
{
    uintptr_t val = syscall_unchecked(regs, this);
    if (is_cli() && this_cpu())
    {
        if (this_cpu()->canary != CANARY)
        {
            panic("proc %d: CPU stack canary overwritten", id_);
        }
    }
    if (canary != CANARY)
    {
        panic("proc %d: stack canary overwritten", id_);
    }
    return val;
}

void proc::syscall_testbuddy(regstate* reg)
{
    // Basic test to test kalloc and kfree
    void* kalloced[50];
    for (int i = 0; i < 10; ++i) 
    {
        kalloced[i] = kalloc(PAGESIZE);
    }

    for (int i = 0; i < 10; ++i) 
    {
        kfree(kalloced[i]);
    }

    // Check if large allocations beyond 2MB fail
    size_t large_test = SIZE_MAX;
    void* tested = kalloc(large_test);
    assert(tested == nullptr);

    // Check that large allocations (less than 2MB) go through and we can kfree without problem
    large_test = (1 << 20) - 1;
    tested = kalloc(large_test);
    kfree(tested);
    tested = kalloc(large_test);
    kfree(tested);

    // Testing with random kalloc sizes to make sure kalloc and kfree work
    uint64_t random;
    for (int i = 0; i < 10; ++i) 
    {
        random = rand(1 << 12, 1 << 18);
        kalloced[i] = kalloc(random);
    }

    for (int i = 0; i < 10; ++i) 
    {
        kfree(kalloced[i]);
    }

    // Stress testing
    // NOTE: t
    for (int i = 0; i < 50; ++i) 
    {
        kalloced[i] = kalloc(PAGESIZE);
    }

    for (int i = 0; i < 50; ++i) 
    {
        kfree(kalloced[i]);
    }

    // Interspersed kallocs and kfrees
    for (int i = 0; i < 10; ++i)
    {
        random = rand(1 << 12, 1 << 18);
        kalloced[i] = kalloc(random);
    }
    for (int i = 5; i < 10; ++i)
    {
        kfree(kalloced[i]);
    }
    for (int i = 10; i < 15; ++i)
    {
        random = rand(1 << 12, 1 << 18);
        kalloced[i] = kalloc(random);
    }
    for (int i = 0; i < 5; ++i)
    {
        kfree(kalloced[i]);
    }
    for (int i = 10; i < 15; ++i)
    {
        kfree(kalloced[i]);
    }
    // log_printf("kalloc succeeded!\n");
    
    auto irqs = print.lock();
    console_printf(CS_SUCCESS "kalloc succeeded!\n");
    print.unlock(irqs);
    return;
}

int proc::syscall_getusage(regstate* regs) 
{
    auto j = vmiter(ptable[id_], regs->reg_rdi);
    if (!j.writable() || !j.user() || (regs->reg_rdi % alignof(usage) != 0))
    {
        return E_FAULT;
    }
    usage* u = reinterpret_cast<usage*>(regs->reg_rdi);
    u->time = ticks;
    u->free_pages = kalloc_free_pages();
    u->allocated_pages = kalloc_allocated_pages();
    return 0;
}

// proc::syscall_fork(regs)
//    Handle fork system call.

pid_t proc::syscall_fork(regstate* regs) {

    spinlock_guard guard(ptable_lock);
    pid_t child_pid = 0;

    // find free process slot
    for (pid_t i = 1; i < NPROC; i++)
    {
        if (!ptable[i])
        {
            child_pid = i;
            ptable[child_pid] = knew<proc>();
            if (!ptable[child_pid])
            {
                return E_NOMEM;
            }
            ptable[child_pid]->id_ = child_pid;
            break;
        }
    }

    // if no free process slot found, return -1
    if (child_pid == 0)
    {
        return E_AGAIN;
    }

    ptable[child_pid]->pagetable_ = knew_pagetable();

    // check if kalloc_pagetable failed
    if(!ptable[child_pid]->pagetable_)
    {
        delete ptable[child_pid];
        ptable[child_pid] = nullptr;
        return E_NOMEM;
    }

    ptable[child_pid]->init_user(ptable[child_pid]->pagetable_);
    memcpy(reinterpret_cast<void*>(ptable[child_pid]->regs_), reinterpret_cast<void*>(regs), sizeof(regstate));

    for (vmiter it(ptable[id_], 0); it.va() < MEMSIZE_VIRTUAL; it += PAGESIZE) 
    {
        // check if pages are user-accessible
        if (it.user() && it.va() != CONSOLE_ADDR)
        {
            // check if pages are not writable and share pages if they are
            if (!it.writable())
            {
                int r = vmiter(ptable[child_pid]->pagetable_, it.va()).try_map(it.pa(), it.perm());

                // check if mapping fails
                if (r)
                {
                    free_process(ptable[child_pid]);
                    return E_NOMEM;
                }
            }
            else
            {
                void* pa = kalloc(PAGESIZE);

                // check if kalloc fails
                if (pa)
                {
                    memcpy((void*) pa, (void*) pa2ka(it.pa()), PAGESIZE);
                    unsigned long perm = it.perm();
                    int r = vmiter(ptable[child_pid]->pagetable_, it.va()).try_map(pa, perm);

                    // check if mapping fails
                    if (r)
                    {
                        kfree(pa);
                        free_process(ptable[child_pid]);
                        return E_NOMEM;
                    }
                }

                // if kalloc fails, then free all allocated memory and return -1
                else
                {
                    free_process(ptable[child_pid]);
                    return E_NOMEM;
                }
            }
        }
        else
        {
            int r = vmiter(ptable[child_pid]->pagetable_, it.va()).try_map(it.va(), it.perm());

            // check if mapping fails
            if (r)
            {
                free_process(ptable[child_pid]);
                return E_NOMEM;
            }
        }
    }

    {
        spinlock_guard table_guard(fd_table_lock);    
        for (int i = 0; i < NUM_FD; i++)
        {
            if (fd_table_[i])
            {
                spinlock_guard guard2(fd_table_[i]->file_descriptor_lock);
                ptable[child_pid]->fd_table_[i] = fd_table_[i];
                ++fd_table_[i]->ref;
            }
        }
    }

    // set registers and state of child process
    ptable[child_pid]->pstate_ = PROC_RUNNABLE;
    ptable[child_pid]->regs_->reg_rax = 0;

    {
        spinlock_guard guard3(family_lock);
        ptable[child_pid]->ppid_ = id_;
        children_.push_back(ptable[child_pid]);
    }

    cpus[child_pid % ncpu].enqueue(ptable[child_pid]);
    return child_pid;
}

int proc::syscall_open(const char* pathname, int flags)
{
    if (!pathname)
    {
        return E_FAULT;
    }

    // Check if pathname is null-terminated and if it is user-accessible
    vmiter it1(this, (uintptr_t) pathname);
    bool pathname_valid = false;
    for (int i = 0; i < (int) memfile::namesize; i++) 
    {
        if(!it1.user() || it1.va() >= MEMSIZE_VIRTUAL)
        {
            return E_FAULT;
        }
        char c = *reinterpret_cast<char*>(it1.kptr());
        if (c == '\0') 
        {
            pathname_valid = true;
            break;
        }
        it1 += 1;
    }

    if (!pathname_valid)
    {
        return E_FAULT;
    }
    irqstate irqs = initfs_lock_.lock();
    int mindex = -1;

    // Lookups for the file in initfs and create if it doesn't exist
    if (flags & OF_CREATE)
    {
        mindex = memfile::initfs_lookup(pathname, memfile::create);
    }
    else
    {
        mindex = memfile::initfs_lookup(pathname, memfile::optional);
    }
    if (mindex < 0)
    {
        initfs_lock_.unlock(irqs);
        return mindex;
    }
    memfile* file = &memfile::initfs[mindex];
    initfs_lock_.unlock(irqs);

    irqs = file->lock_.lock();
    if(flags & OF_TRUNC && file->len_) 
    {
        file->set_length(0);
    }
    file->lock_.unlock(irqs);


    // Allocate file descriptor
    int fd = allocate_fd(flags & OF_READ, flags & OF_WRITE);
    if(fd < 0) {
        return fd;
    }
    file_descriptor *f = fd_table_[fd];

    // Create new vnode for file descriptor
    f->vnode_ = knew<vnode_memfile>();
    if (!f->vnode_) 
    {
        syscall_close(fd);
        return E_NOMEM;
    }

    f->vnode_->vn_refcount = 1;
    f->vnode_->data = reinterpret_cast<void*>(file);
    return fd;
}

int proc::syscall_execv(const char* pathname, const char* const* argv, int argc)
{
    {
        spinlock_guard guard(ptable_lock);
        if (!pathname || !argv || argc < 1 || argv[argc])
        {
            return E_FAULT;
        }

        // Check if pathname is null-terminated and if it is user-accessible
        vmiter it1(this, (uintptr_t) pathname);
        bool pathname_valid = false;
        for (int i = 0; i < (int) memfile::namesize; i++) 
        {
            // Check if pathname is user-accessible
            if(!it1.user() || it1.va() >= MEMSIZE_VIRTUAL)
            {
                return E_FAULT;
            }
            char c = *reinterpret_cast<char*>(it1.kptr());
            if (c == '\0') 
            {
                pathname_valid = true;
                break;
            }
            it1 += 1;
        }

        if (!pathname_valid)
        {
            return E_FAULT;
        }

        // Check if first argument is same as pathname
        if(strcmp(reinterpret_cast<const char*>(pathname), argv[0]) != 0) 
        {
            return E_FAULT;
        }


        x86_64_pagetable *pagetable = knew_pagetable();
        if(!pagetable) 
        {
            return E_NOMEM;
        }

        // Look up the process image in initfs
        auto irqs = initfs_lock_.lock();
        int mindex = memfile::initfs_lookup(reinterpret_cast<const char*>(pathname), memfile::optional);
        if (mindex < 0) 
        {
            free_ptable(pagetable);
            initfs_lock_.unlock(irqs);
            return E_NOENT;
        }

        memfile_loader ld(mindex, pagetable);

        // Load process image
        int r = proc::load(ld);
        initfs_lock_.unlock(irqs);

        if (r < 0)
        {
            free_ptable(pagetable);
            return r;
        }

        size_t args_sz = 0;

        // it would be prudent to cap args_sz in the future
        for (int i = 0; i < argc; i++) 
        {
            args_sz += strlen(argv[i]) + 1;
        }

        size_t argv_sv = sizeof(const char* const) * (argc + 1);
        size_t total_sz = args_sz + argv_sv;
        size_t stack_sz = round_up(total_sz, PAGESIZE) + PAGESIZE;

        // allocate stack page
        void* stkpg = kalloc(stack_sz);
        if (!stkpg)
        {
            free_ptable(pagetable);
            return E_NOMEM;
        }

        // map stack page and console
        int r2 = vmiter(pagetable, MEMSIZE_VIRTUAL - PAGESIZE).try_map(stkpg, PTE_PWU);
        if (r2 < 0 || vmiter(pagetable, CONSOLE_ADDR).try_map(CONSOLE_ADDR, PTE_PWU) < 0)
        {
            kfree(stkpg);
            free_ptable(pagetable);
            return E_NOMEM;
        }

        vmiter it2(pagetable, MEMSIZE_VIRTUAL - args_sz);
        vmiter it3(pagetable, MEMSIZE_VIRTUAL - args_sz - (argc + 1) * sizeof(uintptr_t));
        memset(it3.kptr(), 0, (argc + 1) * sizeof(uintptr_t) + args_sz);

        // copy arguments to stack
        for (size_t i = 0; i < (size_t) argc; i++)
        {
            uintptr_t sz = strlen(argv[i]) + 1;
            memcpy(it2.kptr(), argv[i], sz);
            *(uintptr_t*)it3.kptr() = it2.va();
            it2 += sz;
            it3 += sizeof(uintptr_t);
        }

        // Replace current process with new process
        x86_64_pagetable* oldpt = pagetable_;
        this->init_user(pagetable);
        regs_->reg_rbp = MEMSIZE_VIRTUAL;
        regs_->reg_rsp = MEMSIZE_VIRTUAL - args_sz - (argc + 1) * sizeof(uintptr_t);
        regs_->reg_rip = ld.entry_rip_;
        regs_->reg_rsi = regs_->reg_rsp;
        regs_->reg_rdi = argc;
        set_pagetable(pagetable_);

        // free the memory of the process
        for (vmiter it(oldpt, 0); it.low(); it.next()) 
        {
            if (it.user() && it.pa() != CONSOLE_ADDR)
            {
                it.kfree_page();
            }
        }

        // free the process page table
        for (ptiter it(oldpt); it.low(); it.next())
        {
            it.kfree_ptp();
        }

        vmiter(this, 0).invalidate_all();

        // ensures that the top pagetable is freed
        delete oldpt;
    }
    yield_noreturn();
}

int proc::syscall_waitpid(proc* cur, pid_t pid, int* status, int options)
{
    spinlock_guard guard(ptable_lock);
    proc* child = nullptr;
    bool found = false;

    // find a zombie child that has exited or the specified pid child
    {
        spinlock_guard guard2(family_lock);
        for (proc* a = children_.front(); a; a = children_.next(a))
        {
            if (pid == 0 || a->id_ == pid)
            {
                child = a;
                if (child->pstate_ == proc::ps_zombie)
                {
                    found = true;
                    break;
                }
            }
        }
    }

    // specified pid not found so return E_CHILD
    if (!child)
    {
        return E_CHILD;
    }

    else
    {

        if (!found)
        {
            if (options == W_NOHANG)
            {
                return E_AGAIN;
            }

            // wait until a child exits
            if (pid == 0)
            {
                waiter w;
                w.wait_until(waitq_, [&] () 
                {
                    spinlock_guard guard3(family_lock);
                    if (!child)
                    {
                        child = children_.front();
                    }
                    if (child->pstate_ == proc::ps_zombie)
                    {
                        return true;
                    }
                    child = children_.next(child);
                    return false;
                }, guard);
            }

            // wait until the specified pid child exits
            else
            {
                waiter w;
                w.wait_until(waitq_, [&] () 
                {
                    spinlock_guard guard3(family_lock);
                    if (!child)
                    {
                        child = children_.front();
                    }
                    if ((child->id_ == pid) && (child->pstate_ == proc::ps_zombie))
                    {
                        return true;
                    }
                    return false;
                }, guard);
            }
        }
    }

    assert(child);

    // kill zombie process and return its pid
    return kill_zombie(child, status);
}

// proc::kill_zombie(zombie, status)
//    Cleans ups the zombie process and returns its pid.

pid_t proc::kill_zombie(proc* zombie, int* status) 
{
    spinlock_guard guard(family_lock);

    // remove zombie from children linked list
    children_.erase(zombie);

    // update status
    if (status != nullptr)
    {
        *status = zombie->status_;
    }

    
    pid_t id = zombie->id_;
    assert(zombie != nullptr);
    delete zombie;
    ptable[id] = nullptr;
    return id;
}

int proc::syscall_dup2(int oldfd, int newfd)
{
    if (oldfd == newfd)
    {
        return oldfd;
    }

    auto irqs = fd_table_lock.lock();
    if (oldfd < 0 || oldfd >= NUM_FD || !fd_table_[oldfd] || newfd < 0 || newfd >= NUM_FD)
    {
        fd_table_lock.unlock(irqs);
        return E_BADF;
    }

    auto replace = fd_table_[oldfd];

    if (fd_table_[newfd])
    {
        fd_table_lock.unlock(irqs);
        syscall_close(newfd);
        irqs = fd_table_lock.lock();
    }

    fd_table_[newfd] = replace;

    // maybe move this up there for the future
    auto irqs2 = fd_table_[newfd]->file_descriptor_lock.lock();
    ++fd_table_[newfd]->ref;
    fd_table_[newfd]->file_descriptor_lock.unlock(irqs2);
    fd_table_lock.unlock(irqs);
    return newfd;
}

int proc::syscall_close(int fd)
{
    spinlock_guard guard(global_fd_table_lock);
    spinlock_guard table_guard(fd_table_lock);

    // Check if filedescriptor is valid
    if (fd < 0 || fd >= NUM_FD || !fd_table_[fd])
    {
        return E_BADF;
    }

    file_descriptor* close_fd = fd_table_[fd];
    
    fd_table_[fd] = nullptr;
    spinlock_guard guard2(close_fd->file_descriptor_lock);
    
    // Decrement reference count
    close_fd->ref--;

    // If reference count is 0, free the file descriptor
    if(close_fd->ref == 0) 
    {
        // If vnode is a pipe, close the corresponding end of pipe
        if (close_fd->vnode_->type_ == vnode::v_pipe)
        {
            bbuffer* bounded_buffer = reinterpret_cast<bbuffer*>(close_fd->vnode_->data);
            if (close_fd->writable)
            {
                bounded_buffer->write_closed_ = true;
                bounded_buffer->wq_.notify_all();
            }
            if (close_fd->readable)
            {
                bounded_buffer->read_closed_ = true;
                bounded_buffer->wq_.notify_all();
            }

            // If both ends of the pipe are closed, free the bounded buffer
            if (bounded_buffer->write_closed_ && bounded_buffer->read_closed_)
            {
                kfree(close_fd->vnode_->data);
                close_fd->vnode_->data = nullptr;
            }
        }

        if (close_fd->vnode_ != nullptr)
        {
            spinlock_guard g(close_fd->vnode_->vn_lock);
            --close_fd->vnode_->vn_refcount;

            // If vnode reference count is 0, free the vnode
            if(close_fd->vnode_->vn_refcount == 0) 
            {
                kfree(close_fd->vnode_);
            }
        }


        // Remove the file descriptor from the global file descriptor table
        for (int i = 0; i < 32; i++)
        {
            if (global_fd_table[i] == close_fd)
            {
                global_fd_table[i] = nullptr;
            }
        }
 
        kfree(close_fd);
    }
    return 0;
}


int proc::allocate_fd(bool readable, bool writable)
{
    spinlock_guard guard(global_fd_table_lock);
    spinlock_guard guard2(fd_table_lock);

    // We want to first find a free global descriptor table entry
    int global_fd = -1;
    for (int i = 0; i < 32; i++)
    {
        if (!global_fd_table[i])
        {
            global_fd = i;
            break;
        }
    }

    // If we can't find a free global descriptor table entry, return E_MFILE (too many open files)
    if (global_fd == -1)
    {
        return E_MFILE;
    }

    // Now we want to find a free process descriptor table entry
    int proc_fd = -1;

    for (int i = 0; i < NUM_FD; i++)
    {
        if (!fd_table_[i])
        {
            proc_fd = i;
            break;
        }
    }

    // If we can't find a free process descriptor table entry, return E_MFILE (too many open files)
    if (proc_fd == -1)
    {
        return E_MFILE;
    }


    // Create a new file descriptor and add it to the global and process descriptor tables
    file_descriptor* fd = knew<file_descriptor>();
    if (!fd)
    {
        return E_NOMEM;
    }

    // Initialize the file descriptor fields
    fd->readable = readable;
    fd->writable = writable;
    fd->ref++;
    fd_table_[proc_fd] = fd;
    global_fd_table[global_fd] = fd;
    return proc_fd;
}

uintptr_t proc::syscall_pipe()
{
    int wfd, rfd;

    // allocate file descriptors for read and write ends of the pipe
    wfd = allocate_fd(false, true);
    if (wfd < 0) return wfd;


    rfd = allocate_fd(true, false);
    if (rfd < 0)
    {
        syscall_close(wfd);
        return rfd;
    }

    // allocate associated pipe vnode for the file descriptors
    auto vnode = knew<vnode_pipe>();

    if (!vnode)
    {
        syscall_close(rfd);
        syscall_close(wfd);
        return E_NOMEM;
    }

    // make sure the vnode is linked to the file descriptors
    fd_table_[rfd]->vnode_ = vnode;
    fd_table_[wfd]->vnode_ = vnode;

    // we have two file descriptor references to the vnode
    vnode->vn_refcount = 2;

    // allocate bounded buffer for the pipe vnode
    auto bounder_buffer = knew<bbuffer>();

    if (!bounder_buffer)
    {
        kfree(vnode);
        syscall_close(rfd);
        syscall_close(wfd);
        return E_NOMEM;
    }

    vnode->data = bounder_buffer;

    return rfd | ((uintptr_t) wfd << 32);
}

// proc::syscall_read(regs), proc::syscall_write(regs),
// proc::syscall_readdiskfile(regs)
//    Handle read and write system calls.

uintptr_t proc::syscall_read(regstate* regs) {
    // This is a slow system call, so allow interrupts by default
    sti();

    int fd = regs->reg_rdi;
    uintptr_t addr = regs->reg_rsi;
    size_t sz = regs->reg_rdx;

    // Check file descriptor 
    if (fd < 0 ||  !fd_table_[fd] || !fd_table_[fd]->readable || !fd_table_[fd]->vnode_) 
    {
        return E_BADF;
    }

    // check for integer overflow
    if (addr + sz < addr || sz == SIZE_MAX) {
        return E_FAULT;
    }

    // Validate the read buffer
    if(addr + sz > VA_LOWEND || addr + sz < addr || !vmiter(this, addr).range_perm(sz, PTE_P | PTE_U)) 
    {
        return E_FAULT;
    }

    if (sz == 0) 
    {
        return 0;
    }

    return fd_table_[fd]->vnode_->read(fd_table_[fd], addr, sz);
    
}

uintptr_t proc::syscall_write(regstate* regs) {
    // This is a slow system call, so allow interrupts by default
    sti();

    int fd = regs->reg_rdi;
    uintptr_t addr = regs->reg_rsi;
    size_t sz = regs->reg_rdx;

    if(!sz) return 0;

    // check for integer overflow
    if(addr + sz < addr || sz == SIZE_MAX) {
        return E_FAULT;
    }

    // test that file descriptor is present and writable
    if(fd < 0 || !fd_table_[fd] || !fd_table_[fd]->writable) {
        return E_BADF;
    }

    // check for present and user-accessible memory
    if(!(vmiter(this, addr).range_perm(sz, PTE_P | PTE_U))) {
        return E_FAULT;
    }
    return fd_table_[fd]->vnode_->write(fd_table_[fd], addr, sz);
}

uintptr_t proc::syscall_readdiskfile(regstate* regs) {
    // This is a slow system call, so allow interrupts by default
    sti();

    const char* filename = reinterpret_cast<const char*>(regs->reg_rdi);
    unsigned char* buf = reinterpret_cast<unsigned char*>(regs->reg_rsi);
    size_t sz = regs->reg_rdx;
    off_t off = regs->reg_r10;

    if (!sata_disk) {
        return E_IO;
    }

    // read root directory to find file inode number
    auto ino = chkfsstate::get().lookup_inode(filename);
    if (!ino) {
        return E_NOENT;
    }

    // read file inode
    ino->lock_read();
    chkfs_fileiter it(ino.get());

    size_t nread = 0;
    while (nread < sz) {
        // copy data from current block
        if (auto e = it.find(off).load()) {
            unsigned b = it.block_relative_offset();
            size_t ncopy = min(
                size_t(ino->size - it.offset()),   // bytes left in file
                chkfs::blocksize - b,              // bytes left in block
                sz - nread                         // bytes left in request
            );
            memcpy(buf + nread, e->buf_ + b, ncopy);

            nread += ncopy;
            off += ncopy;
            if (ncopy == 0) {
                break;
            }
        } else {
            break;
        }
    }

    ino->unlock_read();
    return nread;
}


// memshow()
//    Draw a picture of memory (physical and virtual) on the CGA console.
//    Switches to a new process's virtual memory map every 0.25 sec.
//    Uses `console_memviewer()`, a function defined in `k-memviewer.cc`.

static void memshow() {
    static unsigned long last_redisplay = 0;
    static unsigned long last_switch = 0;
    static int showing = 1;

    // redisplay every 0.04 sec
    if (last_redisplay != 0 && ticks - last_redisplay < HZ / 25) {
        return;
    }
    last_redisplay = ticks;

    // switch to a new process every 0.5 sec
    if (ticks - last_switch >= HZ / 2) {
        showing = (showing + 1) % NPROC;
        last_switch = ticks;
    }

    spinlock_guard guard(ptable_lock);

    int search = 0;
    while ((!ptable[showing]
            || !ptable[showing]->pagetable_
            || ptable[showing]->pagetable_ == early_pagetable)
           && search < NPROC) {
        showing = (showing + 1) % NPROC;
        ++search;
    }

    console_memviewer(ptable[showing]);
    if (!ptable[showing]) {
        console_printf(CPOS(10, 26), CS_WHITE "   VIRTUAL ADDRESS SPACE\n"
            "                          [All processes have exited]\n"
            "\n\n\n\n\n\n\n\n\n\n\n");
    }
}


// tick()
//    Called once every tick (0.01 sec, 1/HZ) by CPU 0. Updates the `ticks`
//    counter and performs other periodic maintenance tasks.

void tick() {
    // Update current time
    ++ticks;

    // Wake up processes that are sleeping
    timer_wheel[ticks % TIMER_WHEEL_SIZE].notify_all();

    // Update display
    if (consoletype == CONSOLE_MEMVIEWER) {
        memshow();
    }
}
