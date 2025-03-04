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
    int mindex = memfile::initfs_lookup(name, memfile::required);
    x86_64_pagetable* pt = knew_pagetable();
    assert(mindex >= 0 && pt);

    // load code and data into pagetable
    memfile_loader ld(mindex, pt);
    int r = proc::load(ld);
    assert(r >= 0);

    // allocate process, initialize registers
    proc* p = knew<proc>();
    p->id_ = pid;
    p->ppid_ = 1;
    init->children_.push_back(p);
    p->init_user(pt);
    p->regs_->reg_rip = ld.entry_rip_;

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

        error_printf(CPOS(24, 0),
                     CS_ERROR "Process %d page fault for %p (%s %s, rip=%p)!\n",
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
            p->pstate_ = proc::ps_pre_zombie;
            {   
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
        spinlock_guard guard(ptable_lock);
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

    // set registers and state of child process
    ptable[child_pid]->pstate_ = PROC_RUNNABLE;
    ptable[child_pid]->regs_->reg_rax = 0;

    {
        spinlock_guard guard2(family_lock);
        ptable[child_pid]->ppid_ = id_;
        children_.push_back(ptable[child_pid]);
    }

    cpus[child_pid % ncpu].enqueue(ptable[child_pid]);
    return child_pid;
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
    children_.erase(zombie);
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

// proc::syscall_read(regs), proc::syscall_write(regs),
// proc::syscall_readdiskfile(regs)
//    Handle read and write system calls.

uintptr_t proc::syscall_read(regstate* regs) {
    // This is a slow system call, so allow interrupts by default
    sti();

    uintptr_t addr = regs->reg_rsi;
    size_t sz = regs->reg_rdx;

    // Your code here!
    // * Read from open file `fd` (reg_rdi), rather than `keyboardstate`.
    // * Validate the read buffer.
    auto& kbd = keyboardstate::get();
    auto irqs = kbd.lock_.lock();

    // mark that we are now reading from the keyboard
    // (so `q` should not power off)
    if (kbd.state_ == kbd.boot) {
        kbd.state_ = kbd.input;
    }

    // yield until a line is available
    // (special case: do not block if the user wants to read 0 bytes)
    while (sz != 0 && kbd.eol_ == 0) {
        kbd.lock_.unlock(irqs);
        yield();
        irqs = kbd.lock_.lock();
    }

    // read that line or lines
    size_t n = 0;
    while (kbd.eol_ != 0 && n < sz) {
        if (kbd.buf_[kbd.pos_] == 0x04) {
            // Ctrl-D means EOF
            if (n == 0) {
                kbd.consume(1);
            }
            break;
        } else {
            *reinterpret_cast<char*>(addr) = kbd.buf_[kbd.pos_];
            ++addr;
            ++n;
            kbd.consume(1);
        }
    }

    kbd.lock_.unlock(irqs);
    return n;
}

uintptr_t proc::syscall_write(regstate* regs) {
    // This is a slow system call, so allow interrupts by default
    sti();

    uintptr_t addr = regs->reg_rsi;
    size_t sz = regs->reg_rdx;

    // Your code here!
    // * Write to open file `fd` (reg_rdi), rather than `consolestate`.
    // * Validate the write buffer.
    auto& csl = consolestate::get();
    spinlock_guard guard(csl.lock_);
    size_t n = 0;
    while (n < sz) {
        int ch = *reinterpret_cast<const char*>(addr);
        ++addr;
        ++n;
        console_printf(CS_WHITE "%c", ch);
    }
    return n;
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
