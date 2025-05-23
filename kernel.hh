#ifndef CHICKADEE_KERNEL_HH
#define CHICKADEE_KERNEL_HH
#include "x86-64.h"
#include "lib.hh"
#include "k-list.hh"
#include "k-lock.hh"
#include "k-memrange.hh"
#include "k-vnode.hh"
#include "k-wait.hh"
#include "k-vga.hh"
#include <expected>
#if CHICKADEE_PROCESS
#error "kernel.hh should not be used by process code."
#endif
struct proc;
struct yieldstate;
struct proc_loader;
struct elf_program;
struct file_descriptor;
#define PROC_RUNNABLE 1
#define CANARY 0xABCE1234ABCD5678
#define NUM_FD 10
extern file_descriptor* global_fd_table[32];
extern spinlock family_lock;

// kernel.hh
//
//    Functions, constants, and definitions for the kernel.


// Process descriptor type
struct __attribute__((aligned(4096))) proc {
    enum pstate_t {
        ps_blank = 0, ps_runnable = PROC_RUNNABLE, ps_faulted, ps_blocked, ps_zombie, ps_pre_zombie, ps_thread_leader_exited
    };

    // These four members must come first:
    pid_t id_ = 0;                             // Thread ID
    regstate* regs_ = nullptr;                 // Process's current registers
    yieldstate* yields_ = nullptr;             // Process's current yield state
    std::atomic<int> pstate_ = ps_blank;       // Process stat

    x86_64_pagetable* pagetable_ = nullptr;    // Process's page table
    uintptr_t recent_user_rip_ = 0;            // Most recent user-mode %rip
#if HAVE_SANITIZERS
    int sanitizer_status_ = 0;
#endif

    // Per-CPU run queue, controlled by cpustate::runq_lock_
    list_links runq_links_;                    // Links for run queue
    int runq_cpu_ = -1;                        // CPU index of recent run queue

    pid_t ppid_;                                    // Parent process ID - should only use proc leader's       
    list_links children_links_;                     // Links for child list - should only use proc leader's
    list<proc, &proc::children_links_> children_;   // Children of this process - should only use proc leader's
    wait_queue waitq_;                         // Process's wait queue - should only use proc leader's
    std::atomic<int> thread_counter_ = 1;            // Number of threads in this process (only accurate for leader thread)
    // should only use proc leader's thread counter
    
    wait_queue exiting_wq; //Should only use proc leader's

    pid_t pid_ = 0;                                    // Process ID
    file_descriptor* fd_table_[NUM_FD] = {nullptr};    // File descriptors - should only use proc leader's
    spinlock fd_table_lock;                            // should only use proc leader's

    std::atomic<bool> should_exit_ = false;
    std::atomic<bool> cleanup_yourself = false;   // Only if you texit by yourself

    int status_;
    std::atomic<bool> sleeping_ = false;
    std::atomic<bool> interrupt_ = false;

    uintptr_t canary = (uintptr_t) CANARY;
    proc();
    NO_COPY_OR_ASSIGN(proc);

    inline bool contains(uintptr_t addr) const;
    inline bool contains(void* ptr) const;

    void init_user(x86_64_pagetable* pt);
    void init_kernel(void (*f)());

    static int load(proc_loader& ld);

    void exception(regstate* reg);
    uintptr_t syscall(regstate* reg);

    void yield();
    [[noreturn]] void yield_noreturn();
    [[noreturn]] void resume();
    [[noreturn]] void panic_nonrunnable();

    inline bool resumable() const;
    inline void unblock();

    pid_t syscall_fork(regstate* regs);
    pid_t syscall_waitpid(proc* cur, pid_t pid, int* status, int options);

    int syscall_dup2(int oldfd, int newfd);
    int syscall_close(int fd);

    int allocate_fd(bool readable, bool writable);
    uintptr_t syscall_pipe();
    int syscall_open(const char* pathname, int flags);
    pid_t syscall_clone(regstate* regs);
    uintptr_t syscall_read(regstate* reg);
    uintptr_t syscall_write(regstate* reg);
    uintptr_t syscall_readdiskfile(regstate* reg);
    ssize_t syscall_lseek(int fd, off_t off, int origin);
    void syscall_nasty(regstate* reg);
    void syscall_vga_test(regstate* reg);
    void syscall_display(int fd);
    pid_t syscall_texit(int status);
    int syscall_getusage(regstate* reg);
    void syscall_testbuddy(regstate* reg);
    pid_t kill_zombie(proc* zombie, int* status);
    int syscall_unlink(const char* pathname);
    int syscall_execv(const char* pathname, const char* const* argv, int argc);

    inline irqstate lock_pagetable_read();
    inline void unlock_pagetable_read(irqstate& irqs);

 private:
    static int load_segment(const elf_program& ph, proc_loader& ld);
};

#define NPROC 32
extern proc* ptable[NPROC];
extern spinlock ptable_lock;
#define PROCSTACK_SIZE 4096UL


struct proc_loader {
    x86_64_pagetable* pagetable_;
    uintptr_t entry_rip_ = 0;
    inline proc_loader(x86_64_pagetable* pt)
        : pagetable_(pt) {
    }

    struct buffer {
        uint8_t* data;
        size_t size;
        inline buffer(uint8_t* d, size_t s)
            : data(d), size(s) {
        }
    };
    using get_page_type = std::expected<buffer, int>;

    virtual get_page_type get_page(size_t off) = 0;
    virtual void put_page(buffer) = 0;
};

struct tga_header {
    int id_length;
    uint8_t color_map_type;
    uint8_t image_type;
    short color_map_origin;
    int color_map_length;
    int color_map_depth;
    short x_origin;
    short y_origin;
    int width;
    int height;
    int pixel_depth;
    uint8_t image_descriptor;
};


// CPU state type
struct __attribute__((aligned(4096))) cpustate {
    // These three members must come first: they are referenced in assembly
    cpustate* self_;
    proc* current_ = nullptr;
    uint64_t syscall_scratch_;

    int cpuindex_;
    int lapic_id_;

    list<proc, &proc::runq_links_> runq_;
    spinlock runq_lock_;
    unsigned long nschedule_;
    proc* idle_task_;

    unsigned spinlock_depth_;

    uint64_t gdt_segments_[7];
    x86_64_taskstate taskstate_;

    uintptr_t canary = (uintptr_t) CANARY;

    inline cpustate()
        : self_(this) {
    }
    NO_COPY_OR_ASSIGN(cpustate);

    inline bool contains(uintptr_t addr) const;
    inline bool contains(void* ptr) const;

    void init();
    void init_ap();

    void exception(regstate* reg);

    [[noreturn]] void schedule();

    void enable_irq(int irqno);
    void disable_irq(int irqno);

    void enqueue(proc* p);
    void reenqueue(proc* p);

 private:
    void init_cpu_hardware();
    void init_idle_task();
};

#define MAXCPU 16
extern cpustate cpus[MAXCPU];
extern int ncpu;
#define CPUSTACK_SIZE 4096UL
#define CPUALTSTACK_SIZE 3072UL

inline cpustate* this_cpu();


// yieldstate: callee-saved registers that must be preserved across
// proc::yield()

struct yieldstate {
    uintptr_t reg_rbp;
    uintptr_t reg_rbx;
    uintptr_t reg_r12;
    uintptr_t reg_r13;
    uintptr_t reg_r14;
    uintptr_t reg_r15;
    uintptr_t reg_rflags;
};


// timekeeping

// `HZ` defines the number of timer interrupts per second, or ticks.
// Real kernels typically use 100 or 1000; Chickadee typically uses 100.
// Exception: Sanitizers slow down the kernel so much that recursive timer
// interrupts can become a problem, so when sanitizers are on, we reduce the
// interrupt frequency to 10 per second.
#if HAVE_SANITIZERS
# define HZ 10
#else
# define HZ 100
#endif

extern std::atomic<unsigned long> ticks;        // number of ticks since boot


// Segment selectors
#define SEGSEL_BOOT_CODE        0x8             // boot code segment
#define SEGSEL_KERN_CODE        0x8             // kernel code segment
#define SEGSEL_KERN_DATA        0x10            // kernel data segment
#define SEGSEL_APP_CODE         0x18            // application code segment
#define SEGSEL_APP_DATA         0x20            // application data segment
#define SEGSEL_TASKSTATE        0x28            // task state segment


// Physical memory size
#define MEMSIZE_PHYSICAL        0x200000UL
// Virtual memory size
#define MEMSIZE_VIRTUAL         0x300000UL

enum memtype_t : uint8_t {
    mem_nonexistent = 0,
    mem_available = 1,
    mem_kernel = 2,
    mem_reserved = 3,
    mem_console = 4
};
extern memrangeset<16> physical_ranges;


// Hardware interrupt numbers
#define INT_IRQ                 32U
#define IRQ_TIMER               0
#define IRQ_KEYBOARD            1
#define IRQ_IDE                 14
#define IRQ_ERROR               19
#define IRQ_SPURIOUS            31

#define KTEXT_BASE              0xFFFFFFFF80000000UL
#define HIGHMEM_BASE            0xFFFF800000000000UL

inline uint64_t pa2ktext(uint64_t pa) {
    assert(pa < -KTEXT_BASE);
    return pa + KTEXT_BASE;
}

template <typename T>
inline T pa2ktext(uint64_t pa) {
    return reinterpret_cast<T>(pa2ktext(pa));
}

inline uint64_t ktext2pa(uint64_t ka) {
    assert(ka >= KTEXT_BASE);
    return ka - KTEXT_BASE;
}

template <typename T>
inline uint64_t ktext2pa(T* ptr) {
    return ktext2pa(reinterpret_cast<uint64_t>(ptr));
}


inline uint64_t pa2ka(uint64_t pa) {
    assert(pa < -HIGHMEM_BASE);
    return pa + HIGHMEM_BASE;
}

template <typename T>
inline T pa2kptr(uint64_t pa) {
    static_assert(std::is_pointer<T>::value, "T must be pointer");
    return reinterpret_cast<T>(pa2ka(pa));
}

inline uint64_t ka2pa(uint64_t ka) {
    assert(ka >= HIGHMEM_BASE && ka < KTEXT_BASE);
    return ka - HIGHMEM_BASE;
}

template <typename T>
inline uint64_t ka2pa(T* ptr) {
    return ka2pa(reinterpret_cast<uint64_t>(ptr));
}

inline uint64_t kptr2pa(uint64_t kptr) {
    assert(kptr >= HIGHMEM_BASE);
    return kptr - (kptr >= KTEXT_BASE ? KTEXT_BASE : HIGHMEM_BASE);
}

template <typename T>
inline uint64_t kptr2pa(T* ptr) {
    return kptr2pa(reinterpret_cast<uint64_t>(ptr));
}

template <typename T>
inline bool is_kptr(T* ptr) {
    uintptr_t va = reinterpret_cast<uint64_t>(ptr);
    return va >= HIGHMEM_BASE;
}

template <typename T>
inline bool is_ktext(T* ptr) {
    uintptr_t va = reinterpret_cast<uint64_t>(ptr);
    return va >= KTEXT_BASE;
}


template <typename T>
inline T read_unaligned(const uint8_t* x) {
    T a;
    memcpy(&a, x, sizeof(T));
    return a;
}
template <typename T>
inline T read_unaligned_pa(uint64_t pa) {
    return read_unaligned<T>(pa2kptr<const uint8_t*>(pa));
}
template <typename T, typename U>
inline T read_unaligned(const uint8_t* ptr, T (U::* member)) {
    alignas(U) char space[sizeof(U)] = {};
    U* dummy = (U*)(space);
    T a;
    memcpy(&a, ptr + (reinterpret_cast<uintptr_t>(&(dummy->*member)) - reinterpret_cast<uintptr_t>(dummy)), sizeof(T));
    return a;
}


// kalloc(sz)
//    Allocate and return a pointer to at least `sz` contiguous bytes
//    of memory. Returns `nullptr` if `sz == 0` or on failure.
//
//    If `sz` is a multiple of `PAGESIZE`, the returned pointer is guaranteed
//    to be page-aligned.
void* kalloc(size_t sz) __attribute__((malloc));

// kfree(ptr)
//    Free a pointer previously returned by `kalloc`. Does nothing if
//    `ptr == nullptr`.
void kfree(void* ptr);

// operator new, operator delete
//    Expressions like `new (std::nothrow) T(...)` and `delete x` work,
//    and call kalloc/kfree.
void* operator new(size_t sz, const std::nothrow_t&) noexcept;
void* operator new(size_t sz, std::align_val_t al, const std::nothrow_t&) noexcept;
void* operator new[](size_t sz, const std::nothrow_t&) noexcept;
void* operator new[](size_t sz, std::align_val_t al, const std::nothrow_t&) noexcept;
void operator delete(void* ptr) noexcept;
void operator delete(void* ptr, size_t sz) noexcept;
void operator delete(void* ptr, std::align_val_t al) noexcept;
void operator delete(void* ptr, size_t sz, std::align_val_t al) noexcept;
void operator delete[](void* ptr) noexcept;
void operator delete[](void* ptr, size_t sz) noexcept;
void operator delete[](void* ptr, std::align_val_t al) noexcept;
void operator delete[](void* ptr, size_t sz, std::align_val_t al) noexcept;

// knew<T>(), knew<T>(args...)
//    Like `new (std::nothrow) T(args...)`.
template <typename T>
inline __attribute__((malloc)) T* knew() {
    return new (std::nothrow) T;
}
template <typename T, typename... Args>
inline __attribute__((malloc)) T* knew(Args&&... args) {
    return new (std::nothrow) T(std::forward<Args>(args)...);
}

// knew_array<T>(n)
//    Like `new (std::nothrow) T[n]`.
template <typename T>
inline __attribute__((malloc)) T* knew_array(size_t n) {
    return new (std::nothrow) T[n];
}

// init_kalloc
//    Initialize stuff needed by `kalloc`. Called from `init_hardware`,
//    after `physical_ranges` is initialized.
void init_kalloc();


// Initialize hardware and CPUs
void init_hardware();

// Query machine configuration
unsigned machine_ncpu();
unsigned machine_pci_irq(int pci_addr, int intr_pin);

struct ahcistate;
extern ahcistate* sata_disk;


// Early page table (only kernel mappings)
extern x86_64_pagetable early_pagetable[3];

// Allocate and initialize a new, empty page table
x86_64_pagetable* knew_pagetable();

// Change current page table
void set_pagetable(x86_64_pagetable* pagetable);

// Print memory viewer
void console_memviewer(proc* p);

// Run wait queue ktests
int ktest_wait_queues();


// Start the kernel
[[noreturn]] void kernel_start(const char* command);

// Turn off the virtual machine
[[noreturn]] void poweroff();

// Reboot the virtual machine
[[noreturn]] void reboot();

// Call after last process exits
[[noreturn]] void process_halt();


// log_printf, log_vprintf
//    Print debugging messages to the host's `log.txt` file. We run QEMU
//    so that messages written to the QEMU "parallel port" end up in `log.txt`.
__noinline void log_printf(const char* format, ...);
__noinline void log_vprintf(const char* format, va_list val);


// log_print_backtrace
//    Print a backtrace to the host's `log.txt` file, either for the current
//    stack or for the stack active in `p`.
void log_print_backtrace();
void log_print_backtrace(const proc* p);


// lookup_symbol(addr, name, start)
//    Use the debugging symbol table to look up `addr`. Return the
//    corresponding symbol name (usually a function name) in `*name`
//    and the first address in that symbol in `*start`.
__no_asan
bool lookup_symbol(uintptr_t addr, const char** name, uintptr_t* start);


#if HAVE_SANITIZERS
// Sanitizer functions
void init_sanitizers();
void disable_asan();
void enable_asan();
void asan_mark_memory(unsigned long pa, size_t sz, bool poisoned);
#else
inline void disable_asan() {}
inline void enable_asan() {}
inline void asan_mark_memory(unsigned long pa, size_t sz, bool poisoned) {}
#endif


// `panicking == true` iff some CPU has panicked
extern std::atomic<bool> panicking;


// this_cpu
//    Return a pointer to the current CPU. Requires disabled interrupts.
inline cpustate* this_cpu() {
    assert(is_cli());
    cpustate* result;
    asm volatile ("movq %%gs:(0), %0" : "=r" (result));
    return result;
}

// current
//    Return a pointer to the current `struct proc`.
inline proc* current() {
    proc* result;
    asm volatile ("movq %%gs:(8), %0" : "=r" (result));
    return result;
}

// adjust_this_cpu_spinlock_depth(delta)
//    Adjust this CPU's spinlock_depth_ by `delta`. Does *not* require
//    disabled interrupts.
inline void adjust_this_cpu_spinlock_depth(int delta) {
    asm volatile ("addl %1, %%gs:(%0)"
                  : : "c" (offsetof(cpustate, spinlock_depth_)),
                      "er" (delta)
                  : "cc", "memory");
}

// cpustate::contains(ptr)
//    Return true iff `ptr` lies within this cpustate's allocation.
inline bool cpustate::contains(void* ptr) const {
    return contains(reinterpret_cast<uintptr_t>(ptr));
}
inline bool cpustate::contains(uintptr_t addr) const {
    uintptr_t delta = addr - reinterpret_cast<uintptr_t>(this);
    return delta <= CPUSTACK_SIZE;
}

// proc::contains(ptr)
//    Return true iff `ptr` lies within this cpustate's allocation.
inline bool proc::contains(void* ptr) const {
    return contains(reinterpret_cast<uintptr_t>(ptr));
}
inline bool proc::contains(uintptr_t addr) const {
    uintptr_t delta = addr - reinterpret_cast<uintptr_t>(this);
    return delta <= PROCSTACK_SIZE;
}

// proc::resumable()
//    Return true iff this `proc` can be resumed (`regs_` or `yields_`
//    is set). Also checks some assertions about `regs_` and `yields_`.
inline bool proc::resumable() const {
    assert(!(regs_ && yields_));            // at most one at a time
    assert(!regs_ || contains(regs_));      // `regs_` points within this
    assert(!yields_ || contains(yields_));  // same for `yields_`
    return regs_ || yields_;
}

// proc::unblock()
//    If this task is blocked, then mark it as runnable and schedule it
//    on its home CPU. An atomic compare-and-swap changes the `pstate_`;
//    this is in case a task concurrently running on another CPU
//    sets its `pstate_` to some other value, such as `ps_faulted`.
inline void proc::unblock() {
    int s = ps_blocked;
    if (pstate_.compare_exchange_strong(s, ps_runnable)) {
        cpus[runq_cpu_].reenqueue(this);
    }
}

// proc::lock_pagetable_read()
//    Acquire a “read lock” on this process’s page table. While the “read
//    lock” is held, it is illegal to remove or change existing valid
//    mappings in that page table, or to free page table pages.
inline irqstate proc::lock_pagetable_read() {
    return irqstate();
}
inline void proc::unlock_pagetable_read(irqstate&) {
}


// Tell `k-wait.hh` that it may define inline functions when included again
#define CHICKADEE_PROC_DECLARATION 1
#endif

size_t kalloc_free_pages();

size_t kalloc_allocated_pages();