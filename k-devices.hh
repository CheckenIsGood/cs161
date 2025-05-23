#ifndef CHICKADEE_K_DEVICES_HH
#define CHICKADEE_K_DEVICES_HH
#include "kernel.hh"
#include "k-wait.hh"
#include "chickadeefs.hh"
#include "k-chkfs.hh"

// keyboardstate: keyboard buffer and keyboard interrupts

#define KEY_UP          0xC0
#define KEY_RIGHT       0xC1
#define KEY_DOWN        0xC2
#define KEY_LEFT        0xC3
#define KEY_HOME        0xC4
#define KEY_END         0xC5
#define KEY_PAGEUP      0xC6
#define KEY_PAGEDOWN    0xC7
#define KEY_INSERT      0xC8
#define KEY_DELETE      0xC9

struct keyboardstate {
    spinlock lock_;
    wait_queue wq_;
    char buf_[256];
    unsigned pos_ = 0;      // next position to read
    unsigned len_ = 0;      // number of characters in buffer
    unsigned eol_ = 0;      // position in buffer of most recent \n
    enum { boot, input, fail } state_ = boot;

    static keyboardstate& get() {
        return kbd;
    }

    void check_invariants() {
        assert(pos_ < sizeof(buf_));
        assert(len_ <= sizeof(buf_));
        assert(eol_ <= len_);
    }

    // called from proc::exception(); read characters from device
    void handle_interrupt();

    // consume `n` characters from buffer (0 <= n <= len_)
    void consume(size_t n);

 private:
    static keyboardstate kbd;
    keyboardstate() = default;

    void maybe_echo(int ch);
};


// consolestate: lock for console access

struct consolestate {
    spinlock lock_;

    static consolestate& get() {
        return console;
    }

    void cursor();
    void cursor(bool show);

 private:
    static consolestate console;
    consolestate() = default;

    spinlock cursor_lock_;
    std::atomic<bool> cursor_show_ = true;
    std::atomic<int> displayed_cpos_ = -1;
};


// memfile: in-memory file system of contiguous files

struct memfile {
    static constexpr unsigned namesize = 64;
    char name_[namesize];                // name of file
    unsigned char* data_;                // file data (nullptr if empty)
    size_t len_;                         // length of file data
    size_t capacity_;                    // # bytes available in `data_`

    spinlock lock_;                      // lock for file data

    inline memfile();
    inline memfile(const char* name, unsigned char* first,
                   unsigned char* last);
    inline memfile(const char* name, const char* data);

    // Test if this `memfile` is unused
    inline bool empty() const;

    // Set file length to `len`; return 0 or an error like `E_NOSPC` on failure
    int set_length(size_t len);

    // memfile::initfs[] is the initial file system built in to the kernel
    static constexpr unsigned initfs_size = 64;
    static memfile initfs[initfs_size];

    // Return the index in `initfs` of the memfile named `name`.
    // When the named memfile is not found, the behavior depends on `flag`:
    // if `flag == required`, the function asserts failure; if `flag ==
    // create`, the named memfile is created; and otherwise, an error code
    // is returned.
    enum lookup_flag { optional = 0, required, create };
    static int initfs_lookup(const char* name, lookup_flag flag = optional);
};

inline memfile::memfile()
    : name_(""), data_(nullptr), len_(0), capacity_(0) {
}
inline memfile::memfile(const char* name, unsigned char* first,
                        unsigned char* last)
    : data_(first) {
    size_t namelen = strlen(name);
    ssize_t datalen = reinterpret_cast<uintptr_t>(last)
        - reinterpret_cast<uintptr_t>(first);
    assert(namelen < namesize && datalen >= 0);
    strcpy(name_, name);
    len_ = capacity_ = datalen;
}
inline memfile::memfile(const char* name, const char* data)
    : data_(reinterpret_cast<unsigned char*>(const_cast<char*>(data))),
      len_(strlen(data)), capacity_(0) {
    size_t namelen = strlen(name);
    assert(namelen < namesize);
    strcpy(name_, name);
}
inline bool memfile::empty() const {
    return name_[0] == 0;
}


// memfile::loader: loads a `proc` from a `memfile`

struct memfile_loader : public proc_loader {
    memfile* memfile_;
    inline memfile_loader(memfile* mf, x86_64_pagetable* pt)
        : proc_loader(pt), memfile_(mf) {
    }
    inline memfile_loader(int mf_index, x86_64_pagetable* pt)
        : proc_loader(pt) {
        assert(mf_index >= 0 && unsigned(mf_index) < memfile::initfs_size);
        memfile_ = &memfile::initfs[mf_index];
    }
    get_page_type get_page(size_t off) override;
    void put_page(buffer) override;
};

struct diskfs_loader : public proc_loader {
    chkfs_iref iref_;         // Smart pointer to inode, holds reference
    bcref active_buf_ref_;    // Current loaded buffer block

    diskfs_loader(chkfs_iref iref, x86_64_pagetable* pt)
        : proc_loader(pt), iref_(std::move(iref)) {}

    get_page_type get_page(size_t off) override;
    void put_page(buffer) override;
};

#endif
