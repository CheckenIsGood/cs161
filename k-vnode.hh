#ifndef CHICKADEE_K_VNODE_HH
#define CHICKADEE_K_VNODE_HH
#include "kernel.hh"
#include "k-wait.hh"

struct vnode;
struct vnode_pipe;
struct vnode_memfile;
struct vnode_disk;
struct vnode_kbd_cons;
struct file_descriptor;
struct bbuffer;

struct vnode
{
    enum vnode_type {
        pipe, memfile, disk, kbd_cons
    };
    vnode_type type_;
    int vn_refcount = 0;
    spinlock vn_lock;
    void* data = nullptr;
    vnode(vnode_type t) : type_(t) {}
    virtual uintptr_t read(file_descriptor* f, uintptr_t addr, size_t sz) = 0;
    virtual uintptr_t write(file_descriptor* f, uintptr_t addr, size_t sz) = 0;
};

struct vnode_pipe : public vnode
{
    vnode_pipe() : vnode(vnode::pipe) {}
    uintptr_t read(file_descriptor* f, uintptr_t addr, size_t sz) override;
    uintptr_t write(file_descriptor* f, uintptr_t addr, size_t sz) override;
};

struct vnode_memfile : public vnode
{
    vnode_memfile() : vnode(vnode::memfile) {}
    uintptr_t read(file_descriptor* f, uintptr_t addr, size_t sz) override;
    uintptr_t write(file_descriptor* f, uintptr_t addr, size_t sz) override;
};

struct vnode_disk : public vnode
{
    vnode_disk() : vnode(vnode::disk) {}
    uintptr_t read(file_descriptor* f, uintptr_t addr, size_t sz) override;
    uintptr_t write(file_descriptor* f, uintptr_t addr, size_t sz) override;
};

struct vnode_kbd_cons : public vnode
{
    vnode_kbd_cons() : vnode(vnode::kbd_cons) {}
    uintptr_t read(file_descriptor* f, uintptr_t addr, size_t sz) override;
    uintptr_t write(file_descriptor* f, uintptr_t addr, size_t sz) override;
};

struct file_descriptor 
{
    spinlock file_descriptor_lock;
    std::atomic<int> ref = 0;
    std::atomic<bool> readable;
    std::atomic<bool> writable;
    vnode* vnode_;
    std::atomic<off_t> read_offset = 0;
    std::atomic<off_t> write_offset = 0;
};

struct bbuffer {
    spinlock lock_;
    wait_queue wq_;
    static constexpr size_t bcapacity = 128;
    char bbuf_[bcapacity];
    size_t bpos_ = 0;
    size_t blen_ = 0;
    bool write_closed_ = false;
    bool read_closed_ = false;

    ssize_t read(char* buf, size_t sz);
    ssize_t write(const char* buf, size_t sz);
};

#endif