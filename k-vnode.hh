#ifndef CHICKADEE_K_VNODE_HH
#define CHICKADEE_K_VNODE_HH
#include "kernel.hh"
#include "k-wait.hh"
#include "k-chkfs.hh"
#include "chickadeefs.hh"

struct vnode;
struct vnode_pipe;
struct vnode_memfile;
struct vnode_disk;
struct vnode_kbd_cons;
struct file_descriptor;
struct bbuffer;

using chkfs_iref = ref_ptr<chkfs::inode>;

struct vnode
{
    // vnode types
    enum vnode_type {
        v_pipe, v_memfile, disk, kbd_cons
    };
    vnode_type type_;
    int vn_refcount = 0;                        // Reference count for vnode lifetime management
    spinlock vn_lock;                           // Lock for protecting vnode fields
    void* data = nullptr;                       // Pointer to vnode-specific data (if any)
    chkfs_iref ino_;               // Reference to the inode
    vnode(vnode_type t) : type_(t) {}
    virtual uintptr_t read(file_descriptor* f, uintptr_t addr, size_t sz) = 0;
    virtual uintptr_t write(file_descriptor* f, uintptr_t addr, size_t sz) = 0;
};

struct vnode_pipe : public vnode
{
    vnode_pipe() : vnode(vnode::v_pipe) {}
    uintptr_t read(file_descriptor* f, uintptr_t addr, size_t sz) override;
    uintptr_t write(file_descriptor* f, uintptr_t addr, size_t sz) override;
};

struct vnode_memfile : public vnode
{
    vnode_memfile() : vnode(vnode::v_memfile) {}
    uintptr_t read(file_descriptor* f, uintptr_t addr, size_t sz) override;
    uintptr_t write(file_descriptor* f, uintptr_t addr, size_t sz) override;
};

struct vnode_disk : public vnode
{
    vnode_disk() : vnode(vnode::disk) {}
    uintptr_t read(file_descriptor* f, uintptr_t addr, size_t sz) override;
    uintptr_t write(file_descriptor* f, uintptr_t addr, size_t sz) override;
    ssize_t lseek(file_descriptor* f, off_t off, int origin);
};

struct vnode_kbd_cons : public vnode
{
    vnode_kbd_cons() : vnode(vnode::kbd_cons) {}
    uintptr_t read(file_descriptor* f, uintptr_t addr, size_t sz) override;
    uintptr_t write(file_descriptor* f, uintptr_t addr, size_t sz) override;
};

struct file_descriptor 
{
    spinlock file_descriptor_lock;              // Lock to protect file descriptor access
    int ref = 0;                                // Reference count for this descriptor
    bool readable;                              // Whether file descriptor is readable
    bool writable;                              // Whether file descriptor is writable
    vnode* vnode_ = nullptr;                    // Pointer to associated vnode object
    off_t read_offset = 0;                      // Current read offset
    off_t write_offset = 0;                     // Current write offset (for sequential writes)
};


// Bounded buffer used for pipes or buffered IO (largely taken from CS61)
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