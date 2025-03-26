CS 161 Problem Set 3 VFS Design Document
========================================

```c++


struct file_descriptor {
    spinlock file_descriptor_lock;              // Lock to protect file descriptor access
    int ref = 0;                                // Reference count for this descriptor
    bool readable;                              // Whether file descriptor is readable
    bool writable;                              // Whether file descriptor is writable
    vnode* vnode_ = nullptr;                    // Pointer to associated vnode object
    off_t read_offset = 0;                      // Current read offset
    off_t write_offset = 0;                     // Current write offset (for sequential writes)
};

struct vnode {
    spinlock vnode_lock;
    // vnode types
    enum vnode_type {
        VNODETYPE_PIPE, VNODETYPE_TTY, VNODETYPE_DIR, VNODETYPE_FILE
    };
    vnode_type type_;
    int vn_refcount = 0;                        // Reference count for vnode lifetime management
    spinlock vn_lock;                           // Lock for protecting vnode fields
    void* data = nullptr;                       // Pointer to vnode-specific data (if any)
    vnode(vnode_type t) : type_(t) {}

    filesystem* fs;               // Associated file system

    virtual ssize_t read(file_descriptor* fd, void* buf, size_t count) = 0;
    virtual ssize_t write(file_descriptor* fd, const void* buf, size_t count) = 0;
};

struct vnode_pipe : public vnode {
    type = VNODETYPE_PIPE;
};

struct vnode_tty : public vnode {
    type = VNODETYPE_TTY;
};

struct vnode_dir : public vnode {
    type = VNODETYPE_DIR;
};

struct vnode_file : public vnode {
    type = VNODETYPE_FILE;
};

struct filesystem{
    spinlock vfs_lock;
    const char* name;
    vnode* root_vnode;
};

```

## Functionality
- Each process will have an array of `file_descriptor` pointers which acts as the file descriptor table.
- File descriptors reference `vnode` objects, which represent actual files.
- Each `vnode` contains metadata about the file and supports read/write operations.
- Each `vnode` has the following types:
    - `vnode_pipe`: Represents a pipe for interprocess communication.
    - `vnode_tty`: Represents a terminal device.
    - `vnode_dir`: Represents a directory.
    - `vnode_file`: Represents a regular file.
- We also have a `filesystem` struct that represents a mounted filesystem instance.
- Filesystems manage vnodes and implement file operations.
- Each mounted filesystem has a root `vnode`.

## Memory Allocation and Deallocation
- File Descriptors: Allocated when a process opens a file (open() or pipe()) and freed when the reference count drops to zero (close(fd)).
- Vnode: Created when a file is accessed for the first time and freed when the last reference is removed.
- Filesystem: Allocated when a new filesystem is mounted and deallocated when the filesystem is unmounted.

## Synchronization Invariants
- To prevent deadlocks, locks must always be acquired in the following order: file_descriptor_lock, vnode_lock, vfs_lock
- A file descriptor must acquire its lock before modifying offset or vnode
- A vnode must acquire its lock before modifying file data or metadata.
- A filesystem lock is needed when modifying its vnode list
- Atomic types throughout the structs also ensure safe concurrent accesses.

## Future directions
Could add more fine-grained locks or remove current locks to allow more concurrent access.

## Concerns
I need a more robust way to unmount and mount my filesystems.