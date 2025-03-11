CS 161 Problem Set 3 VFS Design Document
========================================

```c++

#define FILETYPE_WRITE (1 << 0) // none
#define FILETYPE_READ (1 << 1) // pipe
#define VNODETYPE_TTY 1;
#define VNODETYPE_FILE 2;
#define VNODETYPE_DIR 3;
#define VNODETYPE_PIPE 4;


struct file_descriptor {
    int file_type;
    spinlock file_descriptor_lock;
    std::atomic<int> ref = 0;
    std::atomic<bool> readable;
    std::atomic<bool> writable;
    vnode* vnode = nullptr;
    std::atomic<off_t> offset = 0;
};

struct vnode {
    spinlock vnode_lock;
    std::atomic<int> dev;           // Device number
    std::atomic<int> inum;          // Inode number
    std::atomic<int> ref;            // Reference count
    std::atomic<int> type;            // Type of inode

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