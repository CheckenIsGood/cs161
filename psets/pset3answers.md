CS 161 Problem Set 3 Answers
============================
Leave your name out of this file. Put collaboration notes and credit in
`pset3collab.md`.

Answers to written questions
----------------------------

## Part B
I realized that a VFS struct is not necessary so I removed it and all references to it. I also did not fully know what filesystems we were dealing with so I changed the ``read`` and ``write`` functions as well as the vnode types to reflect the actual filesystems we will deal with (changed from ``VNODETYPE_PIPE``, ``VNODETYPE_TTY``, ``VNODETYPE_DIR``, ``VNODETYPE_FILE`` to ``v_pipe`` (a pipe for interprocess communication), ``v_memfile`` (initfs memfile filesystem), ``disk`` (disk file system for future pset), ``kbd_cons`` (keyboard console file system)). I also added a global file descriptor table to my code and added a global file descriptor ``spinlock`` called ``global_fd_table_lock`` to protect access to the global file descriptor table. From now, all entries in the per process file descriptor table are just references to entries in the global file descriptor table. I also added a per-process file descriptor lock that protects all access to the per-process file descriptor table. I also updated the lock hierachy I had so ``global_fd_table_lock`` has the highest lock priority followed by the per process ``fd_table_lock``. So my new lock hierarchy is: ``global_fd_table_lock``, ``fd_table_lock``, ``file_descriptor_lock``, vnode_lock

## Part C
No big changes made other than adding a bounded buffer struct (mostly "repurposed" from CS61 lol) that deals with writes and reads for pipes. I also added ``bbuffer::write`` and ``bbuffer::read`` methods (also repurposed from CS61) for this purpose.

## Part D
To synchronize reads and writes to a ``memfile``, I added a spinlock field called ``lock_``. ``lock_`` must be held in order to change any fields within a ``memfile`` object. In ``memfile_loader::get_page`` it acquires the lock itself to protect the memfile's fields but in ``memfile::set_length`` we require the caller to lock ``lock_`` before calling it. I also added a seperate ``initfs_lock`` spinlock that must be held in order to use ``memfile::initfs``. 

## Part E
I added a file, ``p-testexecv.cc`` that checks the argument passing of execv.


Grading notes
-------------
