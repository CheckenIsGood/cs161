CS 161 Problem Set 2 Answers
============================

Leave your name out of this file. Put collaboration notes and credit in
`pset2collab.md`.

**Brief, clear answers preferred!**


C. Parent processes: Per-process metadata design
------------------------------------------------
For each proc, I added a ``pid_t ppid_`` field to keep track of each process' parent id, ``list_links children_links_`` and ``list<proc, &proc::children_links_> children_`` to keep a linked list of each process' children. With this per-process metadata, each process keeps track of their own children and when they exit, they can look through their children linked list to change each child's ``ppid`` to ``PID 1`` (init's ppid). This means reparenting will take ``O(C)`` time because we will only loop through an exiting process' children linked list, which will contain ``C`` items.


C. Parent processes: Synchronization plan
-----------------------------------------
I used two spinlocks, ``ptable_lock`` and ``family_lock`` to synchronize. I follow a lock hierarchy with the two locks and have ``ptable_lock`` higher in the hierachy (coarser) than ``family_lock``.  My ``ptable_lock`` is used to protect reads/writes/accesses to ``ptable``. The ``family_lock`` synchronizes anything related to parent and children relationships between processes.

The most important synchronization invariant I have is ``ppid_``, which needs to acquire ``family_lock`` to be accessed (and technically ``ptable_lock``). I also use the ``family_lock`` (and technically ``ptable_lock``) to protect ``list_links children_links_`` and ``list<proc, &proc::children_links_> children_`` accesses I do to reparent. The wait queues also use the ``ptable_lock`` to protect during the predicate and only unlock when I do ``maybe_block`` (all done in ``wait_until``).


D. Wait and exit status: Synchronization plan
---------------------------------------------
I used two spinlocks, ``ptable_lock`` and ``family_lock`` to synchronize. I follow a lock hierarchy with the two locks and have ``ptable_lock`` higher in the hierachy (coarser) than ``family_lock``.  My ``ptable_lock`` is used to protect reads/writes/accesses to ``ptable``. The ``family_lock`` synchronizes anything related to parent and children relationships between processes.

Each process has a ``status`` field that stores the exit status for the process, which will be protected by ``ptable_lock``. We also have an ``interrupt_`` field that is an atomic bool that keeps track of if a child exits while a parent is blocked so we can interrupt a parent's sys_msleep (it is atomic). The ``list_links children_links_`` and ``list<proc, &proc::children_links_> children_`` accesses I use to block while waiting for the children of a process to exit are protected by ``family_lock`` (and technically ``ptable_lock``). I also use ``ptable_lock`` and ``family_lock`` to synchronize when I kill the zombies.


Other notes
-----------


Grading notes
-------------
