CS 161 Problem Set 1 Answers
============================
Leave your name out of this file. Put collaboration notes and credit in
`pset1collab.md`.

Answers to written questions
----------------------------

Grading notes
-------------

PART A:

1. The maximum size supported by kalloc() is PAGESIZE (4096 bytes)
2. The first address returned by kalloc() is 0xffff800000001000. This address is exactly 4096 bytes after the kernel base (0xffff800000000000) because our next_free_p starts at 0x0, which is the null pointer and reserved, so our code adds 4096 (PAGESIZE) to it giving us physical address 0x1000. On line 42, this physical address 0x1000 is converted to kernel pointer 0xffff800000001000.
3. 0xffff8000001ff000 is the largest address returned by kalloc() (which is memsize physical - 4096).
4. kalloc() returns kernel text addresses. Line 42 determines this because we see that it converts the physical address to a kernel pointer.
5. In line 205 of k-init.cc, we can change MEMSIZE_PHYSICAL to 0x300000 to use 0x300000 bytes of physical memory
6. 
    for (; next_free_pa < physical_ranges.limit(); next_free_pa += PAGESIZE)
    {
        if (physical_ranges.type(next_free_pa) == mem_available)
        {
            ptr = pa2kptr<void*>(next_free_pa);
            next_free_pa += PAGESIZE;
            break;
        }
    }
7. With the loop using find(), we can just jump to the next range immediately on line 47 (next_free_pa = range->last()). However, we have to keep adding next_free_pa by PAGESIZE until we get out of the range.
8. If there is no page_lock, then there would be no synchronization so if two cores are trying to kalloc a page at the same time, they might return the same address.

PART B:

1. Line 86
2. Line 96
3. The ptiter loop is looping through the page-table pages and the vmiter loop is looping through the user-mapped pages. If the pages marked by the ptiter loop were user-accessible, then a user-level process could arbitrarily modify its own page-table pages, changing its view of memory and allowing it to gain access to kernel code (and other non-user-accessible memory).
4. The status is mem_available. 
5. Chickadee seems to stutter and takes longer time. This is because when you do it.next(), you skip immediately skip through all the invalid pages. However, if you just do it += PAGESIZE, you iterate through every single page, taking more time.
6. If we set NCPU to 2, then we will have three dots (so three pages). Two of the pages are because of idle tasks. When each CPU initializes, it will create a idle task (which run when the CPU has no runnable processes). These idle tasks are not in the mem_kernel hardware ranges or in the pages of the standard processes. So the pages allocated for these idle tasks will be missed in memusage::refresh(). The other page (the one with the largest address) that memusage::refresh() fails to capture is because refresh is called. When refresh is called, we allocate a page for the array v_ which keeps track of the pages that are allocated. However, it doesn't mark the page it allocated for v_.
7. 

PART C:
1. The first transition is on line 107 in `bootentry.S`. The transition happens after the BIOS finishes loading the first 512-byte sector of the hard disk. The processor will switch from real mode (16-bit compatibility mode used by the BIOS) to 64-bit mode, at which point execution transitions to the boot function in boot.cc.
2. Line 33 - The bootloader jumps here after loading the kernel. The code initializes `%rsp` to the top of the `cpus[0]` cpustate page, then jumps to `kernel_start`.
3. Line 262 - Sets up registers to start running kernel code
4. Line 328 - Process is yielding back to the kernel
5. Line 169 - When exception happens
6. Line 213 - Used to transition into `process_main` entry point.
7. Line 522 - Calls `cpustate::init_ap()` if from STARTUP inter-processor interrupt (IPI) that enabled this processor. 
