#include "kernel.hh"
#include "k-lock.hh"
#include "k-list.hh"

// 2^12 = 4096
static constexpr size_t min_order = 12;

// 2^21 = 2MB
static constexpr size_t max_order = 21;

struct page_info 
{
    list_links page_link; // Link to the next page in the free list
    bool free;
    size_t order;
};

// Array representing physical memory pages
static page_info pages[MEMSIZE_PHYSICAL / PAGESIZE];

// Array of free lists for each block order
static list<page_info, &page_info::page_link> free_list[max_order + 1];
spinlock lock;

// Keeps track of the number of allocated pages
static size_t allocated_pages = 0;

// Convert address to page index
inline size_t addr_to_index(uintptr_t addr) 
{
    return addr / PAGESIZE;
}

// Convert page index to address
inline uintptr_t index_to_addr(size_t index) {
    return index * PAGESIZE;
}

// Calculate the index of the buddy block given a page index and order
inline size_t buddy_index(size_t index, size_t order) 
{
    return index ^ (1 << (order - min_order));
}

// Determine the smallest block order that can accommodate the given size
inline size_t size_to_order(size_t sz) 
{
    size_t n = 1 << min_order;
    size_t o = min_order;
    while (o <= max_order && n < sz) {
        n <<= 1;
        o++;
    }

    // Return -1 if the size exceeds max_order
    return (o > max_order) ? -1 : o;
}

// Insert a block of memory into the free list at a given order
static void insert_block(size_t index, size_t o) 
{
    page_info& pg = pages[index];
    pg.free = true;
    pg.order = o;
    (pg.page_link).reset();
    free_list[o].push_front(&pg);
}

// Remove a block from the free list at a given order
static void remove_block(size_t index, size_t o) {
    page_info& pg = pages[index];
    pg.free = false;
    free_list[o].erase(&pg);
}

// Coalesce adjacent free pages into larger blocks if possible
static void coalesce(size_t index, size_t& o) {
    while (o < max_order) 
    {
        // Find the buddy block index
        size_t bidx = buddy_index(index, o);

        // If the buddy block is free and at the same order, merge them
        if (pages[bidx].order == o && pages[bidx].free && bidx < (MEMSIZE_PHYSICAL / PAGESIZE))
        {
            remove_block(bidx, o);
            remove_block(index, o);
            if (bidx < index) 
            {
                index = bidx;
            }
            ++o;
            insert_block(index, o);
        }

        // No further coalescing possible 
        else 
        {
            break;
        }
    }
}

// Initialize the memory allocator by setting up the free lists and populating them
void init_kalloc() {
    spinlock_guard guard(lock);

    for (auto& p : pages) 
    {
        p.free = false;
        p.order = 0;
        p.page_link.reset();
    }

    // Clear the free lists for each order
    for (size_t i = min_order; i <= max_order; ++i) 
    {
        free_list[i].reset();
    }

    // Populate the free list based on available memory ranges
    for (auto& r : physical_ranges) 
    {
        if (r.type() == mem_available) 
        {
            uintptr_t start = r.first();
            uintptr_t end = r.last();
            while (start < end) 
            {
                size_t o = min_order;

                // Try to find the maximum order that fits within the current range
                while (o + 1 <= max_order && (start % (1UL << (o + 1))) == 0 && start + (1UL << (o + 1)) <= end)
                {
                    ++o;
                }

                insert_block(addr_to_index(start), o);
                start += (1UL << o);
            }
        }
    }
}

// Allocate memory of the requested size, returning a pointer to the allocated block
void* kalloc(size_t sz) 
{
    spinlock_guard guard(lock);
    if (sz == 0) 
    {
        return nullptr;
    }
    size_t smallest_order = size_to_order(sz);

    // Return nullptr if the size is too large
    if ((int) smallest_order < 0) 
    {
        return nullptr;
    }

    size_t allocated_order = smallest_order;
    assert(smallest_order >= min_order);

    // Find the first available block of the appropriate size
    while (allocated_order <= max_order && free_list[allocated_order].empty())
    {
        allocated_order++;
    }
    if (allocated_order > max_order) 
    {
        return nullptr;
    }

    // Allocate a block from the free list
    page_info* free_block = free_list[allocated_order].pop_front();
    size_t index = free_block - pages;
    pages[index].free = false;
    assert(!free_block->free);

    assert(allocated_order >= smallest_order);

    // Split the block if necessary
    while (allocated_order > smallest_order) 
    {
        --allocated_order;
        size_t buddy_index = index ^ (1 << (allocated_order - min_order));
        insert_block(buddy_index, allocated_order);

        assert(pages[buddy_index].free);
        assert(pages[buddy_index].order == allocated_order);
    }

    pages[index].order = allocated_order;

    uintptr_t pa = index_to_addr(index);

    // **Invariant: Ensure the allocated block is aligned to 2^o**
    assert(pa % (1UL << allocated_order) == 0);

    asan_mark_memory(pa, 1UL << allocated_order, false);
    memset(pa2kptr<void*>(pa), 0xCC, (1UL << allocated_order));

    allocated_pages += (1UL << (allocated_order - min_order));
    return pa2kptr<void*>(pa);
}

// Free a previously allocated block of memory
void kfree(void* ptr) 
{
    spinlock_guard guard(lock);
    if (!ptr) {
        return;
    }

    // Convert the pointer to a physical address, find page index, and get the order
    uintptr_t pa = ka2pa(ptr);
    size_t index = addr_to_index(pa);
    size_t order = pages[index].order;

    assert(!pages[index].free); // Ensure we're not freeing an already freed block

    asan_mark_memory(pa, 1UL << order, true);

    // Insert the block into the free list and attempt to coalesce with buddies
    insert_block(index, order);
    coalesce(index, order);

    // I hate this codebase, why does this EXIST??????????
    invlpg(ptr);

    // Invariant testing
    bool buddy_allocated = !pages[buddy_index(index, order)].free || pages[buddy_index(index, order)].order != order;
    assert(order == max_order || buddy_allocated);
    allocated_pages -= (1UL << (order - min_order));
}

// Return the number of free pages
size_t kalloc_free_pages() 
{
    spinlock_guard guard(lock);
    return (MEMSIZE_PHYSICAL / PAGESIZE) - allocated_pages;
}

// Return the number of allocated pages
size_t kalloc_allocated_pages() 
{
    spinlock_guard guard(lock);
    return allocated_pages;
}

void* operator new(size_t sz, const std::nothrow_t&) noexcept {
    return kalloc(sz);
}
void* operator new(size_t sz, std::align_val_t, const std::nothrow_t&) noexcept {
    return kalloc(sz);
}
void* operator new[](size_t sz, const std::nothrow_t&) noexcept {
    return kalloc(sz);
}
void* operator new[](size_t sz, std::align_val_t, const std::nothrow_t&) noexcept {
    return kalloc(sz);
}
void operator delete(void* ptr) noexcept {
    kfree(ptr);
}
void operator delete(void* ptr, size_t) noexcept {
    kfree(ptr);
}
void operator delete(void* ptr, std::align_val_t) noexcept {
    kfree(ptr);
}
void operator delete(void* ptr, size_t, std::align_val_t) noexcept {
    kfree(ptr);
}
void operator delete[](void* ptr) noexcept {
    kfree(ptr);
}
void operator delete[](void* ptr, size_t) noexcept {
    kfree(ptr);
}
void operator delete[](void* ptr, std::align_val_t) noexcept {
    kfree(ptr);
}
void operator delete[](void* ptr, size_t, std::align_val_t) noexcept {
    kfree(ptr);
}
