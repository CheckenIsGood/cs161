#include "k-chkfs.hh"
#include "k-ahci.hh"
#include "k-chkfsiter.hh"

bufcache bufcache::bc;

bufcache::bufcache() {
}

list<bcslot, &bcslot::link_> dirty_list_;

spinlock dirty_lock_; // protects dirty_list_

// bufcache::load(bn, cleaner)
//    Reads disk block `bn` into the buffer cache and returns a reference
//    to that bcslot. The returned slot has `buf_ != nullptr` and
//    `state_ >= bcslot::s_clean`. The function may block.
//
//    If this function reads the disk block from disk, and `cleaner != nullptr`,
//    then `cleaner` is called on the slot to clean the block data.
//
//    Returns a null reference if there's no room for the block.

bcref bufcache::load(chkfs::blocknum_t bn, block_clean_function cleaner) {
    bool synced_once = false;
    retry:
    assert(chkfs::blocksize == PAGESIZE);
    auto irqs = lock_.lock();

    size_t evict_slot = size_t(-1);
    uint64_t oldest_time = UINT64_MAX;

    // look for slot containing `bn`
    size_t i, empty_slot = -1;
    for (i = 0; i != nslots; ++i) {
        if (slots_[i].ref_ == 0 && slots_[i].state_ == bcslot::s_clean) 
        {
            if (slots_[i].last_used_ < oldest_time) 
            {
                evict_slot = i;
                oldest_time = slots_[i].last_used_;
            }
        }
        if (slots_[i].empty()) 
        {
            if (empty_slot == size_t(-1)) 
            {
                empty_slot = i;
            }
        } else if (slots_[i].bn_ == bn) {
            break;
        }
    }

    // if not found, use free slot
    if (i == nslots) 
    {
        if (empty_slot != size_t(-1)) 
        {
            i = empty_slot;
        } 
        else if (evict_slot != size_t(-1)) 
        {
            i = evict_slot;
            slots_[i].clear(); // Clear it before reuse
        } 
        else 
        {
            lock_.unlock(irqs);

            // fallback path: attempt to sync if dirty but unreferenced blocks exist
            if (!synced_once) {
                synced_once = true;

                // Check for any unreferenced dirty blocks
                bool saw_unreferenced_dirty = false;
                for (size_t j = 0; j != nslots; ++j) {
                    if (slots_[j].ref_ == 0 && slots_[j].state_ == bcslot::s_dirty) {
                        saw_unreferenced_dirty = true;
                        break;
                    }
                }

                if (saw_unreferenced_dirty) {
                    sync(0);
                    goto retry;
                }
            }

            log_printf("bufcache: no room and no evictable block for %u\n", bn);
            return nullptr;
        }
    }

    // acquire lock on slot
    auto& slot = slots_[i];
    slot.lock_.lock_noirq();

    // mark allocated if empty
    if (slot.empty()) {
        slot.state_ = bcslot::s_allocated;
        slot.bn_ = bn;
    }

    // no longer need cache lock
    lock_.unlock_noirq();

    // add reference
    ++slot.ref_;
    slot.last_used_ = rdtsc();

    // load block
    bool ok = slot.load(irqs, cleaner);

    // unlock
    if (!ok) {
        // remove reference since load was unsuccessful
        --slot.ref_;
    }
    slot.lock_.unlock(irqs);

    // return reference to slot
    if (ok) {
        return bcref(&slot);
    } else {
        return bcref();
    }
}


// bcslot::load(irqs, cleaner)
//    Completes the loading process for a block. Requires that `lock_` is
//    locked, that `state_ >= s_allocated`, and that `bn_` is set to the
//    desired block number.

bool bcslot::load(irqstate& irqs, block_clean_function cleaner) {
    bufcache& bc = bufcache::get();

    // load block, or wait for concurrent reader to load it
    while (true) {
        assert(state_ != s_empty);
        if (state_ == s_allocated) {
            if (!buf_) {
                buf_ = reinterpret_cast<unsigned char*>
                    (kalloc(chkfs::blocksize));
                if (!buf_) {
                    return false;
                }
            }
            state_ = s_loading;
            lock_.unlock(irqs);

            sata_disk->read(buf_, chkfs::blocksize,
                            bn_ * chkfs::blocksize);

            irqs = lock_.lock();
            state_ = s_clean;
            if (cleaner) {
                cleaner(this);
            }
            bc.read_wq_.notify_all();
        } else if (state_ == s_loading) {
            waiter().wait_until(bc.read_wq_, [&] () {
                    return state_ != s_loading;
                }, lock_, irqs);
        } else {
            return true;
        }
    }
}


// bcslot::decrement_reference_count()
//    Decrements this buffer cache slot’s reference count.
//
//    The handout code *erases* the slot (freeing its buffer) once the
//    reference count reaches zero. This is bad for performance, and you
//    will change this behavior in pset 4 part A.

void bcslot::decrement_reference_count() {
    spinlock_guard guard(lock_);    // needed for last_used_
    assert(ref_ != 0);
    last_used_ = rdtsc();
    --ref_;
}


// bcslot::lock_buffer()
//    Acquires a write lock for the contents of this slot. Must be called
//    with no spinlocks held.

void bcslot::lock_buffer() {
    // cli(); 
    // assert(this_cpu()->spinlock_depth_ == 0);
    spinlock_guard guard(lock_);
    assert(state_ == s_clean || state_ == s_dirty);
    assert(buf_owner_ != current());
    while (buf_owner_) {
        guard.unlock();
        current()->yield();
        guard.lock();
    }
    buf_owner_ = current();
    spinlock_guard dirty_guard(dirty_lock_);
    state_ = s_dirty;

    if (!link_.is_linked())
    {
        dirty_list_.push_back(this);
    }
}


// bcslot::unlock_buffer()
//    Releases the write lock for the contents of this slot.

void bcslot::unlock_buffer() {
    spinlock_guard guard(lock_);
    assert(buf_owner_ == current());
    buf_owner_ = nullptr;
}


// bufcache::sync(drop)
//    Writes all dirty buffers to disk, blocking until complete.
//    If `drop > 0`, then additionally free all buffer cache contents,
//    except referenced blocks. If `drop > 1`, then assert that all inode
//    and data blocks are unreferenced.

int bufcache::sync(int drop) {
    // write dirty buffers to disk
    // Your code here!

    if(!sata_disk) return E_IO;

    list<bcslot, &bcslot::link_> mydirty;

    // Atomically swap dirty_list_ with an empty list
    {
        spinlock_guard guard(dirty_lock_);
        mydirty.swap(dirty_list_);
        // bcslot::dirty_list_.reset();
    }

    // Write each dirty slot to disk
    while (auto slot = mydirty.pop_front()) 
    {
        slot->lock_buffer();  // acquire write lock
        sata_disk->write(slot->buf_, chkfs::blocksize, slot->bn_ * chkfs::blocksize);
        slot->state_ = bcslot::s_clean;
        slot->unlock_buffer();  // release write lock
    }

    // drop clean buffers if requested
    if (drop > 0) {
        spinlock_guard guard(lock_);
        for (size_t i = 0; i != nslots; ++i) {
            spinlock_guard eguard(slots_[i].lock_);

            // validity checks: referenced entries aren't empty; if drop > 1,
            // no data blocks are referenced
            assert(slots_[i].ref_ == 0 || slots_[i].state_ != bcslot::s_empty);
            if (slots_[i].ref_ > 0 && drop > 1 && slots_[i].bn_ >= 2) {
                error_printf("sync(2): block %u has nonzero reference count\n", slots_[i].bn_);
                assert_fail(__FILE__, __LINE__, "slots_[i].bn_ < 2");
            }

            // actually drop buffer
            if (slots_[i].ref_ == 0) {
                slots_[i].clear();
            }
        }
    }

    return 0;
}


// inode lock functions
//    The inode lock protects the inode's size and data references.
//    It is a read/write lock; multiple readers can hold the lock
//    simultaneously.
//
//    IMPORTANT INVARIANT: If a kernel task has an inode lock, it
//    must also hold a reference to the disk page containing that
//    inode.

namespace chkfs {

void inode::lock_read() {
    mlock_t v = mlock.load(std::memory_order_relaxed);
    while (true) {
        if (v == mlock_t(-1)) {
            // write locked
            current()->yield();
            v = mlock.load(std::memory_order_relaxed);
        } else if (mlock.compare_exchange_weak(v, v + 1,
                                               std::memory_order_acquire)) {
            return;
        } else {
            pause();
        }
    }
}

void inode::unlock_read() {
    mlock_t v = mlock.load(std::memory_order_relaxed);
    assert(v != 0 && v != mlock_t(-1));
    while (!mlock.compare_exchange_weak(v, v - 1,
                                        std::memory_order_release)) {
        pause();
    }
}

void inode::lock_write() {
    mlock_t v = 0;
    while (!mlock.compare_exchange_weak(v, mlock_t(-1),
                                        std::memory_order_acquire)) {
        current()->yield();
        v = 0;
    }
}

void inode::unlock_write() {
    assert(is_write_locked());
    mlock.store(0, std::memory_order_release);
}

bool inode::is_write_locked() const {
    return mlock.load(std::memory_order_relaxed) == mlock_t(-1);
}

}


// clean_inode_block(slot)
//    Called when loading an inode block into the buffer cache. It clears
//    values that are only used in memory.

static void clean_inode_block(bcslot* slot) {
    uint32_t slot_index = slot->index();
    auto is = reinterpret_cast<chkfs::inode*>(slot->buf_);
    for (unsigned i = 0; i != chkfs::inodesperblock; ++i) {
        // inode is initially unlocked
        is[i].mlock = 0;
        // containing slot's buffer cache position is `slot_index`
        is[i].mbcindex = slot_index;
    }
}


namespace chkfs {
// chkfs::inode::slot()
//    Returns a pointer to the buffer cache slot containing this inode.
//    Requires that this inode is a pointer into buffer cache data.
bcslot* inode::slot() const {
    assert(mbcindex < bufcache::nslots);
    auto& slot = bufcache::get().slots_[mbcindex];
    assert(slot.contains(this));
    return &slot;
}

// chkfs::inode::decrement_reference_Count()
//    Releases the caller’s reference to this inode, which must be located
//    in the buffer cache.
void inode::decrement_reference_count() {
    slot()->decrement_reference_count();
}
}


// chickadeefs state

chkfsstate chkfsstate::fs;

chkfsstate::chkfsstate() {
}


// chkfsstate::inode(inum)
//    Returns a reference to inode number `inum`, or a null reference if
//    there’s no such inode.

chkfs_iref chkfsstate::inode(inum_t inum) {
    auto& bc = bufcache::get();
    auto superblock_slot = bc.load(0);
    assert(superblock_slot);
    auto& sb = *reinterpret_cast<chkfs::superblock*>
        (&superblock_slot->buf_[chkfs::superblock_offset]);

    if (inum <= 0 || inum >= sb.ninodes) {
        return chkfs_iref();
    }

    auto bn = sb.inode_bn + inum / chkfs::inodesperblock;
    auto inode_slot = bc.load(bn, clean_inode_block);
    if (!inode_slot) {
        return chkfs_iref();
    }

    auto iarray = reinterpret_cast<chkfs::inode*>(inode_slot->buf_);
    inode_slot.release(); // the `chkfs_iref` claims the reference
    return chkfs_iref(&iarray[inum % chkfs::inodesperblock]);
}


// chkfsstate::lookup_inode(dirino, filename)
//    Returns the inode corresponding to the file named `filename` in
//    directory inode `dirino`. Returns a null reference if not found.
//    The caller must have acquired at least a read lock on `dirino`.

chkfs_iref chkfsstate::lookup_inode(chkfs::inode* dirino,
                                    const char* filename) {
    chkfs_fileiter it(dirino);
    size_t diroff = 0;
    while (true) {
        auto e = it.find(diroff).load();
        if (!e) {
            return chkfs_iref();
        }
        size_t bsz = min(dirino->size - diroff, blocksize);
        auto dirent = reinterpret_cast<chkfs::dirent*>(e->buf_);
        for (size_t pos = 0; pos < bsz; pos += chkfs::direntsize, ++dirent) {
            if (dirent->inum && strcmp(dirent->name, filename) == 0) {
                return inode(dirent->inum);
            }
        }
        diroff += blocksize;
    }
}


// chkfsstate::lookup_inode(filename)
//    Looks up `filename` in the root directory.

chkfs_iref chkfsstate::lookup_inode(const char* filename) {
    auto dirino = inode(1);
    if (!dirino) {
        return chkfs_iref();
    }
    dirino->lock_read();
    auto ino = fs.lookup_inode(dirino.get(), filename);
    dirino->unlock_read();
    return ino;
}

// chkfsstate::allocate_extent(unsigned count)
//    Allocates and returns the first block number of a fresh extent.
//    The returned extent doesn't need to be initialized (but it should not be
//    in flight to the disk or part of any incomplete journal transaction).
//    Returns the block number of the first block in the extent, or an error
//    code on failure. Errors can be distinguished by
//    `blocknum >= blocknum_t(E_MINERROR)`.

auto chkfsstate::allocate_extent(unsigned count) -> blocknum_t {
    auto& bufcache = bufcache::get();
    auto superblock_slot = bufcache.load(0);

    auto superblock = *reinterpret_cast<chkfs::superblock*>(&superblock_slot->buf_[chkfs::superblock_offset]);

    bcref fbb_bn = bufcache.load(superblock.fbb_bn);

    bitset_view fbb(reinterpret_cast<uint64_t*>(fbb_bn->buf_), chkfs::bitsperblock);

    blocknum_t block_num, current_block;
    bool found_extent;

    found_extent = false;

    block_num = fbb.find_lsb(superblock.data_bn);

    while (block_num + count < superblock.nblocks) 
    {
        unsigned free_count = 0;
        for(current_block = block_num; current_block < block_num + count; ++current_block) 
        {
            if(fbb[current_block]) 
            {
                ++free_count;
            }
            else
            {
                break;
            }
        }

        if(free_count == count) 
        {
            found_extent = true;
            break;
        }

        block_num = current_block + 1;
    }

    if(found_extent) 
    {
        for(blocknum_t i = block_num; i < block_num + count; ++i) 
        {
            fbb_bn->lock_buffer();
            fbb[i] = false;
            fbb_bn->unlock_buffer();
        }
    }

    // check if the block number is valid
    if (block_num >= superblock.nblocks || block_num + count >= superblock.nblocks) 
    {
        return blocknum_t(E_NOSPC);
    }


    if (!found_extent) 
    {
        return blocknum_t(E_NOSPC);
    }

    return block_num;
}

// Caller of the function must be holding a write lock on the root directory inode, buffer lock, and 
// write lock of the inode it is linking to
int chkfsstate::link(chkfs::inum_t inum, const char* pathname)
{
    // find the root directory
    auto root_dirino = this->inode(1);

    chkfs_fileiter it(root_dirino.get());

    // directory entry for the new file
    chkfs::dirent* dirent;
    
    // find a empty directory
    for(size_t diroff = 0; diroff < root_dirino->size; diroff += blocksize) 
    {
        if (auto e = it.find(diroff).load()) 
        {
            // go through block and see if directory entry is empty
            dirent = reinterpret_cast<chkfs::dirent*>(e->buf_);

            // almost jacked from lookup_inode lol
            for(unsigned i = 0; i * sizeof(*dirent) < min(root_dirino->size - diroff, blocksize); ++i, ++dirent) 
            {
                // If we find an empty directory entry, we can use it
                if(!dirent->inum) 
                {
                    e->lock_buffer();
                    dirent->inum = inum;
                    memcpy(dirent->name, pathname, chkfs::maxnamelen + 1);
                    e->unlock_buffer();
                    return 0;
                }
            }
        } 
        else 
        {
            return E_AGAIN;
        }
    }
 
    // We couldn't find an empty directory entry, so we need to allocate a new block
    blocknum_t bn = this->allocate_extent(1);
    if(!bn)
    {
        return E_AGAIN;
    }

    // go to end of file to insert new block
    while (it.active()) 
    {
        it.next();
    }

    int r = it.insert(bn, 1);

    if (r < 0) 
    {
        return E_AGAIN;
    }

    root_dirino->slot()->lock_buffer();
    root_dirino->size += blocksize;
    root_dirino->slot()->unlock_buffer();
 
    // go to end of file
    auto e = it.find(root_dirino->size - blocksize).load();
    if (!e) 
    {
        return E_AGAIN;
    }
    e->lock_buffer();
    dirent = reinterpret_cast<chkfs::dirent*>(&e->buf_[it.block_relative_offset()]);
    memset(dirent, 0, blocksize); // initialize new block to 0


    // set the directory entry
    dirent->inum = inum;
    memcpy(dirent->name, pathname, chkfs::maxnamelen + 1);
    e->unlock_buffer();
    return 0;
}

chkfs_iref chkfsstate::create_file(const char* pathname, uint32_t type)
{
    // get root directory inode
    auto dirino = this->inode(1);

    // hold write lock on root directory inode and lock_buffer to call link later
    dirino->lock_write();
    auto& bufcache = bufcache::get();
    auto superblock_slot = bufcache.load(0);

    auto superblock = *reinterpret_cast<chkfs::superblock*>(&superblock_slot->buf_[chkfs::superblock_offset]);

    for(chkfs::inum_t inum = 1; inum < superblock.ninodes; ++inum) 
    {
        // Inode number inum is located in block number sb.inode_bn + inum/inodesperblock
        auto bn = superblock.inode_bn + inum / chkfs::inodesperblock;
        auto ino_slot = bufcache.load(bn, clean_inode_block);
        if(!ino_slot) 
        {
            dirino->unlock_write();
            return nullptr;
        }
        // Inode at byte offset sizeof(inode) * (inum%inodesperblock)
        size_t ino_index = sizeof(chkfs::inode) * (inum % chkfs::inodesperblock);
        auto ino = reinterpret_cast<chkfs::inode*>(&ino_slot->buf_[ino_index]);

        // check if the inode is locked and obtain lock if so
        if (!ino->is_write_locked()) 
        {
            ino->lock_write();
            if(ino->type == 0) 
            {
                // create directory entry for the new file
                if(chkfsstate::get().link(inum, pathname) < 0) 
                {
                    ino->unlock_write();
                    dirino->unlock_write();
                    return nullptr;
                }

                // Set the inode fields and return

                ino->slot()->lock_buffer();
                ino->size = 0;
                ino->type = type;
                ino->nlink = 1;
                ino->slot()->unlock_buffer();

                auto return_iref = chkfsstate::get().inode(inum);
                ino->unlock_write(); 
                dirino->unlock_write();
                return return_iref;
            }
                
            ino->unlock_write();
        }
    }
    dirino->unlock_write();
    return nullptr;
}

int chkfsstate::unlink(const char* pathname) {
    auto root_dirino = this->inode(1);
    if (!root_dirino) return E_NOENT;

    root_dirino->lock_write();
    chkfs_fileiter it(root_dirino.get());

    for (size_t diroff = 0; diroff < root_dirino->size; diroff += chkfs::blocksize) {
        if (auto e = it.find(diroff).load()) {
            size_t bsz = min(root_dirino->size - diroff, chkfs::blocksize);
            auto dirent = reinterpret_cast<chkfs::dirent*>(e->buf_);
            for (size_t i = 0; i < bsz / sizeof(chkfs::dirent); ++i, ++dirent) {
                if (dirent->inum && strcmp(dirent->name, pathname) == 0) {
                    auto ino = this->inode(dirent->inum);
                    if (!ino) {
                        root_dirino->unlock_write();
                        return E_NOENT;
                    }

                    ino->lock_write();
                    if (ino->nlink == 0) {
                        ino->unlock_write();
                        root_dirino->unlock_write();
                        return E_NOENT;
                    }

                    // Clear dirent
                    e->lock_buffer();
                    dirent->inum = 0;
                    memset(dirent->name, 0, chkfs::maxnamelen + 1);
                    e->unlock_buffer();

                    // Decrement link count
                    ino->nlink--;
                    ino->unlock_write();
                    root_dirino->unlock_write();
                    return 0;
                }
            }
        }
    }

    root_dirino->unlock_write();
    return E_NOENT;
}

