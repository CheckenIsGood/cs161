#include "k-vnode.hh"
#include "k-devices.hh"
#include "k-wait.hh"



uintptr_t vnode_kbd_cons::read(file_descriptor* f, uintptr_t addr, size_t sz) {
     auto& kbd = keyboardstate::get();
    spinlock_guard guard(kbd.lock_);

    // mark that we are now reading from the keyboard
    // (so `q` should not power off)
    if (kbd.state_ == kbd.boot) {
        kbd.state_ = kbd.input;
    }

    // yield until a line is available
    // (special case: do not block if the user wants to read 0 bytes)
    waiter w;
    w.wait_until(kbd.wq_, [&] () {
        return sz == 0 || kbd.eol_ != 0;
    }, guard);

    // read that line or lines
    size_t n = 0;
    while (kbd.eol_ != 0 && n < sz) {
        if (kbd.buf_[kbd.pos_] == 0x04) {
            // Ctrl-D means EOF
            if (n == 0) {
                kbd.consume(1);
            }
            break;
        } else {
            *reinterpret_cast<char*>(addr) = kbd.buf_[kbd.pos_];
            ++addr;
            ++n;
            kbd.consume(1);
        }
    }

    return n;
 }
 
 uintptr_t vnode_kbd_cons::write(file_descriptor* f, uintptr_t addr, size_t sz) {
    auto& csl = consolestate::get();
    spinlock_guard guard(csl.lock_);
    size_t n = 0;
    while (n < sz) {
        int ch = *reinterpret_cast<const char*>(addr);
        ++addr;
        ++n;
        console_printf(CS_WHITE "%c", ch);
    }
    return n;
 }

uintptr_t vnode_pipe::read(file_descriptor* f, uintptr_t addr, size_t sz) 
{
    if (f->writable || !f || !f->vnode_ || f->vnode_->type_ != vnode::v_pipe) 
    {
        return E_BADF;
    }
    return reinterpret_cast<bbuffer*>(f->vnode_->data)->read(reinterpret_cast<char*>(addr), sz);
}

uintptr_t vnode_pipe::write(file_descriptor* f, uintptr_t addr, size_t sz) 
{
    if (f->readable || !f || !f->vnode_ || f->vnode_->type_ != vnode::v_pipe) 
    {
        return E_BADF;
    }
    return reinterpret_cast<bbuffer*>(f->vnode_->data)->write(reinterpret_cast<const char*>(addr), sz);
}


uintptr_t vnode_memfile::read(file_descriptor* f, uintptr_t addr, size_t sz) 
{
    spinlock_guard f_guard(f->file_descriptor_lock);
    if (!f->readable || !f || !f->vnode_ || f->vnode_->type_ != vnode::v_memfile)
    {
        return E_BADF;
    }
    memfile* mfile = reinterpret_cast<memfile*>(f->vnode_->data);
    spinlock_guard guard(mfile->lock_);
    size_t read_sz = min(sz, mfile->len_ - f->read_offset);
    memcpy(reinterpret_cast<char*>(addr), &mfile->data_[f->read_offset], read_sz);
    f->read_offset += read_sz;
    return read_sz;
}

uintptr_t vnode_memfile::write(file_descriptor* f, uintptr_t addr, size_t sz) 
{
    spinlock_guard f_guard(f->file_descriptor_lock);
    if (!f->writable || !f || !f->vnode_ || f->vnode_->type_ != vnode::v_memfile)
    {
        return E_BADF;
    }
    memfile* mfile = reinterpret_cast<memfile*>(f->vnode_->data);
    spinlock_guard guard(mfile->lock_);
    auto r = mfile->set_length(f->write_offset + sz);

    if(r < 0) 
    {
        return r;
    }

    sz = min(mfile->capacity_ - f->write_offset, sz);
    memcpy(&mfile->data_[f->write_offset], reinterpret_cast<void*>(addr), sz);
    f->write_offset += sz;
    return sz;
}


// Largely taken from god eddie's notes from CS61
ssize_t bbuffer::write(const char* buf, size_t sz) 
{
    spinlock_guard guard(lock_);
    assert(!this->write_closed_);
    size_t pos = 0;

    waiter w;
     w.wait_until(wq_, [&] () {
         return (this->blen_ < bcapacity || read_closed_);
     }, guard);

    if (read_closed_) 
    {
        return E_PIPE;
    }

    while (pos < sz && this->blen_ < bcapacity) {
        size_t bindex = (this->bpos_ + this->blen_) % bcapacity;
        size_t bspace = min(bcapacity - bindex, bcapacity - this->blen_);
        size_t n = min(sz - pos, bspace);
        memcpy(&this->bbuf_[bindex], &buf[pos], n);
        this->blen_ += n;
        pos += n;
    }

    if(pos > 0) 
    {
         wq_.notify_all();
     }

    if (pos == 0 && sz > 0) 
    {
        return -1;  // try again
    } 
    
    else 
    {
        return pos;
    }
}

// Largely taken from god eddie's notes from CS61
ssize_t bbuffer::read(char* buf, size_t sz) {
    spinlock_guard guard(lock_);

    waiter w;
     w.wait_until(wq_, [&] () {
         return (this->blen_ > 0 || write_closed_);
     }, guard);

    size_t pos = 0;
    while (pos < sz && this->blen_ > 0) {
        size_t bspace = min(this->blen_, bcapacity - this->bpos_);
        size_t n = min(sz - pos, bspace);
        memcpy(&buf[pos], &this->bbuf_[this->bpos_], n);
        this->bpos_ = (this->bpos_ + n) % bcapacity;
        this->blen_ -= n;
        pos += n;
    }

    if(pos > 0) 
    {
         wq_.notify_all();
     }

    if (pos == 0 && sz > 0 && !this->write_closed_) 
    {
        return -1;  // try again
    } 
    
    else 
    {
        return pos;
    }
}