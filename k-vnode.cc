#include "kernel.hh"
#include "k-devices.hh"
#include "k-wait.hh"
#include "k-vnode.hh"


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