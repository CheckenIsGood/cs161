CS 161 Problem Set 5 Answers
============================
Leave your name out of this file. Put collaboration notes and credit in
`pset5collab.md`.

Answers to written questions
----------------------------


# Threads Synchronization Plan
We have a leader thread (first thread that is created in fork) whose datafields will be shared among the other threads of the same proc. In other words, shared process state components like the per process file descriptor table, pagetable, etc. are all stored by the leader thread and all the other threads in the same process use the leader thread's shared state components. The shared process state components are protected by the ptable_lock. The file descriptor table is also protected by a per process file descriptor lock and each file descriptor is also protected by its own file descriptor lock.

# Project

### 1. What was your goal?

The goal of my project was to implement VGA graphics and also support the TGA file type so I could put a TGA file in my diskfs and be able to display it. The ultimate goal of the project was being able to display a picture of Professor Mickens' face on Chickadee.

### 2. What’s your design?

In my `k-vga.cc` file, I have a several arrays that store the unique configuration data that I can send to the VGA via port-mapped IO (I use `outb()`) to set the video mode. Also in my `k-vga.cc` file, I created the `vga_set_mode(unsigned char* regs)` function which takes in one of the arrays with the configuration data and actually calls `outb()` to the VGA regs and sets up the video mode. I also have a targa file parser that looks through the targa file metadata, color map, and sets up the correct color palette for the image (also by using port-mapped IO). Afterwards, users can just input a targa image file they opened and use the display syscall I implemented to have Chickadee display the image. I also evolved my project a bit to play an animation.

### 3. What code did you write (what files and functions)?

- `k-vga.cc` and `k-vga.hh`
Has several arrays containing video mode configuration data, `vga_set_mode(unsigned char* regs)` function which actually sends configuration data to VGA and sets up given video mode, and macros like `set_vga_plane.`

- `kernel.hh` and `kernel.cc`
Defined TGA metadata struct `tga_header` in `kernel.hh`. In `kernel.cc`, I have a basic `syscall_vga_test` which tests VGA functionality, `syscall_display` which takes filedescriptor value of image file we want to display and displays it, `tga_parser(int fd, pid_t pid_)` function that parses TGA file, `vga_clear_screen()` function which clears the screen, and `vga_plot_pixel(int x, int y, unsigned short color)` which plots an individual pixel.

- `p-animation.cc`
Plays a looping animation.

- `p-badapple.cc`
Plays first minute of Bad Apple (famous video animation that is ported by nerds to random stuff like calculators and homebrew OSes hahaha).

- `p-vga.cc`
Displays an image of god.

### 4. What challenges did you encounter?

I ran into a lot of problems. First, actually learning how to interact with VGA was a problem and figuring out how to set color palettes took a while (had to look on OSDev a lot). After that, parsing my TGA file was the most difficult as I had weird compiler issues, weird formatting, etc. At one point, I was looking at my TGA file byte by byte to see what was going on. Reading the color map and using that to set my color palette also took a wihle because TGA is special and stores values via BGR not RGB (took a while to debug).

### 5. How can we test your work?

You can run `p-animation.cc` to see a looping animation, `p-badapple.cc` to see a short video, and `p-vga.cc` to actually see a TGA file being displayed. In order to run my code in a graphical context, you have to install XQuartz (if on Mac or Windows), add "-e DISPLAY=docker.for.mac.host.internal:0" to your run-docker command (for Mac) (or add the env variable to the Dockerfile and rebuild it), and then make sure XQuartz allows connections from network clients (also do run xhost +localhost to let local containers to connect). Here is a youtube link of my code working cause it took a while for me to set this up: https://www.youtube.com/watch?v=IkAjcODcHQk


Grading notes
-------------
