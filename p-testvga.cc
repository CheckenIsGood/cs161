#include "u-lib.hh"

void int_to_str(int value, char* str, int width) {
    for (int i = width - 1; i >= 0; --i) {
        str[i] = '0' + (value % 10);
        value /= 10;
    }
    str[width] = '\0';
}

void process_main()
{

    int fd = sys_open("test000.tga", OF_READ | OF_WRITE);
    assert_gt(fd, 0);
    sys_display(fd);
    sys_close(fd);


    while (true) {
    }
}