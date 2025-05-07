#include "u-lib.hh"

typedef struct {
    uint8_t id_length;
    uint8_t color_map_type;
    uint8_t image_type;
    uint8_t color_map[5];
    uint8_t x_origin[2];
    uint8_t y_origin[2];
    uint8_t width[2];
    uint8_t height[2];
    uint8_t depth;
    uint8_t descriptor;
} TGAHeader;

void int_to_str(int value, char* str, int width) {
    for (int i = width - 1; i >= 0; --i) {
        str[i] = '0' + (value % 10);
        value /= 10;
    }
    str[width] = '\0';
}

void process_main()
{
    for (int i = 0; i < 642; ++i) {
            char filename[24] = "zbadapple";
            int_to_str(i, filename + 9, 4);  // write 4-digit frame number at filename[9]
            filename[13] = '.';
            filename[14] = 't';
            filename[15] = 'g';
            filename[16] = 'a';
            filename[17] = '\0';

            int fd = sys_open(filename, OF_READ);
            assert_gt(fd, 0);

            sys_display(fd);
            sys_close(fd);

            sys_msleep(83);  // ~12 FPS
        }

    // int fd = sys_open("zanime000.tga", OF_READ | OF_WRITE);
    // assert_gt(fd, 0);
    // sys_display(fd);
    // sys_close(fd);


    while (true) {
    }
}