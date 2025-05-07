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

void process_main()
{
    int fd = sys_open("test000.tga", OF_READ | OF_WRITE);
    assert_gt(fd, 0);
    console_printf("%d\n", fd);


    uint8_t meta[51];

    // sys_lseek(fd, 16, LSEEK_SET);
    sys_read(fd, (char*) &meta, 50);

    int meta_data_size = (int) meta[0];
    int height = (int) (meta[12] | (meta[13] << 8));

    console_printf("Height: %d\n", height);
    console_printf("Meta data size: %d\n", meta_data_size);
    // assert(header.depth == 24);

    console_printf("First: %x\n", meta[0]);
    // console_printf("Second: %hu\n", width);

    // sys_lseek(fd, 822, LSEEK_SET);

    sys_vga_test();
    while (true) {
    }
}