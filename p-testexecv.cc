#include "u-lib.hh"

int str_to_int(const char* s) {
    int result = 0;
    while (*s) {
        result = result * 10 + (*s - '0');
        s++;
    }
    return result;
}

void process_main(int argc, char** argv) {

    // THE PURPOSE OF THIS TEST IS TO MAKE SURE ARGUMENT PASSING WORKS
    int count = 0;

    // If execv-ed, parse count and verify that argument passing works
    if (argc == 3) {
        count = str_to_int(argv[1]);
        assert_memeq(argv[0], "testexecv", 8);
        assert(count >= 1 && count <= 240);
        assert_memeq(argv[2], "argtest", 7);
    }

    if (count == 240) {
        console_printf(CS_SUCCESS "testexecv succeeded!\n");
        sys_exit(0);
    }

    // Prepare next argument list
    char counter_arg[16];
    snprintf(counter_arg, sizeof(counter_arg), "%d", count + 1);
    const char* args[] = {
        "testexecv",
        counter_arg,
        "argtest",
        nullptr
    };

    // Print progress
    sys_write(1, "Calling execv number: ", 22);
    sys_write(1, counter_arg, strlen(counter_arg));
    sys_write(1, "\n", 1);

    // Exec self
    int r = sys_execv("testexecv", args);
    assert_eq(r, 0);

    sys_exit(1); // Should never reach here
}