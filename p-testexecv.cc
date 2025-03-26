#include "u-lib.hh"

#define DECAY 2

void process_main(int argc, char** argv)
{
    pid_t p = sys_getpid();

    if (p == 2)
    {
        sys_consoletype(CONSOLE_MEMVIEWER);
    }

    else
    {
        // Check argument passing
        assert(argc == p);
        assert_memeq(argv[0], "testexecv", 9);
        for (int i = 2; i <= p; i++)
        {
            assert((int)strlen(argv[i - 1]) == i);
            for (int j = 0; j < i; j++)
            {
                if (i <= 9) assert(*(argv[i - 1] + j) == '0' + i);
                else assert(*(argv[i - 1] + j) == 'a' + i - 10);
            }
        }
    }

    if (p == 2)
    {
        while (sys_fork() < 0);
        while (sys_fork() < 0);
    }
    else
    {
        do
        {
            if (rand(1, 10) <= DECAY) break;
        } while (sys_fork() < 0);
    }

    p = sys_getpid();
    if (p == 2)
    {
        while (true);
    }
    else if (p > 15)
    {
        sys_exit(0);
    }

    // Generate arguments according to pid
    const char* args[] = {
        "testexecv", "22", "333", "4444", "55555", "666666", "7777777", "88888888", "999999999", "aaaaaaaaaa", "bbbbbbbbbbb", "cccccccccccc", "ddddddddddddd", "eeeeeeeeeeeeee", "fffffffffffffff", nullptr
    };
    args[p] = nullptr;

    do
    {
        if (rand(1, 10) <= DECAY) break;
    } while (sys_execv("testexecv", args) < 0);
    
    sys_exit(0);
}