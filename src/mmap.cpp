module;

#include <span>
#include <stdint.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <unistd.h>
#include <errno.h>

export module mmap;

import formatted_error;

using namespace std;

export class mmap {
public:
    mmap(int fd);
    mmap(mmap&& other);
    ~mmap();

    span<uint8_t> get_span() const {
        return span((uint8_t*)addr, length);
    }

    void* addr;
    size_t length;
};

mmap::mmap(int fd) {
    struct stat st;
    if (fstat(fd, &st) == -1)
        throw formatted_error("fstat failed (errno {})", errno);

    length = st.st_size;

    addr = ::mmap(nullptr, length, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    if (addr == MAP_FAILED)
        throw formatted_error("mmap failed (errno {})", errno);
}

mmap::mmap(mmap&& other) {
    addr = other.addr;
    length = other.length;

    other.addr = nullptr;
    other.length = 0;
}

mmap::~mmap() {
    if (length > 0)
        munmap(addr, length);
}
