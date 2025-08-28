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

class mmap {
public:
    mmap(const char* filename);
    mmap(mmap&& other);
    ~mmap();

    span<const uint8_t> get_span() const {
        return span((uint8_t*)addr, length);
    }

    void* addr;
    size_t length;
};

mmap::mmap(const char* filename) {
    auto fd = open(filename, O_RDONLY);
    if (fd < 0)
        throw formatted_error("{}: open failed (errno {})", filename, errno);

    struct stat st;
    if (fstat(fd, &st) == -1) {
        close(fd);
        throw formatted_error("{}: fstat failed (errno {})", filename, errno);
    }

    length = st.st_size;

    addr = ::mmap(nullptr, length, PROT_READ, MAP_SHARED, fd, 0);
    if (addr == MAP_FAILED) {
        close(fd);
        throw formatted_error("{}: mmap failed (errno {})", filename, errno);
    }

    close(fd);
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
