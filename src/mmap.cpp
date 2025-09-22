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
    mmap(const char* fn);
    mmap(mmap&& other);
    ~mmap();

    span<uint8_t> get_span() const {
        return span((uint8_t*)addr, length);
    }

    void* addr;
    size_t length;
    int fd = 0;
};

mmap::mmap(const char* fn) {
    auto fd = open(fn, O_RDWR);
    if (fd < 0)
        throw formatted_error("{}: open failed (errno {})", fn, errno);

    struct stat st;
    if (fstat(fd, &st) == -1) {
        auto err = errno;
        close(fd);
        throw formatted_error("fstat failed (errno {})", err);
    }

    length = st.st_size;

    addr = ::mmap(nullptr, length, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    if (addr == MAP_FAILED) {
        auto err = errno;
        close(fd);
        throw formatted_error("mmap failed (errno {})", err);
    }

    this->fd = fd;
}

mmap::mmap(mmap&& other) {
    addr = other.addr;
    length = other.length;
    fd = other.fd;

    other.addr = nullptr;
    other.length = 0;
    other.fd = 0;
}

mmap::~mmap() {
    if (length > 0)
        munmap(addr, length);

    if (fd != 0)
        close(fd);
}
