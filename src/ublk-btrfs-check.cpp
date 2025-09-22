#include <fcntl.h>
#include <getopt.h>
#include <linux/sched.h>
#include <poll.h>
#include <ublksrv.h>
#include <ublksrv_utils.h>
#include <string.h>
#include <iostream>
#include <memory>
#include <vector>
#include <mutex>
#include <shared_mutex>
#include <thread>
#include <format>
#include <print>

import formatted_error;
import mmap;
import cxxbtrfs;

using namespace std;

class ublksrv_ctrl_dev_deleter {
public:
    void operator()(ublksrv_ctrl_dev* dev) {
        ublksrv_ctrl_deinit(dev);
    }
};

using ublksrv_ctrl_dev_ptr = unique_ptr<ublksrv_ctrl_dev, ublksrv_ctrl_dev_deleter>;

class ublksrv_dev_deleter {
public:
    void operator()(const ublksrv_dev* dev) {
        ublksrv_dev_deinit(dev);
    }
};

using ublksrv_dev_ptr = unique_ptr<const ublksrv_dev, ublksrv_dev_deleter>;

class ublksrv_queue_deleter {
public:
    void operator()(const ublksrv_queue* q) {
        ublksrv_queue_deinit(q);
    }
};

using ublksrv_queue_ptr = unique_ptr<const ublksrv_queue, ublksrv_queue_deleter>;

struct queue_info {
    const struct ublksrv_dev* dev;
    int qid;
    jthread thread;
};

struct run_params {
    bool do_trace;
    bool do_reflink;
    string_view filename;
};

static const unsigned int SECTOR_SHIFT = 9; // 512-byte sectors

static char jbuf[4096];
static mutex jbuf_lock;
static ublksrv_ctrl_dev_ptr ctrl_dev;
static optional<mmap> mapping;
static shared_mutex write_mutex;

static int init_tgt(struct ublksrv_dev* dev, int type, int /*argc*/,
                    char** /*argv*/) {
    auto& info = *ublksrv_ctrl_get_dev_info(ublksrv_get_ctrl_dev(dev));
    auto& tgt = dev->tgt;

    struct ublksrv_tgt_base_json tgt_json = {
        .type = type
    };

    strcpy(tgt_json.name, "ublk-btrfs-check");

    tgt_json.dev_size = tgt.dev_size = mapping->length;
    tgt.tgt_ring_depth = info.queue_depth;
    tgt.nr_fds = 0;

    ublksrv_json_write_dev_info(ublksrv_get_ctrl_dev(dev), jbuf, sizeof jbuf);
    ublksrv_json_write_target_base_info(jbuf, sizeof jbuf, &tgt_json);

    return 0;
}

static int do_read(const struct ublksrv_queue& q, const struct ublk_io_data& data,
                   const run_params& params) {
    auto& iod = *data.iod;
    unsigned int num_sectors = iod.nr_sectors;

    if (params.do_trace)
        print("UBLK_IO_OP_READ ({:x}, {:x})\n", iod.start_sector, iod.nr_sectors);

    if (iod.start_sector >= mapping->length >> SECTOR_SHIFT)
        num_sectors = 0;
    else if (iod.start_sector + iod.nr_sectors >= mapping->length >> SECTOR_SHIFT)
        num_sectors = (mapping->length >> SECTOR_SHIFT) - iod.start_sector;

    memcpy((void*)iod.addr,
           mapping->get_span().data() + (iod.start_sector << SECTOR_SHIFT),
           num_sectors << SECTOR_SHIFT);

    ublksrv_complete_io(&q, data.tag, num_sectors << SECTOR_SHIFT);

    return num_sectors << SECTOR_SHIFT;
}

static pid_t sys_clone3(clone_args* args) {
    return syscall(__NR_clone3, args, sizeof(clone_args));
}

static void do_check(uint64_t generation, const run_params& params) {
    int pipefds[2];

    if (auto ret = pipe(pipefds); ret < 0)
        throw formatted_error("pipe failed (errno {})", errno);

    clone_args ca;
    int pidfd = 0;
    pid_t parent_tid = -1;

    memset(&ca, 0, sizeof(ca));

    ca.parent_tid = (uint64_t)(uintptr_t)&parent_tid;
    ca.pidfd = (uint64_t)(uintptr_t)&pidfd;
    ca.flags = CLONE_PARENT_SETTID | CLONE_PIDFD;
    ca.exit_signal = SIGCHLD;

    auto pid = sys_clone3(&ca);

    if (pid == -1)
        throw formatted_error("clone3 failed (errno {})", errno);
    else if (pid != 0) {
        siginfo_t siginfo;
        string check_stderr;

        close(pipefds[1]);

        // FIXME - read from stderr pipe (pipefds[0])

        while (true) {
            array<pollfd, 2> fds;

            fds[0].fd = pipefds[0];
            fds[0].events = POLLIN;
            fds[0].revents = 0;

            fds[1].fd = pidfd;
            fds[1].events = POLLIN;
            fds[1].revents = 0;

            auto ret = poll(fds.data(), fds.size(), -1);

            if (ret == -1) {
                if (errno == EINTR)
                    continue;
                else {
                    auto e = errno;
                    close(pipefds[0]);
                    close(pidfd);
                    throw formatted_error("poll failed (errno {})", e);
                }
            }

            if (fds[0].revents & POLLIN) {
                char buf[4096];

                ret = read(pipefds[0], buf, sizeof(buf));
                if (ret < 0) {
                    if (errno == EINTR)
                        continue;
                    else {
                        auto e = errno;
                        close(pipefds[0]);
                        close(pidfd);
                        throw formatted_error("read failed (errno {})", e);
                    }
                }

                check_stderr.append(string_view(buf, ret));

                continue;
            }

            if (fds[1].revents & POLLIN)
                break;
        }

        if (waitid(P_PIDFD, pidfd, &siginfo, WEXITED) < 0) { // already dead, should return immediately
            auto e = errno;
            close(pipefds[0]);
            close(pidfd);
            throw formatted_error("waitid failed (errno {})", e);
        }

        if (siginfo.si_status == 0)
            print("btrfs check passed (generation {:x})\n", generation);
        else {
            print(stderr, "{}", check_stderr);
            print(stderr, "btrfs check returned {} (generation {:x})\n",
                  siginfo.si_status, generation);
        }

        close(pipefds[0]);
        close(pidfd);

        return;
    }

    close(pipefds[0]);

    vector<string> argv;

    argv.emplace_back("/sbin/btrfs");
    argv.emplace_back("check");
    argv.emplace_back("--force");
    argv.emplace_back(params.filename);

    vector<char*> argv2;

    for (auto& s : argv) {
        argv2.push_back((char*)s.c_str());
    }
    argv2.push_back(nullptr);

    if (dup3(pipefds[1], STDERR_FILENO, 0) < 0) {
        auto e = errno;
        close(pipefds[1]);
        throw formatted_error("dup3 failed for pipe (errno {})", e);
    }

    // replace stdout with /dev/null
    auto devnull = open("/dev/null", O_WRONLY);
    if (devnull < 0)
        throw formatted_error("open failed for /dev/null (errno {})", errno);

    if (dup3(devnull, STDOUT_FILENO, 0) < 0) {
        auto e = errno;
        close(devnull);
        throw formatted_error("dup3 failed for /dev/null (errno {})", e);
    }

    close(devnull);

    if (execve(argv[0].c_str(), (char**)argv2.data(), nullptr)) {
        print(stderr, "execve failed (errno {})\n", errno);
        exit(1);
    }

    // doesn't return
}

static void do_reflink_copy() {
    // FIXME
    cerr << "FIXME - do_reflink_copy" << endl;
}

static int do_write(const struct ublksrv_queue& q, const struct ublk_io_data& data,
                    const run_params& params) {
    auto& iod = *data.iod;
    unsigned int num_sectors = iod.nr_sectors;

    if (params.do_trace)
        print("UBLK_IO_OP_WRITE ({:x}, {:x})\n", iod.start_sector, iod.nr_sectors);

    if (iod.start_sector >= mapping->length >> SECTOR_SHIFT)
        num_sectors = 0;
    else if (iod.start_sector + iod.nr_sectors >= mapping->length >> SECTOR_SHIFT)
        num_sectors = (mapping->length >> SECTOR_SHIFT) - iod.start_sector;

    if (num_sectors == 0) {
        ublksrv_complete_io(&q, data.tag, 0);
        return 0;
    }

    // FIXME - recognize and handle partitions?

    auto write = [](auto& iod, unsigned int num_sectors) {
        memcpy(mapping->get_span().data() + (iod.start_sector << SECTOR_SHIFT),
               (void*)iod.addr, num_sectors << SECTOR_SHIFT);
    };

    if (iod.start_sector << SECTOR_SHIFT <= btrfs::superblock_addrs[0] &&
        (iod.start_sector + iod.nr_sectors) << SECTOR_SHIFT > btrfs::superblock_addrs[0]) {
        unique_lock lock(write_mutex);

        write(iod, num_sectors);

        auto& sb = *(btrfs::super_block*)(uintptr_t)(iod.addr + btrfs::superblock_addrs[0] - (iod.start_sector << SECTOR_SHIFT));

        // ignore if btrfs magic no longer in superblock
        if (sb.magic == btrfs::MAGIC) {
            do_check(sb.generation, params); // FIXME - option for this

            if (params.do_reflink)
                do_reflink_copy();
        }

        ublksrv_complete_io(&q, data.tag, num_sectors << SECTOR_SHIFT);
    } else {
        shared_lock lock(write_mutex);

        write(iod, num_sectors);

        ublksrv_complete_io(&q, data.tag, num_sectors << SECTOR_SHIFT);
    }

    return num_sectors << SECTOR_SHIFT;
}

static int handle_io_async(const struct ublksrv_queue* q,
                           const struct ublk_io_data* data) {
    auto& iod = *data->iod;
    const auto& params = *(run_params*)q->private_data;

    switch (ublksrv_get_op(&iod)) {
        case UBLK_IO_OP_READ:
            return do_read(*q, *data, params);

        case UBLK_IO_OP_WRITE:
            return do_write(*q, *data, params);

        case UBLK_IO_OP_DISCARD:
            if (params.do_trace) {
                print("handle_io_async: UBLK_IO_OP_DISCARD ({:x}, {:x})\n",
                      iod.start_sector, iod.nr_sectors);
            }
            break;

        case UBLK_IO_OP_FLUSH:
            if (params.do_trace)
                print("handle_io_async: UBLK_IO_OP_FLUSH\n");
            break;

        default:
            print(stderr, "handle_io_async: unrecognized op {}\n",
                  ublksrv_get_op(&iod));
            ublksrv_complete_io(q, data->tag, -EINVAL);
            return -EINVAL;
    }

    ublksrv_complete_io(q, data->tag, iod.nr_sectors << SECTOR_SHIFT);

    return iod.nr_sectors << SECTOR_SHIFT;
}

static const struct ublksrv_tgt_type tgt_type = {
    .handle_io_async = handle_io_async,
    .init_tgt = init_tgt,
    .name =  "ublk-btrfs-check",
};

static void io_handler_fn(queue_info* info, const run_params& params) {
    auto& dev = *info->dev;
    auto& dinfo = *ublksrv_ctrl_get_dev_info(ublksrv_get_ctrl_dev(&dev));

    sched_setscheduler(getpid(), SCHED_RR, nullptr);

    {
        lock_guard lock(jbuf_lock);

        ublksrv_json_write_queue_info(ublksrv_get_ctrl_dev(&dev), jbuf,
                                      sizeof(jbuf), info->qid, ublksrv_gettid());
        ublksrv_tgt_store_dev_data(&dev, jbuf);
    }

    ublksrv_queue_ptr q{ublksrv_queue_init(&dev, info->qid, (void*)&params)};
    if (!q) {
        // FIXME - throw exception and return it to other thread
        print(stderr, "ublk dev {} queue {} init queue failed\n", dinfo.dev_id, info->qid);
        return;
    }

    print("tid {}: ublk dev {} queue {} started\n", ublksrv_gettid(),
          dinfo.dev_id, q->q_id);

    while (true) {
        if (ublksrv_process_io(q.get()) < 0)
            break;
    }

    print("ublk dev {} queue {} exited\n", dinfo.dev_id, q->q_id);
}

static void set_parameters(struct ublksrv_ctrl_dev* cdev,
                           const struct ublksrv_dev* dev) {
    auto& info = *ublksrv_ctrl_get_dev_info(cdev);
    struct ublk_params p = {
        .types = UBLK_PARAM_TYPE_BASIC | UBLK_PARAM_TYPE_DISCARD,
        .basic = {
            .logical_bs_shift	= SECTOR_SHIFT,
            .physical_bs_shift	= 12,
            .io_opt_shift		= 12,
            .io_min_shift		= SECTOR_SHIFT,
            .max_sectors		= info.max_io_buf_bytes >> SECTOR_SHIFT,
            .dev_sectors		= dev->tgt.dev_size >> SECTOR_SHIFT,
        },
        .discard = {
            .discard_granularity = 1 << SECTOR_SHIFT,
            .max_discard_sectors = UINT_MAX >> SECTOR_SHIFT,
            .max_discard_segments = 1,
        }
    };

    {
        lock_guard lock(jbuf_lock);

        ublksrv_json_write_params(&p, jbuf, sizeof(jbuf));
    }

    if (auto ret = ublksrv_ctrl_set_params(cdev, &p); ret)
        throw formatted_error("dev {} set basic parameter failed {}", info.dev_id, ret);
}

static void start_daemon(ublksrv_ctrl_dev* ctrl_dev, const run_params& params) {
    // FIXME - unprivileged ublksrv_ctrl_get_affinity returns EACCES without a wait(??)
    this_thread::sleep_for(chrono::milliseconds{100});

    if (auto ret = ublksrv_ctrl_get_affinity(ctrl_dev); ret < 0)
        throw formatted_error("ublksrv_ctrl_get_affinity failed (error {})", ret);

    const auto& dinfo = *ublksrv_ctrl_get_dev_info(ctrl_dev);
    vector<queue_info> info_array;

    info_array.resize(dinfo.nr_hw_queues);

    ublksrv_dev_ptr dev{ublksrv_dev_init(ctrl_dev)};
    if (!dev)
        throw runtime_error("ublksrv_dev_init failed");

    for (unsigned int i = 0; i < dinfo.nr_hw_queues; i++) {
        info_array[i].dev = dev.get();
        info_array[i].qid = i;

        info_array[i].thread = jthread(io_handler_fn, &info_array[i], params);
    }

    set_parameters(ctrl_dev, dev.get());

    if (auto ret = ublksrv_ctrl_start_dev(ctrl_dev, getpid()); ret < 0)
        throw formatted_error("ublksrv_ctrl_start_dev failed (error {})", ret);

    ublksrv_ctrl_get_info(ctrl_dev);
    ublksrv_ctrl_dump(ctrl_dev, jbuf);

    for (auto& a : info_array) {
        a.thread.join();
    }
}

static void sig_handler(int) {
    ublksrv_ctrl_stop_dev(ctrl_dev.get());
}

static void open_backing_file(const char* fn) {
    auto fd = open(fn, O_RDWR);
    if (fd < 0)
        throw formatted_error("{}: open failed (errno {})", fn, errno);

    try {
        mapping.emplace(fd);
    } catch (...) {
        close(fd);
        throw;
    }

    close(fd);
}

static void ublk_check(string_view fn, bool do_trace, bool do_reflink) {
    ublksrv_dev_data dev_data = {
        .dev_id = -1,
        .max_io_buf_bytes = DEF_BUF_SIZE,
        .nr_hw_queues = DEF_NR_HW_QUEUES,
        .queue_depth = DEF_QD,
        .tgt_type = "ublk-btrfs-check",
        .tgt_ops = &tgt_type,
        .flags = UBLK_F_UNPRIVILEGED_DEV,
    };

    open_backing_file(string{fn}.c_str());

    ctrl_dev.reset(ublksrv_ctrl_init(&dev_data));
    if (!ctrl_dev)
        throw runtime_error("ublksrv_ctrl_init failed");

    if (signal(SIGTERM, sig_handler) == SIG_ERR)
        throw formatted_error("signal failed (errno {})", errno);

    if (signal(SIGINT, sig_handler) == SIG_ERR)
        throw formatted_error("signal failed (errno {})", errno);

    run_params params;

    params.do_trace = do_trace;
    params.do_reflink = do_reflink;
    params.filename = fn;

    if (auto ret = ublksrv_ctrl_add_dev(ctrl_dev.get()); ret < 0)
        throw formatted_error("ublksrv_ctrl_add_dev failed (error {})", ret);

    try {
        start_daemon(ctrl_dev.get(), params);
    } catch (...) {
        ublksrv_ctrl_del_dev(ctrl_dev.get());
        throw;
    }

    ublksrv_ctrl_del_dev(ctrl_dev.get());
}

int main(int argc, char** argv) {
    bool do_trace = false, do_reflink = false, print_usage = false;

    while (true) {
        enum {
            GETOPT_VAL_HELP
        };

        static const option long_opts[] = {
            { "trace", no_argument, nullptr, 't' },
            { "reflink", no_argument, nullptr, 'r' },
            { "help", no_argument, nullptr, GETOPT_VAL_HELP },
            { nullptr, 0, nullptr, 0 }
        };

        auto c = getopt_long(argc, argv, "rt", long_opts, nullptr);
        if (c < 0)
            break;

        switch (c) {
            case 't':
                do_trace = true;
                break;
            case 'r':
                do_reflink = true;
                break;
            case GETOPT_VAL_HELP:
            case '?':
                print_usage = true;
                break;
        }
    }

    if (print_usage || optind != argc - 1) {
        fprintf(stderr, R"(Usage: ublk-btrfs-check [options] <file>

    Start a ublk device which does btrfs checking.

    Options:
    -t|--trace          print commands as we receive them
    -r|--reflink        create a reflink copy of the image every time we write
                        the superblock
    --help              print this screen
)");
        return 1;
    }

    auto fn = string_view(argv[optind]);

    try {
        ublk_check(fn, do_trace, do_reflink);
    } catch (const exception& e) {
        cerr << "Exception: " << e.what() << endl;
    }

    return 0;
}
