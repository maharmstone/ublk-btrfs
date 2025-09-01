#include <fcntl.h>
#include <ublksrv.h>
#include <ublksrv_utils.h>
#include <string.h>
#include <iostream>
#include <memory>
#include <vector>
#include <mutex>
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

struct demo_queue_info {
    const struct ublksrv_dev* dev;
    int qid;
    jthread thread;
};

static const unsigned int SECTOR_SHIFT = 9; // 512-byte sectors

static char jbuf[4096];
static mutex jbuf_lock;
static ublksrv_ctrl_dev_ptr ctrl_dev;
static optional<mmap> mapping;

static int demo_init_tgt(struct ublksrv_dev* dev, int type, int /*argc*/,
                         char** /*argv*/) {
    auto& info = *ublksrv_ctrl_get_dev_info(ublksrv_get_ctrl_dev(dev));
    auto& tgt = dev->tgt;

    struct ublksrv_tgt_base_json tgt_json = {
        .type = type
    };

    strcpy(tgt_json.name, "null");

    tgt_json.dev_size = tgt.dev_size = mapping->length;
    tgt.tgt_ring_depth = info.queue_depth;
    tgt.nr_fds = 0;

    ublksrv_json_write_dev_info(ublksrv_get_ctrl_dev(dev), jbuf, sizeof jbuf);
    ublksrv_json_write_target_base_info(jbuf, sizeof jbuf, &tgt_json);

    return 0;
}

static int do_read(const struct ublksrv_queue& q, const struct ublk_io_data& data) {
    auto& iod = *data.iod;
    unsigned int num_sectors = iod.nr_sectors;

    print("demo_handle_io_async: UBLK_IO_OP_READ ({:x}, {:x})\n",
          iod.start_sector, iod.nr_sectors, iod.addr);

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

static void do_check() {
    auto pid = fork();

    if (pid == -1)
        throw formatted_error("fork failed (errno {})", errno);
    else if (pid != 0) {
        int status;

        if (waitpid(pid, &status, 0) == -1)
            throw formatted_error("waitpid failed (errno {})", errno);

        if (status == 0)
            print("btrfs check passed\n");
        else
            print("btrfs check returned {}\n", status);

        return;
    }

    vector<string> argv;

    argv.push_back("/sbin/btrfs");
    argv.push_back("check");
    argv.push_back("--force");
    argv.push_back("file"); // FIXME

    vector<char*> argv2;

    for (auto& s : argv) {
        argv2.push_back((char*)s.c_str());
    }
    argv2.push_back(nullptr);

    // FIXME - replace stderr with pipe, and only print output if we fail?

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

static int do_write(const struct ublksrv_queue& q, const struct ublk_io_data& data) {
    auto& iod = *data.iod;
    unsigned int num_sectors = iod.nr_sectors;

    print("demo_handle_io_async: UBLK_IO_OP_WRITE ({:x}, {:x})\n",
          iod.start_sector, iod.nr_sectors, iod.addr);

    if (iod.start_sector >= mapping->length >> SECTOR_SHIFT)
        num_sectors = 0;
    else if (iod.start_sector + iod.nr_sectors >= mapping->length >> SECTOR_SHIFT)
        num_sectors = (mapping->length >> SECTOR_SHIFT) - iod.start_sector;

    if (num_sectors == 0) {
        ublksrv_complete_io(&q, data.tag, 0);
        return 0;
    }

    // FIXME - recognize and handle partitions

    // FIXME - block here if superblock currently being checked

    memcpy(mapping->get_span().data() + (iod.start_sector << SECTOR_SHIFT),
           (void*)iod.addr, num_sectors << SECTOR_SHIFT);

    // FIXME - only if btrfs magic still in superblock?
    if (iod.start_sector << SECTOR_SHIFT <= btrfs::superblock_addrs[0] &&
        (iod.start_sector + iod.nr_sectors) << SECTOR_SHIFT > btrfs::superblock_addrs[0]) {
        do_check();
    }

    ublksrv_complete_io(&q, data.tag, num_sectors << SECTOR_SHIFT);

    return num_sectors << SECTOR_SHIFT;
}

static int demo_handle_io_async(const struct ublksrv_queue* q,
                                const struct ublk_io_data* data) {
    auto& iod = *data->iod;

    switch (ublksrv_get_op(&iod)) {
        case UBLK_IO_OP_READ:
            return do_read(*q, *data);

        case UBLK_IO_OP_WRITE:
            return do_write(*q, *data);

        case UBLK_IO_OP_DISCARD:
            print("demo_handle_io_async: UBLK_IO_OP_DISCARD ({:x}, {:x})\n",
                  iod.start_sector, iod.nr_sectors);
            break;

        case UBLK_IO_OP_FLUSH:
            print("demo_handle_io_async: UBLK_IO_OP_FLUSH\n");
            break;

        default:
            print("demo_handle_io_async: unrecognized op {}\n", ublksrv_get_op(&iod));
            ublksrv_complete_io(q, data->tag, -EINVAL);
            return -EINVAL;
    }

    ublksrv_complete_io(q, data->tag, iod.nr_sectors << SECTOR_SHIFT);

    return iod.nr_sectors << SECTOR_SHIFT;
}

static const struct ublksrv_tgt_type demo_tgt_type = {
    .handle_io_async = demo_handle_io_async,
    .init_tgt = demo_init_tgt,
    .name =  "demo_null",
};

static void demo_null_io_handler_fn(demo_queue_info* info) {
    auto& dev = *info->dev;
    auto& dinfo = *ublksrv_ctrl_get_dev_info(ublksrv_get_ctrl_dev(&dev));

    sched_setscheduler(getpid(), SCHED_RR, nullptr);

    {
        lock_guard lock(jbuf_lock);

        ublksrv_json_write_queue_info(ublksrv_get_ctrl_dev(&dev), jbuf,
                                      sizeof(jbuf), info->qid, ublksrv_gettid());
        ublksrv_tgt_store_dev_data(&dev, jbuf);
    }

    ublksrv_queue_ptr q{ublksrv_queue_init(&dev, info->qid, nullptr)};
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

static void demo_null_set_parameters(struct ublksrv_ctrl_dev* cdev,
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

static void start_daemon(ublksrv_ctrl_dev* ctrl_dev) {
    // FIXME - unprivileged ublksrv_ctrl_get_affinity returns EACCES without a wait(??)
    this_thread::sleep_for(chrono::milliseconds{100});

    if (auto ret = ublksrv_ctrl_get_affinity(ctrl_dev); ret < 0)
        throw formatted_error("ublksrv_ctrl_get_affinity failed (error {})", ret);

    const auto& dinfo = *ublksrv_ctrl_get_dev_info(ctrl_dev);
    vector<demo_queue_info> info_array;

    info_array.resize(dinfo.nr_hw_queues);

    ublksrv_dev_ptr dev{ublksrv_dev_init(ctrl_dev)};
    if (!dev)
        throw runtime_error("ublksrv_dev_init failed");

    for (unsigned int i = 0; i < dinfo.nr_hw_queues; i++) {
        info_array[i].dev = dev.get();
        info_array[i].qid = i;

        info_array[i].thread = jthread(demo_null_io_handler_fn, &info_array[i]);
    }

    demo_null_set_parameters(ctrl_dev, dev.get());

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

static void ublk_check() {
    ublksrv_dev_data dev_data = {
        .dev_id = -1,
        .max_io_buf_bytes = DEF_BUF_SIZE,
        .nr_hw_queues = DEF_NR_HW_QUEUES,
        .queue_depth = DEF_QD,
        .tgt_type = "demo_null",
        .tgt_ops = &demo_tgt_type,
        .flags = UBLK_F_UNPRIVILEGED_DEV,
    };

    open_backing_file("file"); // FIXME - solicit name

    ctrl_dev.reset(ublksrv_ctrl_init(&dev_data));
    if (!ctrl_dev)
        throw runtime_error("ublksrv_ctrl_init failed");

    if (signal(SIGTERM, sig_handler) == SIG_ERR)
        throw formatted_error("signal failed (errno {})", errno);

    if (signal(SIGINT, sig_handler) == SIG_ERR)
        throw formatted_error("signal failed (errno {})", errno);

    if (auto ret = ublksrv_ctrl_add_dev(ctrl_dev.get()); ret < 0)
        throw formatted_error("ublksrv_ctrl_add_dev failed (error {})", ret);

    try {
        start_daemon(ctrl_dev.get());
    } catch (...) {
        ublksrv_ctrl_del_dev(ctrl_dev.get());
        throw;
    }

    ublksrv_ctrl_del_dev(ctrl_dev.get());
}

int main() {
    try {
        ublk_check();
    } catch (const exception& e) {
        cerr << "Exception: " << e.what() << endl;
    }

    return 0;
}
