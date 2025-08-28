#include <ublksrv.h>
#include <ublksrv_utils.h>
#include <string.h>
#include <iostream>
#include <memory>

using namespace std;

static char jbuf[4096];

class ublksrv_ctrl_dev_deleter {
public:
    void operator()(ublksrv_ctrl_dev* dev) {
        ublksrv_ctrl_deinit(dev);
    }
};

using ublksrv_ctrl_dev_ptr = unique_ptr<ublksrv_ctrl_dev, ublksrv_ctrl_dev_deleter>;

static int demo_init_tgt(struct ublksrv_dev* dev, int type, int /*argc*/,
                         char** /*argv*/) {
    auto& info = *ublksrv_ctrl_get_dev_info(ublksrv_get_ctrl_dev(dev));
    auto& tgt = dev->tgt;

    struct ublksrv_tgt_base_json tgt_json = {
        .type = type
    };

    strcpy(tgt_json.name, "null");

    tgt_json.dev_size = tgt.dev_size = 144UL * 1024 * 1024 * 1024;
    tgt.tgt_ring_depth = info.queue_depth;
    tgt.nr_fds = 0;

    ublksrv_json_write_dev_info(ublksrv_get_ctrl_dev(dev), jbuf, sizeof jbuf);
    ublksrv_json_write_target_base_info(jbuf, sizeof jbuf, &tgt_json);

    return 0;
}

static int demo_handle_io_async(const struct ublksrv_queue* q,
                                const struct ublk_io_data* data) {
    const struct ublksrv_io_desc* iod = data->iod;

    ublksrv_complete_io(q, data->tag, iod->nr_sectors << 9);

    return 0;
}

static const struct ublksrv_tgt_type demo_tgt_type = {
    .handle_io_async = demo_handle_io_async,
    .init_tgt = demo_init_tgt,
    .name =  "demo_null",
};

static void ublk_check() {
    ublksrv_dev_data dev_data = {
        .dev_id = -1,
        .max_io_buf_bytes = DEF_BUF_SIZE,
        .nr_hw_queues = DEF_NR_HW_QUEUES,
        .queue_depth = DEF_QD,
        .tgt_type = "demo_null",
        .tgt_ops = &demo_tgt_type,
        .run_dir = ublksrv_get_pid_dir(),
        .flags = 0,
    };

    ublksrv_ctrl_dev_ptr dev{ublksrv_ctrl_init(&dev_data)};
    if (!dev)
        throw runtime_error("ublksrv_ctrl_init failed");

    // FIXME
}

int main() {
    try {
        ublk_check();
    } catch (const exception& e) {
        cerr << "Exception: " << e.what() << endl;
    }

    return 0;
}
