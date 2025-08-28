#include <ublksrv.h>
#include <ublksrv_utils.h>
#include <string.h>
#include <iostream>
#include <memory>
#include <vector>

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

struct demo_queue_info {
    const struct ublksrv_dev* dev;
    int qid;
    pthread_t thread;
};

static char jbuf[4096];
static pthread_mutex_t jbuf_lock;
static ublksrv_ctrl_dev_ptr ctrl_dev;

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

static void* demo_null_io_handler_fn(void* data) {
    auto& info = *(struct demo_queue_info*)data;
    const struct ublksrv_dev* dev = info.dev;
    auto& dinfo = *ublksrv_ctrl_get_dev_info(ublksrv_get_ctrl_dev(dev));
    auto dev_id = dinfo.dev_id;
    auto q_id = info.qid;
    const struct ublksrv_queue *q;

    sched_setscheduler(getpid(), SCHED_RR, nullptr);

    pthread_mutex_lock(&jbuf_lock);
    ublksrv_json_write_queue_info(ublksrv_get_ctrl_dev(dev), jbuf, sizeof jbuf,
                                  q_id, ublksrv_gettid());
    ublksrv_tgt_store_dev_data(dev, jbuf);
    pthread_mutex_unlock(&jbuf_lock);

    q = ublksrv_queue_init(dev, q_id, NULL);
    if (!q) {
        fprintf(stderr, "ublk dev %d queue %d init queue failed\n",
                dinfo.dev_id, q_id);
        return nullptr;
    }

    fprintf(stdout, "tid %d: ublk dev %d queue %d started\n",
            ublksrv_gettid(),
            dev_id, q->q_id);

    while (true) {
        if (ublksrv_process_io(q) < 0)
            break;
    }

    fprintf(stdout, "ublk dev %d queue %d exited\n", dev_id, q->q_id);
    ublksrv_queue_deinit(q);

    return nullptr;
}

static void demo_null_set_parameters(struct ublksrv_ctrl_dev* cdev,
                                     const struct ublksrv_dev* dev) {
    const struct ublksrv_ctrl_dev_info *info = ublksrv_ctrl_get_dev_info(cdev);
    struct ublk_params p = {
        .types = UBLK_PARAM_TYPE_BASIC,
        .basic = {
            .logical_bs_shift	= 9,
            .physical_bs_shift	= 12,
            .io_opt_shift		= 12,
            .io_min_shift		= 9,
            .max_sectors		= info->max_io_buf_bytes >> 9,
            .dev_sectors		= dev->tgt.dev_size >> 9,
        },
    };
    int ret;

    pthread_mutex_lock(&jbuf_lock);
    ublksrv_json_write_params(&p, jbuf, sizeof jbuf);
    pthread_mutex_unlock(&jbuf_lock);

    ret = ublksrv_ctrl_set_params(cdev, &p);
    if (ret)
        fprintf(stderr, "dev %d set basic parameter failed %d\n",
                info->dev_id, ret);
}

static void start_daemon(ublksrv_ctrl_dev* ctrl_dev) {
    if (auto ret = ublksrv_ctrl_get_affinity(ctrl_dev); ret < 0)
        throw runtime_error("ublksrv_ctrl_get_affinity failed"); // FIXME - include ret

    const auto& dinfo = *ublksrv_ctrl_get_dev_info(ctrl_dev);
    vector<demo_queue_info> info_array;

    info_array.resize(dinfo.nr_hw_queues);

    ublksrv_dev_ptr dev{ublksrv_dev_init(ctrl_dev)};
    if (!dev)
        throw runtime_error("ublksrv_dev_init failed");

    for (unsigned int i = 0; i < dinfo.nr_hw_queues; i++) {
        info_array[i].dev = dev.get();
        info_array[i].qid = i;
        pthread_create(&info_array[i].thread, nullptr, demo_null_io_handler_fn,
                       &info_array[i]);
    }

    demo_null_set_parameters(ctrl_dev, dev.get());

    if (auto ret = ublksrv_ctrl_start_dev(ctrl_dev, getpid()); ret < 0)
        throw runtime_error("ublksrv_ctrl_start_dev failed"); // FIXME - include ret

    ublksrv_ctrl_get_info(ctrl_dev);
    ublksrv_ctrl_dump(ctrl_dev, jbuf);

    for (auto& a : info_array) {
        void* thread_ret;

        pthread_join(a.thread, &thread_ret);
    }
}

static void sig_handler(int sig) {
    ublksrv_ctrl_stop_dev(ctrl_dev.get());
}

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

    ctrl_dev.reset(ublksrv_ctrl_init(&dev_data));
    if (!ctrl_dev)
        throw runtime_error("ublksrv_ctrl_init failed");

    if (signal(SIGTERM, sig_handler) == SIG_ERR)
        throw runtime_error("signal failed"); // FIXME - include errno

    if (signal(SIGINT, sig_handler) == SIG_ERR)
        throw runtime_error("signal failed"); // FIXME - include errno

    if (auto ret = ublksrv_ctrl_add_dev(ctrl_dev.get()); ret < 0)
        throw runtime_error("ublksrv_ctrl_add_dev failed"); // FIXME - include ret

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
