#include "vmlinux.h"
#include "bpf_helpers.h"
#include "bpf_core_read.h"
#include "bpf_tracing.h"
#include "io.h"
#include "core_fixes.bpf.h"
#include "ver.h"

#define MAX_ENTRIES     10240

extern __u32 LINUX_KERNEL_VERSION __kconfig;

struct piddata {
        char comm[TASK_COMM_LEN];
        u32 pid;
};

struct {
        __uint(type, BPF_MAP_TYPE_HASH);
        __uint(max_entries, MAX_ENTRIES);
        __type(key, struct request *);
        __type(value, struct piddata);
} infobyreq SEC(".maps");

struct stage {
        u64 insert;
        u64 issue;
        __u32 dev;
};

struct {
        __uint(type, BPF_MAP_TYPE_HASH);
        __uint(max_entries, MAX_ENTRIES);
        __type(key, u64);
        __type(value, struct stage);
} start SEC(".maps");

struct {
        __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
        __uint(key_size, sizeof(u32));
        __uint(value_size, sizeof(u32));
} events SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u32);
} filter_enable_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 128);
    __type(key, __u32);
    __type(value, __u32);
} pid_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 128);
    __type(key, __u32);
    __type(value, __u32);
} vdx_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 128);
    __type(key, __u32);
    __type(value, __u32);
} gt_map SEC(".maps");

static int goless(s64 val)
{
        __u32 key = 0;
        __u32 *en = NULL;
        en = bpf_map_lookup_elem(&filter_enable_map, &key);
        if (en) {
                if (*en == 3) {
			if (val < 0)
				return 1;
                        __u32 *val2 = NULL;
        		val2 = bpf_map_lookup_elem(&gt_map, &key);
			__u32 tmp  = (__u32)val / 1000000U;
                        if (val2) {
				if (*val2 > tmp)
					return 1;
			}
		}
	
        }
        return 0;
}

static int goskip(__u32 val, int type)
{
        __u32 key = 0;
        __u32 *en = NULL;
        en = bpf_map_lookup_elem(&filter_enable_map, &key);
        if (en) {
                if ((*en == 1) && (type == 1)) {
                        __u32 *val2 = NULL;
                        val2 = bpf_map_lookup_elem(&pid_map, &(val));
                        if (val2 == NULL)
				return 1;
		} else if ((*en == 2) && (type == 2)){
                        __u32 *val2 = NULL;
                        val2 = bpf_map_lookup_elem(&vdx_map, &(val));
                        if (val2 == NULL)
				return 1;
		}
	
        }
        return 0;
}

static __always_inline
int trace_pid(struct request *rq)
{
        u64 id = bpf_get_current_pid_tgid();
        struct piddata piddata = {};

        piddata.pid = id >> 32;
	if (goskip(piddata.pid, 1))
		return 0;
        bpf_get_current_comm(&piddata.comm, TASK_COMM_LEN);
        bpf_map_update_elem(&infobyreq, &rq, &piddata, 0);


        return 0;
}

SEC("kprobe/blk_start_request")
int bpf_prog1(struct pt_regs *ctx)
{
        return trace_pid((void*)ctx->di);
}
#if K514
SEC("kprobe/__blk_account_io_start")
int bpf_prog2(struct pt_regs *ctx)
{
	return trace_pid((void*)ctx->di);
}
#else
SEC("kprobe/blk_account_io_start")
int bpf_prog2(struct pt_regs *ctx)
{
	return trace_pid((void*)ctx->di);
}
#endif
SEC("kprobe/blk_account_io_merge_bio")
int bpf_prog6(struct pt_regs *ctx)
{
        return trace_pid((void*)ctx->di);
}

SEC("raw_tracepoint/block_rq_insert")
int bpf_prog4(u64 *ctx)
{
        struct stage *stagep = NULL;
        struct stage stage = {};
        u64 ts = bpf_ktime_get_ns();

	u64 key;
	struct request *rq;
#if K514
	key = (u64)(ctx[0]);
	rq = (struct request *)(ctx[0]);
#else
	key = (u64)(ctx[1]);
	rq = (struct request *)(ctx[1]);
#endif
        stagep = bpf_map_lookup_elem(&start, &key);

        if (!stagep) {
#if K514
		struct gendisk *disk = BPF_CORE_READ(rq, q, disk);
#else
                struct gendisk *disk = BPF_CORE_READ(rq, rq_disk);
#endif

                stage.dev = disk ? MKDEV(BPF_CORE_READ(disk, major),
                                BPF_CORE_READ(disk, first_minor)) : 0;
                if (goskip(stage.dev, 2))
                        return 0;
                stagep = &stage;
        }

        stagep->insert = ts;
        if (stagep == &stage)
                bpf_map_update_elem(&start, &rq, stagep, 0);

	return 0;
}

SEC("raw_tracepoint/block_rq_issue")
int bpf_prog5(u64 *ctx)
{
        struct stage *stagep = NULL;
        struct stage stage = {};
        u64 ts = bpf_ktime_get_ns();
	u64 key;
	struct request *rq;
#if K514
	key = (u64)(ctx[0]);
	rq = (struct request *)(ctx[0]);
#else
	key = (u64)(ctx[1]);
	rq = (struct request *)(ctx[1]);
#endif
        struct piddata *piddatap = NULL;
        piddatap = bpf_map_lookup_elem(&infobyreq, &rq);
        if (!piddatap) {
		trace_pid(rq);
	}
	
        stagep = bpf_map_lookup_elem(&start, &key);

        if (stagep == NULL) {
#if K514
		struct gendisk *disk = BPF_CORE_READ(rq, q, disk);
#else
                struct gendisk *disk = BPF_CORE_READ(rq, rq_disk);
#endif

                stage.dev = disk ? MKDEV(BPF_CORE_READ(disk, major),
                                BPF_CORE_READ(disk, first_minor)) : 0;
                if (goskip(stage.dev, 2))
                        return 0;
                stagep = &stage;
        }

        stagep->issue = ts;
        if (stagep == &stage)
                bpf_map_update_elem(&start, &rq, stagep, 0);

	return 0;
}

SEC("raw_tracepoint/block_rq_complete")
int bpf_prog3(u64 *ctx)
{
        u64 ts = bpf_ktime_get_ns();
        struct piddata *piddatap;
        struct event event = {};
        struct stage *stagep = NULL;
	s64 delta;
	struct request *rq;
	rq = (struct request *)(ctx[0]);

        stagep = bpf_map_lookup_elem(&start, &rq);
        if (stagep == NULL) {
                return 0;
	}
        delta = (s64)(ts - stagep->issue);
        if (delta < 0)
                goto cleanup;
        piddatap = bpf_map_lookup_elem(&infobyreq, &rq);
        if (!piddatap) {
                event.comm[0] = '?';
                //goto cleanup;
        } else {
                __builtin_memcpy(&event.comm, piddatap->comm,
                                TASK_COMM_LEN);
                event.pid = piddatap->pid;
        }
	if (goskip(event.pid, 1))
		return 0;
        event.delta = delta;
        if (BPF_CORE_READ(rq, q, elevator)) {
                if (!stagep->insert)
                        event.qdelta = -1; /* missed or don't insert entry */
                else
                        event.qdelta = stagep->issue - stagep->insert;
        }

	if (goless(delta)) {
		if (goless(event.qdelta)) {
                	goto cleanup;
		}
	}
        event.ts = ts;
        event.sector = BPF_CORE_READ(rq, __sector);
        event.len = ctx[2];
        event.cmd_flags = BPF_CORE_READ(rq, cmd_flags);
        event.dev = stagep->dev;
        bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &event,
                        sizeof(event));

cleanup:
        bpf_map_delete_elem(&start, &rq);
        bpf_map_delete_elem(&infobyreq, &rq);
	return 0;
}

char LICENSE[] SEC("license") = "GPL";
