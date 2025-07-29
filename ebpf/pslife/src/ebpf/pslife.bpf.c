// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)

#include "vmlinux.h"
#include "bpf_helpers.h"
#include "bpf_core_read.h"
#include "bpf_tracing.h"
#include "pslife.h"

#define BPF_F_CURRENT_CPU 0xffffffffULL
#define DNAME_INLINE_LEN	32
#define TASK_COMM_LEN		16

struct {
	__uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
	__uint(key_size, sizeof(u32));
	__uint(value_size, sizeof(u32));
} perf_buf SEC(".maps");

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

int goskip(pid_t pid) 
{
	__u32 key = 0;
	__u32 *en = NULL;
	en = bpf_map_lookup_elem(&filter_enable_map, &key);
	if (en) {
		if (*en == 1) {
			__u32 *val2 = NULL;
	    		val2 = bpf_map_lookup_elem(&pid_map, &(pid));
			if (val2 == NULL)
				return 1;
		}
	}
	return 0;

}

SEC("tracepoint/sched/sched_process_fork")
int handle_sched_process_fork(struct trace_event_raw_sched_process_fork *ctx)
{
	struct fork_event e = {};
	e.pri.type = 0;
	e.pri.ts = bpf_ktime_get_ns();
	
	e.p_pid = ctx->parent_pid;
	e.pid  = ctx->child_pid;

	if (goskip(e.p_pid))
		return 0;

	bpf_probe_read_kernel_str(e.p_comm, sizeof(e.p_comm),
	                          ctx->parent_comm);
	bpf_probe_read_kernel_str(e.comm, sizeof(e.comm),
	                          ctx->child_comm);
	
	bpf_perf_event_output(ctx, &perf_buf, BPF_F_CURRENT_CPU,
	                      &e, sizeof(e));
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_kill")
int kill_entry(struct trace_event_raw_sys_enter *ctx)
{

    	struct kill_event e = {};
	e.pri.type = 1;
	e.pri.ts = bpf_ktime_get_ns();

        pid_t tpid = (pid_t)ctx->args[0];
        int sig = (int)ctx->args[1];

        __u64 pid_tgid;
        __u32 tid;

        pid_tgid = bpf_get_current_pid_tgid();
        tid = (__u32)pid_tgid;
        e.pid = pid_tgid >> 32;
        e.tpid = tpid;

	if (goskip(e.tpid))
		return 0;

	e.sig = sig;
	bpf_get_current_comm(e.comm, sizeof(e.comm));
	bpf_perf_event_output(ctx, &perf_buf, BPF_F_CURRENT_CPU,
	                      &e, sizeof(e));
        return 0;
}

char LICENSE[] SEC("license") = "GPL";
