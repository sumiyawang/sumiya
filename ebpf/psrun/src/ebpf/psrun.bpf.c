// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)

#include "vmlinux.h"
#include "bpf_helpers.h"
#include "bpf_core_read.h"
#include "bpf_tracing.h"
#include "psrun.h"
#include "bits.bpf.h"
#include "maps.bpf.h"
#include "core_fixes.bpf.h"

#define BPF_F_CURRENT_CPU 0xffffffffULL
#define DNAME_INLINE_LEN	32
#define TASK_COMM_LEN		16

#define TASK_RUNNING    0

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
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u32);
} stack_enable_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_STACK_TRACE);
    __uint(key_size, sizeof(u32));
    __uint(value_size, 127 * sizeof(u64));
    __uint(max_entries, 4096);
} u_stack_traces SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_STACK_TRACE);
    __uint(key_size, sizeof(u32));
    __uint(value_size, 127 * sizeof(u64));
    __uint(max_entries, 4096);
} stack_traces SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 128);
    __type(key, __u32);
    __type(value, __u32);
} pid_map SEC(".maps");

struct {
        __uint(type, BPF_MAP_TYPE_HASH);
        __uint(max_entries, 128);
        __type(key, u32);
        __type(value, u64);
} start SEC(".maps");

struct {
        __uint(type, BPF_MAP_TYPE_HASH);
        __uint(max_entries, 128);
        __type(key, u32);
        __type(value, struct hist);
} hists SEC(".maps");

static int goskip(pid_t pid) 
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

static int start_wait(pid_t pid)
{
        u64 ts;
	if (goskip(pid))
		return 0;

        ts = bpf_ktime_get_ns();
        bpf_map_update_elem(&start, &pid, &ts, BPF_ANY);
        return 0;
}

SEC("tracepoint/sched/sched_wakeup")
int handle_sched_wakeup(struct trace_event_raw_sched_wakeup_template *ctx)
{
        return start_wait(ctx->pid);
}

SEC("tracepoint/sched/sched_wakeup_new")
int handle_sched_wakeup_new(struct trace_event_raw_sched_wakeup_template *ctx)
{
        return start_wait(ctx->pid);
}

SEC("tracepoint/sched/sched_switch")
int handle_sched_switch(struct trace_event_raw_sched_switch *ctx)
{
	pid_t prev_pid = ctx->prev_pid;
	long prev_state = ctx->prev_state;
	pid_t next_pid = ctx->next_pid;
	char *next_comm = BPF_CORE_READ(ctx, next_comm);

        u64 *tsp, slot;
        s64 delta;
        u64 ts;
	struct hist *hp = NULL;

        struct hist zero = {
		.slots = {0},
		.comm = "",
	};

	if (prev_state == TASK_RUNNING) {
		if (!goskip(prev_pid)) {
        		ts = bpf_ktime_get_ns();
        		bpf_map_update_elem(&start, &prev_pid, &ts, BPF_ANY);
        		return 0;
		}
	}

	if (goskip(next_pid))
		return 0;

        tsp = bpf_map_lookup_elem(&start, &next_pid);
        if (!tsp) {
                return 0;
	}

        delta = bpf_ktime_get_ns() - *tsp;
        if (delta < 0)
                goto cleanup;

	hp = bpf_map_lookup_elem(&hists, &next_pid);
	if (!hp) {
        	bpf_map_update_elem(&hists, &next_pid, &zero, BPF_ANY);
		hp = bpf_map_lookup_elem(&hists, &next_pid);
		if (!hp)
                	goto cleanup;
	}

        bpf_probe_read_kernel_str(&(hp->comm), sizeof(hp->comm), ctx->next_comm);

        delta /= 1000000U;
	/*
 	 * 4.19 kernel think bpf code like:
 	 *
 	 * slot = log2l(delta);
 	 * hp->slots[slot]++;
 	 *
 	 * is unsafe. we just only code:
 	 */
	if (delta < 2) {
		__sync_fetch_and_add(&(hp->slots[0]), 1);
	} else if(delta < 4) {
		__sync_fetch_and_add(&(hp->slots[1]), 1);
	} else if(delta < 8) {
		__sync_fetch_and_add(&(hp->slots[2]), 1);
	} else if(delta < 16) {
		__sync_fetch_and_add(&(hp->slots[3]), 1);
	} else if(delta < 32) {
		__sync_fetch_and_add(&(hp->slots[4]), 1);
	} else if(delta < 64) {
		__sync_fetch_and_add(&(hp->slots[5]), 1);
	} else if(delta < 128) {
		__sync_fetch_and_add(&(hp->slots[6]), 1);
	} else if(delta < 256) {
		__sync_fetch_and_add(&(hp->slots[7]), 1);
	} else if(delta < 512) {
		__sync_fetch_and_add(&(hp->slots[8]), 1);
	} else if(delta < 1024) {
		__sync_fetch_and_add(&(hp->slots[9]), 1);
	} else if(delta < 2048) {
	/*
	 * fatal error for waiting
	 */
		__sync_fetch_and_add(&(hp->slots[10]), 1);
	} else if(delta < 4096) {
		__sync_fetch_and_add(&(hp->slots[11]), 1);
	} else {
		__sync_fetch_and_add(&(hp->slots[13]), 1);
	}
	__u32 key = 0;
	__u32 *en = NULL;
	__u32 setval = 0;
	en = bpf_map_lookup_elem(&stack_enable_map, &key);

	if (en) {
		setval = *en;
		if (delta > setval) {
			struct stack_event e ={};
			e.pid = next_pid;
			e.prev_pid = prev_pid;
			e.delta_ms = delta;
			bpf_get_current_comm(e.comm, sizeof(e.comm));
        		bpf_probe_read_kernel_str(&(e.next_comm), sizeof(e.next_comm), ctx->next_comm);
        		e.ns = bpf_ktime_get_ns();
			e.u_stack_id = bpf_get_stackid(ctx, &u_stack_traces, BPF_F_USER_STACK);
        		e.stack_id = bpf_get_stackid(ctx, &stack_traces, 0);
        		bpf_perf_event_output(ctx, &perf_buf, BPF_F_CURRENT_CPU, &e, sizeof(e));
		}
	}

cleanup:
        bpf_map_delete_elem(&start, &next_pid);
        return 0;
}

char LICENSE[] SEC("license") = "GPL";
