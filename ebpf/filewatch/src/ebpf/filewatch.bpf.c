// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)

#include "vmlinux.h"
#include "bpf_helpers.h"
#include "bpf_core_read.h"
#include "bpf_tracing.h"
#include "filewatch.h"

#define BPF_F_CURRENT_CPU 0xffffffffULL
#define DNAME_INLINE_LEN	32
#define TASK_COMM_LEN		16

struct {
	__uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
	__uint(key_size, sizeof(u32));
	__uint(value_size, sizeof(u32));
} perf_buf SEC(".maps");

static void fill_dir(struct dentry *dentry, struct event *e)
{
	struct dentry *parent = dentry;
	const u8 *fpath;
	struct dentry *tp;

	if (parent) {
		fpath = BPF_CORE_READ(parent, d_name.name);
		bpf_probe_read_kernel_str(&(e->file0), DNAME_INLINE_LEN, fpath);
	} else 
		goto dir_done;
	tp = BPF_CORE_READ(parent, d_parent);
	if (parent != tp)
		parent = tp;
	else 
		goto dir_done;

	if (parent) {
		fpath = BPF_CORE_READ(parent, d_name.name);
		bpf_probe_read_kernel_str(&(e->file1), DNAME_INLINE_LEN, fpath);
	} else 
		goto dir_done;
	tp = BPF_CORE_READ(parent, d_parent);
	if (parent != tp)
		parent = tp;
	else 
		goto dir_done;

	if (parent) {
		fpath = BPF_CORE_READ(parent, d_name.name);
		bpf_probe_read_kernel_str(&(e->file2), DNAME_INLINE_LEN, fpath);
	} else 
		goto dir_done;
	tp = BPF_CORE_READ(parent, d_parent);
	if (parent != tp)
		parent = tp;
	else 
		goto dir_done;

	if (parent) {
		fpath = BPF_CORE_READ(parent, d_name.name);
		bpf_probe_read_kernel_str(&(e->file3), DNAME_INLINE_LEN, fpath);
	} else 
		goto dir_done;
	tp = BPF_CORE_READ(parent, d_parent);
	if (parent != tp)
		parent = tp;
	else 
		goto dir_done;

	if (parent) {
		fpath = BPF_CORE_READ(parent, d_name.name);
		bpf_probe_read_kernel_str(&(e->file4), DNAME_INLINE_LEN, fpath);
	} else 
		goto dir_done;
	tp = BPF_CORE_READ(parent, d_parent);
	if (parent != tp)
		parent = tp;
	else 
		goto dir_done;
dir_done:
	return;

}

SEC("kprobe/security_inode_create")
int BPF_KPROBE(security_inode_create, void *arg0, void *arg1, void *arg2)
{
	u64 ts;
	struct event e = {};

	ts = bpf_ktime_get_ns();
	e.ts = ts;
	e.sym = 0;
	fill_dir((struct dentry *)arg1, &e);

	e.pid = bpf_get_current_pid_tgid();
        bpf_get_current_comm(&e.comm, sizeof(e.comm));

	bpf_perf_event_output(ctx, &perf_buf, BPF_F_CURRENT_CPU, &e, sizeof(e));
	return 0;
}

SEC("kprobe/vfs_open")
int BPF_KPROBE(vfs_open, struct path *path, struct file *file)
{
	u64 ts;
	struct event e = {};

	ts = bpf_ktime_get_ns();
	e.ts = ts;
	e.sym = 1;

	struct dentry *dentry = BPF_CORE_READ(path, dentry);
	fill_dir(dentry, &e);

	e.pid = bpf_get_current_pid_tgid();
        bpf_get_current_comm(&e.comm, sizeof(e.comm));

	bpf_perf_event_output(ctx, &perf_buf, BPF_F_CURRENT_CPU, &e, sizeof(e));
	return 0;
}

SEC("kprobe/security_inode_unlink")
int BPF_KPROBE(security_inode_unlink, struct inode *dir, struct dentry *dentry)
{
        struct event e = {};
        const u8 *qs_name_ptr;
	u64 ts;
	bool has_arg = false;

	e.pid = bpf_get_current_pid_tgid();
	e.sym = 2;

	fill_dir(dentry, &e);
        bpf_get_current_comm(&e.comm, sizeof(e.comm));
	ts = bpf_ktime_get_ns();
	e.ts = ts;

	bpf_perf_event_output(ctx, &perf_buf, BPF_F_CURRENT_CPU, &e, sizeof(e));

        return 0;
}

char LICENSE[] SEC("license") = "GPL";
