/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
#include "vmlinux.h"
#include "bpf_helpers.h"
#include "bpf_core_read.h"
#include "bpf_tracing.h"
#include "slabtop.h"

#define MAX_ENTRIES	10240

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_ENTRIES);
	__type(key, char *);
	__type(value, struct slabrate_info);
} slab_entries SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_ENTRIES);
	__type(key, __u32);
	__type(value, struct psslab_info);
} ps_stat SEC(".maps");

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

static int probe_entry(struct kmem_cache *cachep)
{
	__u64 pid_tgid = bpf_get_current_pid_tgid();
	__u32 pid = pid_tgid >> 32;
	struct slabrate_info *valuep;
	struct psslab_info *psslab;
	const char *name = BPF_CORE_READ(cachep, name);
	struct slabrate_info slab_zero_value = {};
	struct psslab_info ps_zero_value = {};

	if (goskip(pid))
		return 0;

	valuep = bpf_map_lookup_elem(&slab_entries, &name);
	if (!valuep) {
		bpf_map_update_elem(&slab_entries, &name, &slab_zero_value, BPF_ANY);
		valuep = bpf_map_lookup_elem(&slab_entries, &name);
		if (!valuep)
			return 0;
		bpf_probe_read_kernel(&valuep->name, sizeof(valuep->name), name);
	}

	valuep->count++;
	valuep->size += BPF_CORE_READ(cachep, size);

	psslab = bpf_map_lookup_elem(&ps_stat, &pid);
	if (!psslab) {
		bpf_map_update_elem(&ps_stat, &pid, &ps_zero_value, BPF_ANY);
		psslab = bpf_map_lookup_elem(&ps_stat, &pid);
		if (!psslab)
			return 0;
		bpf_get_current_comm(&psslab->comm, TASK_COMM_LEN);
		psslab->pid = pid;
	} else {
		psslab->count = psslab->count + 1;
		psslab->size += BPF_CORE_READ(cachep, size);
	}
	return 0;
}

SEC("kprobe/kmem_cache_alloc")
int BPF_KPROBE(kmem_cache_alloc, struct kmem_cache *cachep)
{
	return probe_entry(cachep);
}

SEC("kprobe/kmem_cache_alloc_noprof")
int BPF_KPROBE(kmem_cache_alloc_noprof, struct kmem_cache *cachep)
{
       return probe_entry(cachep);
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
