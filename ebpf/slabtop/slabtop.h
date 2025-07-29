/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
#ifndef __SLABRATETOP_H
#define __SLABRATETOP_H

#define CACHE_NAME_SIZE 32
#define TASK_COMM_LEN 32
#define MAX_PIDS 256

struct slabrate_info {
	char name[CACHE_NAME_SIZE];
	__u64 count;
	__u64 size;
};

struct psslab_info {
	char comm[TASK_COMM_LEN];
	__u64 count;
	__u64 size;
	__u32 pid;
};

#endif /* __SLABRATETOP_H */
