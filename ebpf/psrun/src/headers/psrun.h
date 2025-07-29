/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
#ifndef __RUNQLAT_H
#define __RUNQLAT_H

#define MAX_SLOTS	26

struct hist {
	__u32 slots[MAX_SLOTS];
	char comm[16];
};

struct stack_event {
    __u32 pid;
    __u32 prev_pid;
    __u64 delta_ms;
    __u64 ns;
    __u64 stack_id;
    __u64 u_stack_id;
    char comm[16];
    char next_comm[16];
};

#endif /* __RUNQLAT_H */
