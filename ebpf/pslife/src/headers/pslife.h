/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
#ifndef __FILELIFE_H
#define __FILELIFE_H

#define DNAME_INLINE_LEN	32
#define TASK_COMM_LEN		16
#define SYM_LEN	64

struct pri_e {
    int type;
    __u64 ts;
};

struct fork_event {
    struct pri_e pri;
    __u32 p_pid;
    __u32 pid;
    char  p_comm[16];
    char  comm[16];
};

struct kill_event {
    struct pri_e pri;
    unsigned int pid;
    unsigned int tpid;
    int sig;
    char comm[TASK_COMM_LEN];
};

#endif /* __FILELIFE_H */
