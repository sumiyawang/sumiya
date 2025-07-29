#ifndef __BIOSNOOP_H
#define __BIOSNOOP_H

#define DISK_NAME_LEN   32
#define TASK_COMM_LEN   16
#define RWBS_LEN        8

#define MINORBITS       20
#define MINORMASK       ((1U << MINORBITS) - 1)

#define MKDEV(ma, mi)   (((ma) << MINORBITS) | (mi))

struct event {
        char comm[TASK_COMM_LEN];
        __u64 delta;
        __u64 qdelta;
        __u64 ts;
        __u64 sector;
        __u64 len;
        __u32 pid;
	int tag;
        __u32 cmd_flags;
        __u32 dev;
	void* rq;
	__u32 type;
};

#endif /* __BIOSNOOP_H */
