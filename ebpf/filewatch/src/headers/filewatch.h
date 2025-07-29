/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
#ifndef __FILELIFE_H
#define __FILELIFE_H

#define DNAME_INLINE_LEN	32
#define DIR_LV	8
#define TASK_COMM_LEN		16
#define SYM_LEN	64

struct event {
	char file0[DNAME_INLINE_LEN];
	char file1[DNAME_INLINE_LEN];
	char file2[DNAME_INLINE_LEN];
	char file3[DNAME_INLINE_LEN];
	char file4[DNAME_INLINE_LEN];
	char file5[DNAME_INLINE_LEN];
	char file6[DNAME_INLINE_LEN];
	char file7[DNAME_INLINE_LEN];
	char comm[TASK_COMM_LEN];
	__u64 ts;
	pid_t pid;
	int sym;
	/* private */
	void *dentry;
};

#endif /* __FILELIFE_H */
