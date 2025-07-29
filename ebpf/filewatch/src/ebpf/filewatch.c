// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
// 02 Jan 2025   Sumiya Wang   Created this.

#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include "libbpf.h"
#include "bpf.h"
#include <sys/resource.h>
#include "filewatch.h"
#include "filewatch.skel.h"
#include "btf_helpers.h"
#include "trace_helpers.h"

#define PERF_BUFFER_PAGES	128
#define PERF_POLL_TIMEOUT_MS	100

static volatile sig_atomic_t exiting = 0;

static void sig_int(int signo)
{
	exiting = 1;
}

static int64_t g_offset_ns = 0;

static int64_t calc_monotonic_offset_ns(void)
{
    struct timespec ts_real, ts_mono;
    clock_gettime(CLOCK_REALTIME, &ts_real);
    clock_gettime(CLOCK_MONOTONIC, &ts_mono);

    uint64_t real_now_ns = (uint64_t)ts_real.tv_sec * 1000000000ULL + ts_real.tv_nsec;
    uint64_t mono_now_ns = (uint64_t)ts_mono.tv_sec * 1000000000ULL + ts_mono.tv_nsec;

    return (int64_t)(real_now_ns - mono_now_ns);
}

static void format_time_ns(uint64_t ns, char* buf, size_t buflen)
{
    time_t sec = ns / 1000000000ULL;
    uint32_t remainder_ns = ns % 1000000000ULL;

    struct tm* tm_info = gmtime(&sec);
    if (!tm_info) {
        snprintf(buf, buflen, "gmtime_error");
        return;
    }

    snprintf(buf, buflen,
             "%04d-%02d-%02d %02d:%02d:%02d.%02u",
             tm_info->tm_year + 1900,
             tm_info->tm_mon + 1,
             tm_info->tm_mday,
             tm_info->tm_hour + 8,
             tm_info->tm_min,
             tm_info->tm_sec,
             remainder_ns / 1000);
}
static void handle_event(void *ctx, int cpu, void *data, __u32 data_sz)
{
        const struct event *e = data;
	char fsym[64];
	char utc[128];
	int i;
	switch (e->sym) {
	case 0:
		strcpy(fsym, "create");
		break;
	case 1:
		strcpy(fsym, "open");
		break;
	case 2:
		strcpy(fsym, "rm");
		break;
	default:
		strcpy(fsym, "err");
		break;
	}
	uint64_t real_ts_ns = e->ts + g_offset_ns;
	format_time_ns(real_ts_ns, utc, sizeof(utc));
        printf("[%s] [%s ", utc, fsym);
	if ((e->file4[0] != '\0') && (e->file4[0] != '/'))
        	printf("%s", e->file4);
	if ((e->file3[0] != '\0') && (e->file3[0] != '/'))
        	printf("/%s", e->file3);
	if ((e->file2[0] != '\0') && (e->file2[0] != '/'))
        	printf("/%s", e->file2);
	if ((e->file1[0] != '\0') && (e->file1[0] != '/'))
        	printf("/%s", e->file1);
	if ((e->file0[0] != '\0') && (e->file0[0] != '/'))
        	printf("/%s ] ", e->file0);
        printf("[%d %s]\n",e->pid, e->comm);
}

void handle_lost_events(void *ctx, int cpu, __u64 lost_cnt)
{
	fprintf(stderr, "lost %llu events on CPU #%d\n", lost_cnt, cpu);
}

void bump_memlock_rlimit(void)
{
        struct rlimit rlim_new = {
                .rlim_cur       = RLIM_INFINITY,
                .rlim_max       = RLIM_INFINITY,
        };

        if (setrlimit(RLIMIT_MEMLOCK, &rlim_new)) {
                fprintf(stderr, "Failed to increase RLIMIT_MEMLOCK limit!\n");
                exit(1);
        }
}

int main(int argc, char **argv)
{
        struct perf_buffer_opts pb_opts;
	bool attach_open = false;

	if (argc > 1 && strcmp(argv[1], "open") == 0) {
	    attach_open = true;
	    printf("trace open\n");
	}

	struct bpf_link *link_open = NULL, *link_sym1 = NULL, *link_sym2 = NULL;
	g_offset_ns = calc_monotonic_offset_ns();
	struct perf_buffer *pb = NULL;
	struct filewatch_bpf *obj;
	int err;

        bump_memlock_rlimit();

	obj = filewatch_bpf__open();
	if (!obj) {
		fprintf(stderr, "failed to open BPF object\n");
		return 1;
	}

	err = filewatch_bpf__load(obj);
	if (err) {
		fprintf(stderr, "failed to load BPF object: %d\n", err);
		goto cleanup;
	}


	obj->links.security_inode_unlink = bpf_program__attach_kprobe(obj->progs.security_inode_unlink, false, "security_inode_unlink");
	
	obj->links.security_inode_create = bpf_program__attach_kprobe(obj->progs.security_inode_create, false, "security_inode_create");
	
	if (attach_open) {
	    obj->links.vfs_open = bpf_program__attach_kprobe(obj->progs.vfs_open, false, "vfs_open");
	}

	printf("Tracing files ... Hit Ctrl-C to end.\n");

	pb = perf_buffer__new(bpf_map__fd(obj->maps.perf_buf), PERF_BUFFER_PAGES,
			      handle_event, handle_lost_events, NULL, NULL);
	if (!pb) {
		err = -errno;
		fprintf(stderr, "failed to open perf buffer: %d\n", err);
		goto cleanup;
	}

	if (signal(SIGINT, sig_int) == SIG_ERR) {
		fprintf(stderr, "can't set signal handler: %s\n", strerror(errno));
		err = 1;
		goto cleanup;
	}

	while (!exiting) {
		err = perf_buffer__poll(pb, PERF_POLL_TIMEOUT_MS);
		if (err < 0 && err != -EINTR) {
			fprintf(stderr, "error polling perf buffer: %s\n", strerror(-err));
			goto cleanup;
		}
		/* reset err to return 0 if exiting */
		err = 0;
	}

cleanup:
	perf_buffer__free(pb);
	filewatch_bpf__destroy(obj);

	return err != 0;
}
