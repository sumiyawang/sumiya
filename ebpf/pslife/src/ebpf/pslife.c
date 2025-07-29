// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
// 02 Jan 2025   Sumiya Wang   Created this.
//
#include <argp.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include "libbpf.h"
#include "bpf.h"
#include <sys/resource.h>
#include "pslife.h"
#include "pslife.skel.h"
#include "btf_helpers.h"
#include "trace_helpers.h"

#define PERF_BUFFER_PAGES	128
#define PERF_POLL_TIMEOUT_MS	100

static volatile sig_atomic_t exiting = 0;

static void sig_int(int signo)
{
	exiting = 1;
}

static struct global {
        pid_t pid;
	bool attach_fork ;
	bool attach_kill ;
	bool enf;
} gl = { };

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
             "%04d-%02d-%02d %02d:%02d:%02d.%01u",
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
	int type;
	char utc[128];
	struct fork_event *tmp = data;
	type = tmp->pri.type;

	uint64_t real_ts_ns = tmp->pri.ts + g_offset_ns;

	format_time_ns(real_ts_ns, utc, sizeof(utc));

	if (type == 0) {
	    struct fork_event *e = data;
	    printf("[%s] [%s] [%d] ---fork---> [%s] [%d]\n", utc, e->p_comm, e->p_pid, e->comm,e->pid);
	} else if (type == 1) {
	    struct kill_event *e = data;
	    printf("[%s] [%s] [%d]   kill -%d   [%d]\n", utc, e->comm, e->pid, e->sig, e->tpid);
	}
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

static const struct argp_option opts[] = {
        { "process", 'p', "PID", 0, "only aim pid", 0 },
        { NULL, 'h', NULL, OPTION_HIDDEN, "Show the full help", 0 },
        {},
};

const char argp_program_doc[] =
"Trace the fork/kill of process.\n"
"\n"
"USAGE: ./pslife [-p 123]\n"
"\n";


static error_t parse_arg(int key, char *arg, struct argp_state *state)
{
        int pid;

        switch (key) {
        case 'p':
                errno = 0;
                pid = strtol(arg, NULL, 10);
                if (errno || pid <= 0) {
                        fprintf(stderr, "invalid PID: %s\n", arg);
                        argp_usage(state);
                }
                gl.pid = pid;
		gl.enf = true;
		gl.attach_fork = true;
		gl.attach_kill = true;
                break;
        default:
                return ARGP_ERR_UNKNOWN;
        }
        return 0;
}

int main(int argc, char **argv)
{
        struct perf_buffer_opts pb_opts;
	int err;
	int enable_map_fd = -1, pid_map_fd = -1;
	struct bpf_map *map = NULL;

        static const struct argp argp = { 
                .options = opts,
                .parser = parse_arg,
                .doc = argp_program_doc,
        };

	gl.attach_fork = true;
	gl.attach_kill = true;
	gl.enf = 0;
	gl.pid = 0;

	err = argp_parse(&argp, argc, argv, 0, NULL, NULL);

	struct bpf_link *link_open = NULL, *link_sym1 = NULL, *link_sym2 = NULL;
	g_offset_ns = calc_monotonic_offset_ns();
	struct perf_buffer *pb = NULL;
	struct pslife_bpf *obj;

        bump_memlock_rlimit();

	obj = pslife_bpf__open();
	if (!obj) {
		fprintf(stderr, "failed to open BPF object\n");
		return 1;
	}

	err = pslife_bpf__load(obj);
	if (err) {
		fprintf(stderr, "failed to load BPF object: %d\n", err);
		goto cleanup;
	}

	int map_fd = bpf_map__fd(obj->maps.filter_enable_map);
	__u32 key = 0;
	bpf_map_update_elem(map_fd, &key, &gl.enf, BPF_ANY);
	if (gl.enf) {
		map_fd = bpf_map__fd(obj->maps.pid_map);
		key = gl.pid;
		printf("grep pid %d\n",gl.pid);
		bpf_map_update_elem(map_fd, &(gl.pid), &key, BPF_ANY);
	}

	if (gl.attach_fork) {
		obj->links.handle_sched_process_fork = bpf_program__attach_tracepoint(obj->progs.handle_sched_process_fork, "sched", "sched_process_fork");
	}

	if (gl.attach_kill) {
		obj->links.kill_entry = bpf_program__attach_tracepoint(obj->progs.kill_entry, "syscalls", "sys_enter_kill");
	}

	printf("Tracing process ... Hit Ctrl-C to end.\n");

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
	pslife_bpf__destroy(obj);

	return err != 0;
}
