// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
// 9 Jan 2025   Sumiya Wang   Created this.
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
#include "psrun.h"
#include "psrun.skel.h"
#include "btf_helpers.h"
#include "trace_helpers.h"

#define PERF_BUFFER_PAGES	128
#define PERF_POLL_TIMEOUT_MS	100
#define MAX_PIDS 256
#define PERF_MAX_STACK_DEPTH 127

static volatile sig_atomic_t exiting = 0;
struct psrun_bpf *obj;

struct ksyms *ksyms = NULL;
struct syms_cache *syms_cache = NULL;
static int64_t g_offset_ns = 0;

static void sig_int(int signo)
{
	exiting = 1;
}

static struct global {
        pid_t pid_a[MAX_PIDS];
	bool enf;
	int it;
	int pid_c;
	int dump_val;
} gl = { };

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
        { "process", 'p', "PID", 0, "target pid", 0 },
        { "interval", 'i', "INT", 0, "interval", 0 },
        { "stack", 's', "INT", 0, "dump stack if wait time (ms)", 0 },
        { NULL, 'h', NULL, OPTION_HIDDEN, "Show the full help", 0 },
        {},
};

const char argp_program_doc[] =
"Trace the sched waittime of process.\n"
"\n"
"USAGE: ./psrun [-p 123,200-205,300]\n"
"\n";

static void parse_pid_range(const char *range_str) {
    char *dash_pos = strchr(range_str, '-');
    if (dash_pos != NULL) {
        *dash_pos = '\0';
        int start_pid = strtol(range_str, NULL, 10);
        int end_pid = strtol(dash_pos + 1, NULL, 10);

        if (errno || start_pid <= 0 || end_pid <= 0 || start_pid > end_pid) {
            fprintf(stderr, "invalid PID range: %s\n", range_str);
            return;
        }

        for (int pid = start_pid; pid <= end_pid; ++pid) {
            if (gl.pid_c < MAX_PIDS) {
                gl.pid_a[gl.pid_c++] = pid;
            } else {
                fprintf(stderr, "Too many PIDs (max is %d)\n", MAX_PIDS);
                return;
            }
        }
    } else {
        int pid = strtol(range_str, NULL, 10);
        if (errno || pid <= 0) {
            fprintf(stderr, "invalid PID: %s\n", range_str);
            return;
        }

        if (gl.pid_c < MAX_PIDS) {
            gl.pid_a[gl.pid_c++] = pid;
        } else {
            fprintf(stderr, "Too many PIDs (max is %d)\n", MAX_PIDS);
        }
    }
}

static error_t parse_arg(int key, char *arg, struct argp_state *state)
{
        int pid;
        char *token;
        int i = 0;

        switch (key) {
        case 'p':
            gl.pid_c = 0;
    
            token = strtok(arg, ",");
            while (token != NULL) {
                errno = 0;
                pid = strtol(token, NULL, 10);
   		parse_pid_range(token);             
                token = strtok(NULL, ",");
            }
    
            gl.enf = true;
            break;
        case 'i':
                errno = 0;
                i = strtol(arg, NULL, 10);
                if (errno || i <= 0) {
                        fprintf(stderr, "invalid time: %s\n", arg);
                        argp_usage(state);
                }
                i = strtol(arg, NULL, 10);
		gl.it = i;
		break;
        case 's':
                errno = 0;
                i = strtol(arg, NULL, 10);
                if (errno || i <= 0) {
                        fprintf(stderr, "invalid time: %s\n", arg);
                        argp_usage(state);
                }
                i = strtol(arg, NULL, 10);
		if (i < 1)
                        fprintf(stderr, "dump stack must set wait time > 1ms\n");
		gl.dump_val = i;
            	gl.enf = true;
		break;
        case 'h':
                argp_state_help(state, stderr, ARGP_HELP_STD_HELP);
                break;

    default:
        return ARGP_ERR_UNKNOWN;
    }

    if (!gl.enf)
        argp_usage(state);

    return 0;
}

static int print_log2_hists(struct bpf_map *hists)
{
        const char *units = "msecs";
        int err, fd = bpf_map__fd(hists);
        __u32 lookup_key = -2, next_key;
        struct hist hist;
	int i, pid;

	for (i = 0; i < gl.pid_c; ++i) {
		pid = gl.pid_a[i];
        	err = bpf_map_lookup_elem(fd, &pid, &hist);
                if (err < 0) {
                	printf("  pid %d: (not schdule more than %ds)\n", pid, gl.it);
                } else {
                	printf("  pid %d: [%s] run delay:\n", pid, hist.comm);
                	print_log2_hist(hist.slots, MAX_SLOTS, units);
			printf("\n");
                	err = bpf_map_delete_elem(fd, &pid);
                	if (err < 0) {
                	        fprintf(stderr, "failed to cleanup hist : %d\n", err);
                	        return -1;
                	}
		}
	}

        return 0;
}

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
        const struct stack_event *e = data;
        int i, stack_fd;
        unsigned long *stack;
        long offset;
        const struct ksym *ksym;

        char utc[128];
       struct sym_info sinfo;
       const struct syms *syms;
       int idx,err;
        uint64_t real_ts_ns = e->ns + g_offset_ns;

        format_time_ns(real_ts_ns, utc, sizeof(utc));

        printf("%s \n[%d] [%s] sched from [%d] [%s], wait %d ms:\n", utc, e->pid, e->next_comm, e->prev_pid, e->comm, (int)e->delta_ms);
        stack = calloc(PERF_MAX_STACK_DEPTH, sizeof(*stack));

        stack_fd = bpf_map__fd(obj->maps.stack_traces);

        if (bpf_map_lookup_elem(stack_fd, &e->stack_id, stack) != 0) {
                fprintf(stderr, "    [Missed Kernel Stack]\n\n");
                goto cleanup;
        }
        for (i = 0; i < PERF_MAX_STACK_DEPTH && stack[i]; i++) {
                ksym = ksyms__map_addr(ksyms, stack[i]);
                offset = stack[i] - ksym->addr;
                printf("    %lx %s+%ld\n", ksym->addr,ksym ? ksym->name : "Unknown", offset);
        }

        free(stack);
        stack = calloc(PERF_MAX_STACK_DEPTH, sizeof(*stack));

        stack_fd = bpf_map__fd(obj->maps.u_stack_traces);

        if (bpf_map_lookup_elem(stack_fd, &e->u_stack_id, stack) != 0) {
                fprintf(stderr, "    [Missed user Stack]\n\n");
                goto cleanup;
        }

        syms = syms_cache__get_syms(syms_cache, e->prev_pid);
        idx = 0;
        for (i = 0; i < PERF_MAX_STACK_DEPTH && stack[i]; i++) {
               err = syms__map_addr_dso(syms, stack[i], &sinfo);
               printf("    #%-2d 0x%016lx", idx++, stack[i]);
                       if (sinfo.sym_name)
                               printf(" %s+0x%lx", sinfo.sym_name, sinfo.sym_offset);
                       printf(" (%s+0x%lx)", sinfo.dso_name, sinfo.dso_offset);
               printf("\n");
        }
        printf("\n");


cleanup:
        free(stack);
}

static void handle_lost_events(void *ctx, int cpu, __u64 lost_cnt)
{
        fprintf(stderr, "Lost %llu events on CPU #%d!\n", lost_cnt, cpu);
}

int main(int argc, char **argv)
{
        struct perf_buffer_opts pb_opts;
	int err;
	int enable_map_fd = -1, pid_map_fd = -1;
	struct bpf_map *map = NULL;
	struct tm *tm;
	time_t t;
	char ts[32];

        static const struct argp argp = { 
                .options = opts,
                .parser = parse_arg,
                .doc = argp_program_doc,
        };

	gl.enf = 0;
	gl.it = 3;
	gl.dump_val = 0;

	err = argp_parse(&argp, argc, argv, 0, NULL, NULL);
	if (err||!gl.enf) {
	    fprintf(stderr, "./psrun -h\n");
            return err;
	}

	struct bpf_link *link_open = NULL, *link_sym1 = NULL, *link_sym2 = NULL;

        bump_memlock_rlimit();

	obj = psrun_bpf__open();
	if (!obj) {
		fprintf(stderr, "failed to open BPF object\n");
		return 1;
	}

	err = psrun_bpf__load(obj);
	if (err) {
		fprintf(stderr, "failed to load BPF object: %d\n", err);
		goto cleanup;
	}

	int map_fd = bpf_map__fd(obj->maps.filter_enable_map);
	__u32 key = 0;
        int i;
	bpf_map_update_elem(map_fd, &key, &gl.enf, BPF_ANY);
	if (gl.enf) {
		map_fd = bpf_map__fd(obj->maps.pid_map);
		for (i = 0; i < gl.pid_c; ++i) {
		    key = gl.pid_a[i];
		    printf("trace pid %d\n", key);
		    bpf_map_update_elem(map_fd, &key, &key, BPF_ANY);
		}
	} else {
		printf("here for trace cpu runq\n");
	}

	map_fd = bpf_map__fd(obj->maps.stack_enable_map);
	key = 0;
	bpf_map_update_elem(map_fd, &key, &gl.dump_val, BPF_ANY);

	obj->links.handle_sched_wakeup = 
		bpf_program__attach_tracepoint(obj->progs.handle_sched_wakeup, "sched", "sched_wakeup");
	obj->links.handle_sched_wakeup_new = 
		bpf_program__attach_tracepoint(obj->progs.handle_sched_wakeup_new, "sched", "sched_wakeup_new");
	obj->links.handle_sched_switch = 
		bpf_program__attach_tracepoint(obj->progs.handle_sched_switch, "sched", "sched_switch");


	if (signal(SIGINT, sig_int) == SIG_ERR) {
		fprintf(stderr, "can't set signal handler: %s\n", strerror(errno));
		err = 1;
		goto cleanup;
	}
	if (gl.dump_val == 0) {
		printf("Process sched wait time: Hit Ctrl-C to end.\n");
        	while (1) {
        	        sleep(gl.it);
        	        printf("\n");

        	        time(&t);
        	        tm = localtime(&t);
			strftime(ts, sizeof(ts), "[%Y-%m-%d %H:%M:%S]", tm);
        	        printf("%-8s ", ts);
        	        printf("\n");

        	        err = print_log2_hists(obj->maps.hists);
        	        printf("\n\n");
        	        if (err)
        	                break;

        	        if (exiting)
        	                break;
        	}
	} else {
		printf("dump prev stack if wait long time, Hit Ctrl-C to end.\n");
		struct perf_buffer_opts pb_opts;
		struct perf_buffer *pb = NULL;
	        ksyms = ksyms__load();
	        if (!ksyms) {
	                fprintf(stderr, "failed to load kallsyms\n");
	                goto cleanup;
	        }
	        syms_cache = syms_cache__new(0);
	        if (!syms_cache) {
	                fprintf(stderr, "failed to create syms_cache\n");
	                goto cleanup;
	        }
		g_offset_ns = calc_monotonic_offset_ns();

	        pb = perf_buffer__new(bpf_map__fd(obj->maps.perf_buf), PERF_BUFFER_PAGES,
	                               handle_event, handle_lost_events, NULL, NULL);
		while (!exiting && ((err = perf_buffer__poll(pb, 100)) >= 0)) {
			;
		}
	}

cleanup:
	psrun_bpf__destroy(obj);

	return err != 0;
}
