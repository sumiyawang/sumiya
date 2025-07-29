// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
// 14 Jan 2025   Sumiya Wang   Created this.
#include <argp.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include "libbpf.h"
#include "blk_types.h"
#include "bpf.h"
#include <sys/resource.h>
#include "io.h"
#include "io.skel.h"
#include "btf_helpers.h"
#include "trace_helpers.h"

#define PERF_BUFFER_PAGES	4096
#define PERF_POLL_TIMEOUT_MS	1000000
#define MAX_PIDS 256
#define PERF_MAX_STACK_DEPTH 127

static volatile sig_atomic_t exiting = 0;
struct io_bpf *obj;

struct ksyms *ksyms = NULL;
struct syms_cache *syms_cache = NULL;
static int64_t g_offset_ns = 0;
static struct partitions *partitions;

static void sig_int(int signo)
{
	exiting = 1;
}

static struct global {
        __u64 min_lat_ms;
        char *disk;
        int duration;
	pid_t pid_a[MAX_PIDS];
	int pid_c;
	int enf;
	int gt;
} gl = {};

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
	{ "disk",  'd', "DISK",  0, "Trace this disk only", 0 },
        { "greater", 'g', "ms", 0, "greater than x ms", 0 },
        { NULL, 'h', NULL, OPTION_HIDDEN, "Show the full help", 0 },
        {},
};

const char argp_program_doc[] =
"Trace the IO.\n"
"\n"
"USAGE: ./io [-p 123] [-d vda]\n"

"io type list:\n"
"W ===  REQ_OP_WRITE            === write sectors to the device\n"
"F ===  REQ_OP_FLUSH            === flush the volatile write cache\n"
"D ===  REQ_OP_DISCARD          === discard sectors\n"
"A ===  REQ_RAHEAD              === read ahead, can fail anytime\n"
"R ===  REQ_OP_READ             === read sectors from the device\n"
"S ===  REQ_OP_SYNC             === IO with sync op\n"
"Z ===  REQ_OP_ZONE_RESET       === reset a zone write pointer\n"
"M ===  REQ_META                === metadata io request\n"
"DE === REQ_OP_SECURE_ERASE     === securely erase sectors\n"
"FF === REQ_FUA                 === forced unit access\n"
"ZR === REQ_OP_ZONE_RESET_ALL   === reset all the zones present on the device\n"
"ZW === REQ_OP_WRITE_ZEROES     === write the zero filled sector many times\n"
"ZO === REQ_OP_ZONE_OPEN        === Open a zone\n"
"ZC === REQ_OP_ZONE_CLOSE       === Close a zone\n"
"ZF === REQ_OP_ZONE_FINISH      === Transition a zone to full\n"
"SI === REQ_OP_SCSI_IN          === SCSI passthrough using struct scsi_request\n"
"SO === REQ_OP_SCSI_OUT         === SCSI passthrough using struct scsi_request\n"
"DI === REQ_OP_DRV_IN           === Driver private requests\n"
"DO === REQ_OP_DRV_OUT          === Driver private requests\n"
"SCI =  REQ_OP_SCSI_IN          === SCSI passthrough using struct scsi_request\n"
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
    
            gl.enf = 1;
            break;
        case 'd':
            gl.disk = arg;
            if (strlen(arg) + 1 > DISK_NAME_LEN) {
                    fprintf(stderr, "invaild disk name: too long\n");
                    argp_usage(state);
            }
            gl.enf = 2;
            break;
        case 'g':
	    int tmp;
            tmp = strtol(arg, NULL, 10);
            if (errno || tmp <= 0) {
                    fprintf(stderr, "invalid val: %s\n", arg);
                    argp_usage(state);
            }
	    gl.gt = tmp;
            gl.enf = 3;
            break;
        case 'h':
            argp_state_help(state, stderr, ARGP_HELP_STD_HELP);
            break;
    default:
        return ARGP_ERR_UNKNOWN;
    }

    return 0;
}

static void blk_fill_rwbs(char *rwbs, unsigned int op)
{
        int i = 0;

        if (op & REQ_PREFLUSH)
                rwbs[i++] = 'F';

        switch (op & REQ_OP_MASK) {
        case REQ_OP_WRITE:
        case REQ_OP_WRITE_SAME:
                rwbs[i++] = 'W';
                break;
        case REQ_OP_DISCARD:
                rwbs[i++] = 'D';
                break;
        case REQ_OP_SECURE_ERASE:
                rwbs[i++] = 'D';
                rwbs[i++] = 'E';
                break;
        case REQ_OP_FLUSH:
                rwbs[i++] = 'F';
                break;
        case REQ_OP_READ:
                rwbs[i++] = 'R';
                break;
        case REQ_OP_WRITE_ZEROES:
                rwbs[i++] = 'W';
                rwbs[i++] = 'Z';
                break;
        case REQ_OP_ZONE_RESET:
                rwbs[i++] = 'R';
                rwbs[i++] = 'E';
                break;
        case REQ_OP_SCSI_IN:
                rwbs[i++] = 'S';
                rwbs[i++] = 'C';
                rwbs[i++] = 'I';
                break;
        case REQ_OP_SCSI_OUT:
                rwbs[i++] = 'S';
                rwbs[i++] = 'C';
                rwbs[i++] = 'O';
                break;
        case REQ_OP_DRV_IN:
                rwbs[i++] = 'D';
                rwbs[i++] = 'R';
                rwbs[i++] = 'I';
                break;
        case REQ_OP_DRV_OUT:
                rwbs[i++] = 'D';
                rwbs[i++] = 'R';
                rwbs[i++] = 'O';
                break;
        default:
		printf("op %x\n",op & REQ_OP_MASK);
                rwbs[i++] = '0'+ (op & REQ_OP_MASK);
        }

        if (op & REQ_FUA)
                rwbs[i++] = 'F';
        if (op & REQ_RAHEAD)
                rwbs[i++] = 'A';
        if (op & REQ_SYNC)
                rwbs[i++] = 'S';
        if (op & REQ_META)
                rwbs[i++] = 'M';

        rwbs[i] = '\0';
}

static void handle_event(void *ctx, int cpu, void *data, __u32 data_sz)
{
        const struct partition *partition;
        struct event e;
        char rwbs[RWBS_LEN];
        struct timespec ct; 
        struct tm *tm;
        char ts[32];

        if (data_sz < sizeof(e)) {
                printf("Error: packet too small\n");
                return;
        }
        memcpy(&e, data, sizeof(e));

        clock_gettime(CLOCK_REALTIME, &ct);
        tm = localtime(&ct.tv_sec);
        strftime(ts, sizeof(ts), "%H:%M:%S", tm);
        printf("%-8s.%04ld ", ts, ct.tv_nsec / 100000);
        blk_fill_rwbs(rwbs, e.cmd_flags);
        partition = partitions__get_by_dev(partitions, e.dev);
        printf("%-18.18s %-7d %-7s %-4s %-10lld %-7lld ",
                e.comm, e.pid, partition ? partition->name : "Unknown", rwbs,
                e.sector, e.len);
        printf("%7.3f ", e.qdelta != -1 ?
                        e.qdelta / 1000000.0 : -1);
        printf("%7.3f\n", e.delta / 1000000.0);
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
	const struct partition *partition;
	struct perf_buffer *pb = NULL;
	__u64 time_end = 0;

        static const struct argp argp = { 
                .options = opts,
                .parser = parse_arg,
                .doc = argp_program_doc,
        };
	gl.enf = 0;

	err = argp_parse(&argp, argc, argv, 0, NULL, NULL);
	if (err) {
	    fprintf(stderr, "./io -h\n");
            return err;
	}

	struct bpf_link *link_open = NULL, *link_sym1 = NULL, *link_sym2 = NULL;

        bump_memlock_rlimit();

	obj = io_bpf__open();
	if (!obj) {
		fprintf(stderr, "failed to open BPF object\n");
		return 1;
	}

        partitions = partitions__load();
        if (!partitions) {
                fprintf(stderr, "failed to load partitions info\n");
                goto cleanup;
        }

        /* initialize global data (filtering options) */

	err = io_bpf__load(obj);
	if (err) {
		fprintf(stderr, "failed to load BPF object: %d\n", err);
		goto cleanup;
	}

	int map_fd = bpf_map__fd(obj->maps.filter_enable_map);
	__u32 key = 0;
        int i;

	bpf_map_update_elem(map_fd, &key, &gl.enf, BPF_ANY);

	if (gl.enf > 0) {
		map_fd = bpf_map__fd(obj->maps.pid_map);
		for (i = 0; i < gl.pid_c; ++i) {
		    key = gl.pid_a[i];
		    bpf_map_update_elem(map_fd, &key, &key, BPF_ANY);
		    printf("trace pid %d\n", key);
		}

        	if (gl.disk) {
        	        partition = partitions__get_by_name(partitions, gl.disk);
        	        if (!partition) {
        	                printf("ERR: not found device name: %s\n",gl.disk);
        	                goto cleanup;
        	        }
			map_fd = bpf_map__fd(obj->maps.vdx_map);
			key = partition->dev;
		    	bpf_map_update_elem(map_fd, &key, &key, BPF_ANY);
		    	printf("trace device %s %d\n", gl.disk, partition->dev);
        	}

        	if (gl.gt) {
			map_fd = bpf_map__fd(obj->maps.gt_map);
			key = 0;
		    	bpf_map_update_elem(map_fd, &key, &gl.gt, BPF_ANY);
		    	printf("trace io delay > %d ms\n", gl.gt);
		}
        }

        ksyms = ksyms__load();
        if (!ksyms) {
                fprintf(stderr, "failed to load kallsyms\n");
                goto cleanup;
        }

	if (ksyms__get_symbol(ksyms, "blk_start_request")) {
		obj->links.bpf_prog1 =
			bpf_program__attach_kprobe(obj->progs.bpf_prog1, false, "blk_start_request");
	}

	if (ksyms__get_symbol(ksyms, "blk_account_io_start")) {
		obj->links.bpf_prog2 =
			bpf_program__attach_kprobe(obj->progs.bpf_prog2, false, "blk_account_io_start");
	} else {
		obj->links.bpf_prog2 =
			bpf_program__attach_kprobe(obj->progs.bpf_prog2, false, "__blk_account_io_start");
	}
	
	obj->links.bpf_prog3 =
			bpf_program__attach_raw_tracepoint(obj->progs.bpf_prog3, "block_rq_complete");
	obj->links.bpf_prog4 =
			bpf_program__attach_raw_tracepoint(obj->progs.bpf_prog4, "block_rq_insert");
	obj->links.bpf_prog5 =
			bpf_program__attach_raw_tracepoint(obj->progs.bpf_prog5, "block_rq_issue");

        pb = perf_buffer__new(bpf_map__fd(obj->maps.events), PERF_BUFFER_PAGES,
                              handle_event, handle_lost_events, NULL, NULL);
        if (!pb) {
                err = -errno;
                fprintf(stderr, "failed to open perf buffer: %d\n", err);
                goto cleanup;
        }

        printf("%-13s ", "TIME(s)");
        printf("%-15s %-7s %-7s %-4s %-10s %-7s ",
                "COMM", "PID", "DISK", "TYPE", "SECTOR", "BYTES");
        printf("%7s ", "OS wati(ms)");
        printf("%7s\n", "DISK wait(ms)");

        time_end = get_ktime_ns() + gl.duration * NSEC_PER_SEC;

        if (signal(SIGINT, sig_int) == SIG_ERR) {
                fprintf(stderr, "can't set signal handler: %s\n", strerror(errno));
                err = 1;
                goto cleanup;
        }

        /* main: poll */
        while (!exiting) {
                err = perf_buffer__poll(pb, PERF_POLL_TIMEOUT_MS);
                if (err < 0 && err != -EINTR) {
                        fprintf(stderr, "error polling perf buffer: %s\n", strerror(-err));
                        goto cleanup;
                }
                /* reset err to return 0 if exiting */
                err = 0;
                if (gl.duration && get_ktime_ns() > time_end)
                        break;
        }

cleanup:
        perf_buffer__free(pb);
        io_bpf__destroy(obj);
        ksyms__free(ksyms);
        partitions__free(partitions);

        return err != 0;
}
