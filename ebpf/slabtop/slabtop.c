/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */

#include <argp.h>
#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "libbpf.h"
#include "bpf.h"
#include "slabtop.h"
#include "slabtop.skel.h"
#include "trace_helpers.h"

#define warn(...) fprintf(stderr, __VA_ARGS__)
#define OUTPUT_ROWS_LIMIT 10240

enum SORT_BY {
	SORT_BY_CACHE_NAME,
	SORT_BY_CACHE_COUNT,
	SORT_BY_CACHE_SIZE,
};

static volatile sig_atomic_t exiting = 0;

static struct global {
        pid_t pid_a[MAX_PIDS];
        int pid_c;
	int type;
	int enf;
} gl = {};

static pid_t target_pid = 0;
static bool clear_screen = true;
static int output_rows = 20;
static int sort_by = SORT_BY_CACHE_SIZE;
static int interval = 1;
static int count = 99999999;
static bool verbose = false;

const char argp_program_doc[] =
"Trace slab kmem cache alloc by process.\n"
"\n"
"USAGE: slabtop [-h] [-p PID] [interval] [count]\n"
"\n"
"EXAMPLES:\n"
"    slabtop            # slab rate top, refresh every 1s\n"
"    slabtop -p 181     # only trace PID 181\n"
"    slabtop -s count   # sort columns by count\n"
"    slabtop -f         # sort by file\n"
"    slabtop -r 100     # print 100 rows\n"
"    slabtop 5 10       # 5s summaries, 10 times\n";

static const struct argp_option opts[] = {
	{ "pid", 'p', "PID", 0, "Process ID to trace", 0 },
	{ "all", 'f', NULL, 0, "sort with file", 0 },
	{ "noclear", 'C', NULL, 0, "Don't clear the screen", 0 },
	{ "sort", 's', "SORT", 0, "Sort columns, default size [name, count, size]", 0 },
	{ "rows", 'r', "ROWS", 0, "Maximum rows to print, default 20", 0 },
	{ "verbose", 'v', NULL, 0, "Verbose debug output", 0 },
	{ NULL, 'h', NULL, OPTION_HIDDEN, "Show the full help", 0 },
	{},
};

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
	long pid, rows;
	static int pos_args;
	char *token;

	switch (key) {
	case 'p':
            gl.pid_c = 0;
    
            char *token = strtok(arg, ",");
            while (token != NULL) {
                errno = 0;
                pid = strtol(token, NULL, 10);
                parse_pid_range(token);    
                token = strtok(NULL, ",");
            }
    
            gl.enf = 1;
            gl.type = 0;
            break;
	case 'C':
		clear_screen = false;
		break;
	case 'f':
		gl.type = 0;
		break;
	case 's':
		if (!strcmp(arg, "name")) {
			sort_by = SORT_BY_CACHE_NAME;
		} else if (!strcmp(arg, "count")) {
			sort_by = SORT_BY_CACHE_COUNT;
		} else if (!strcmp(arg, "size")) {
			sort_by = SORT_BY_CACHE_SIZE;
		} else {
			warn("invalid sort method: %s\n", arg);
			argp_usage(state);
		}
		break;
	case 'r':
		errno = 0;
		rows = strtol(arg, NULL, 10);
		if (errno || rows <= 0) {
			warn("invalid rows: %s\n", arg);
			argp_usage(state);
		}
		output_rows = rows;
		if (output_rows > OUTPUT_ROWS_LIMIT)
			output_rows = OUTPUT_ROWS_LIMIT;
		break;
	case 'v':
		verbose = true;
		break;
	case 'h':
		argp_state_help(state, stderr, ARGP_HELP_STD_HELP);
		break;
	case ARGP_KEY_ARG:
		errno = 0;
		if (pos_args == 0) {
			interval = strtol(arg, NULL, 10);
			if (errno || interval <= 0) {
				warn("invalid interval\n");
				argp_usage(state);
			}
		} else if (pos_args == 1) {
			count = strtol(arg, NULL, 10);
			if (errno || count <= 0) {
				warn("invalid count\n");
				argp_usage(state);
			}
		} else {
			warn("unrecognized positional argument: %s\n", arg);
			argp_usage(state);
		}
		pos_args++;
		break;
	default:
		return ARGP_ERR_UNKNOWN;
	}
	return 0;
}

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
	if (level == LIBBPF_DEBUG && !verbose)
		return 0;
	return vfprintf(stderr, format, args);
}

static void sig_int(int signo)
{
	exiting = 1;
}

static int sort_column(const void *obj1, const void *obj2)
{
	struct slabrate_info *s1 = (struct slabrate_info *)obj1;
	struct slabrate_info *s2 = (struct slabrate_info *)obj2;

	if (sort_by == SORT_BY_CACHE_NAME) {
		return strcasecmp(s1->name, s2->name);
	} else if (sort_by == SORT_BY_CACHE_COUNT) {
		return s2->count - s1->count;
	} else if (sort_by == SORT_BY_CACHE_SIZE) {
		return s2->size - s1->size;
	} else {
		return s2->size - s1->size;
	}
}

static int sort_column_ps(const void *obj1, const void *obj2)
{
	struct psslab_info *s1 = (struct psslab_info *)obj1;
	struct psslab_info *s2 = (struct psslab_info *)obj2;

	if (sort_by == SORT_BY_CACHE_COUNT) {
		return s2->count - s1->count;
	} else if (sort_by == SORT_BY_CACHE_SIZE) {
		return s2->size - s1->size;
	} else {
		return s2->size - s1->size;
	}
}

static int print_stat(struct slabtop_bpf *obj)
{
	FILE *f;
	time_t t;
	struct tm *tm;
	char ts[16], buf[256];
	char *key, **prev_key = NULL;
	static struct slabrate_info values[OUTPUT_ROWS_LIMIT];
	static struct psslab_info pvalues[OUTPUT_ROWS_LIMIT];
	int n, i, err = 0, rows = 0;
	int fd;
	if (gl.type == 0)
		fd = bpf_map__fd(obj->maps.slab_entries);
	else
		fd = bpf_map__fd(obj->maps.ps_stat);

	f = fopen("/proc/loadavg", "r");
	if (f) {
		time(&t);
		tm = localtime(&t);
		strftime(ts, sizeof(ts), "%H:%M:%S", tm);
		memset(buf, 0 , sizeof(buf));
		n = fread(buf, 1, sizeof(buf), f);
		if (n)
			printf("%8s loadavg: %s\n", ts, buf);
		fclose(f);
	}
	if (gl.type == 0)
		printf("%-32s %8s %10s\n", "CACHE", "ALLOCS", "BYTES");
	else
		printf("%-32s %8s %10s\n", "PROCESS", "ALLOCS", "BYTES");

	while (1) {
		err = bpf_map_get_next_key(fd, prev_key, &key);
		if (err) {
			if (errno == ENOENT) {
				err = 0;
				break;
			}
			warn("bpf_map_get_next_key failed: %s\n", strerror(errno));
			return err;
		}
		if (gl.type == 0)
			err = bpf_map_lookup_elem(fd, &key, &values[rows++]);
		else
			err = bpf_map_lookup_elem(fd, &key, &pvalues[rows++]);
		if (err) {
			warn("bpf_map_lookup_elem failed: %s\n", strerror(errno));
			return err;
		}
		prev_key = &key;
	}

	if (gl.type == 0) {
		qsort(values, rows, sizeof(struct slabrate_info), sort_column);
	} else {
		qsort(pvalues, rows, sizeof(struct psslab_info), sort_column_ps);
	}
	rows = rows < output_rows ? rows : output_rows;
	for (i = 0; i < rows; i++) {
		if (gl.type == 0) {
			printf("%-20s %6lld %10lld\n",
		       values[i].name, values[i].count, values[i].size);
		} else {
			printf("[%8d] %-20s %6lld %10lld\n",
		        pvalues[i].pid, pvalues[i].comm, pvalues[i].count, pvalues[i].size);
		}
	}

	printf("\n");
	prev_key = NULL;

	while (1) {
		err = bpf_map_get_next_key(fd, prev_key, &key);
		if (err) {
			if (errno == ENOENT) {
				err = 0;
				break;
			}
			warn("bpf_map_get_next_key failed: %s\n", strerror(errno));
			return err;
		}
		err = bpf_map_delete_elem(fd, &key);
		if (err) {
			warn("bpf_map_delete_elem failed: %s\n", strerror(errno));
			return err;
		}
		prev_key = &key;
	}
	return err;
}

int main(int argc, char **argv)
{
	static const struct argp argp = {
		.options = opts,
		.parser = parse_arg,
		.doc = argp_program_doc,
	};
	struct slabtop_bpf *obj;
	int err;
	gl.type = 1;
	gl.enf = 0;
	err = argp_parse(&argp, argc, argv, 0, NULL, NULL);
	if (err)
		return err;

	libbpf_set_print(libbpf_print_fn);

	obj = slabtop_bpf__open();
	if (!obj) {
		warn("failed to open BPF object\n");
		return 1;
	}

	if (kprobe_exists("kmem_cache_alloc"))
		bpf_program__set_autoload(obj->progs.kmem_cache_alloc_noprof, false);
	else if (kprobe_exists("kmem_cache_alloc_noprof"))
		bpf_program__set_autoload(obj->progs.kmem_cache_alloc, false);
	else {
		warn("kmem_cache_alloc and kmem_cache_alloc_noprof function not found\n");
		goto cleanup;
	}

	err = slabtop_bpf__load(obj);
	if (err) {
		warn("failed to load BPF object: %d\n", err);
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
	}

	err = slabtop_bpf__attach(obj);
	if (err) {
		warn("failed to attach BPF programs: %d\n", err);
		goto cleanup;
	}

	if (signal(SIGINT, sig_int) == SIG_ERR) {
		warn("can't set signal handler: %s\n", strerror(errno));
		err = 1;
		goto cleanup;
	}

	while (1) {
		sleep(interval);

		if (clear_screen) {
			err = system("clear");
			if (err)
				goto cleanup;
		}

		err = print_stat(obj);
		if (err)
			goto cleanup;

		count--;
		if (exiting || !count)
			goto cleanup;
	}

cleanup:
	slabtop_bpf__destroy(obj);

	return err != 0;
}
