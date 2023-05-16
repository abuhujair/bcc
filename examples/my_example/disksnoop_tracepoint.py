#!/usr/bin/python3

from __future__ import print_function
from bcc import BPF
from bcc.utils import printb

# load BPF program
b = BPF(text="""
#include <linux/sched.h>
#include <uapi/linux/ptrace.h>
#include <linux/random.h>

struct data_t{
    u64 ts;
    u32 bytes;
};

BPF_HASH(start, u64, struct data_t);

TRACEPOINT_PROBE(block, block_rq_issue) {
    // args is from /sys/kernel/debug/tracing/events/block/block_rq_issue/format
    // stash start timestamp by request ptr
    struct data_t data = {};

	data.ts = bpf_ktime_get_ns();
	data.bytes = args->bytes;
	u64 pid = bpf_get_current_pid_tgid();
	start.update(&pid, &data);
    return 0;
}

TRACEPOINT_PROBE(block, block_rq_complete) {
    // args is from /sys/kernel/debug/tracing/events/random/urandom_read/format
    
    u64 delta = bpf_ktime_get_ns();
    u64 pid = bpf_get_current_pid_tgid();
	
    struct data_t * data = start.lookup(&pid);
	
    if (data != 0) {
		delta = delta - data->ts;
		bpf_trace_printk("%u %x %d\\n",  
            data->bytes, args->rwbs, delta / 1000);
		start.delete(&pid);
	}
    return 0;
}
""")

REQ_WRITE = 1		# from include/linux/blk_types.h

# header
print("%-18s %-2s %-7s %8s" % ("TIME(s)", "T", "BYTES", "LAT(ms)"))

# format output
# format output
while 1:
	try:
		(task, pid, cpu, flags, ts, msg) = b.trace_fields()
		(bytes_s, bflags_s, us_s) = msg.split()

		if int(bflags_s, 16) & REQ_WRITE:
			type_s = b"W"
		elif bytes_s == "0":	# see blk_fill_rwbs() for logic
			type_s = b"M"
		else:
			type_s = b"R"
		ms = float(int(us_s, 10)) / 1000

		printb(b"%-18.9f %-2s %-7s %8.2f" % (ts, type_s, bytes_s, ms))
	except KeyboardInterrupt:
		exit()
