#!/usr/bin/python
#
# sync_timing.py    Trace time between syncs.
#                   For Linux, uses BCC, eBPF. Embedded C.
#
# Written as a basic example of tracing time between events.
#
# Copyright 2016 Netflix, Inc.
# Licensed under the Apache License, Version 2.0 (the "License")

from __future__ import print_function
from bcc import BPF
from bcc.utils import printb

# load BPF program
b = BPF(text="""
#include <uapi/linux/ptrace.h>

BPF_HASH(last);

int do_trace(struct pt_regs *ctx) {
    u64 count, *count_p, key = 0;

    // attempt to read stored timestamp
    count_p = last.lookup(&key);
    if (count_p != NULL) {
        count = *count_p+1;
    }
    else
    {
    	count = 1; 
    }
    bpf_trace_printk("%d\\n", count);

    // update stored count
    last.update(&key, &count);
    return 0;
}
""")

b.attach_kprobe(event=b.get_syscall_fnname("sync"), fn_name="do_trace")
print("Tracing for quick sync's... Ctrl-C to end")

# format output
start = 0
while 1:
    try:
        (task, pid, cpu, flags, ts, count) = b.trace_fields()
        printb(b"At time %.2f s: sync detected, count %s" % (ts, count))
    except KeyboardInterrupt:
        exit()
