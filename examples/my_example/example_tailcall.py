#!/usr/bin/python3

from __future__ import print_function
from bcc import BPF
from bcc.utils import printb
from ctypes import *

# load BPF program
b = BPF(text="""
BPF_PROG_ARRAY(prog_array, 10);

int tail_call(void *ctx) {
    bpf_trace_printk("Tail-call\\n");
    prog_array.call(ctx,2);
    return 0;
}

int do_tail_call(void *ctx) {
    bpf_trace_printk("Original program\\n");
    prog_array.call(ctx, 2);
    return 0;
}
""")

tail_fn = b.load_func("tail_call", BPF.KPROBE)
prog_array = b.get_table("prog_array")
prog_array[c_int(2)] = c_int(tail_fn.fd)
b.attach_kprobe(event=b.get_syscall_fnname("clone"), fn_name="do_tail_call")

# format output
while 1:
    try:
        (task, pid, cpu, flags, ts, msg) = b.trace_fields()
        printb(b"%s %s" % (msg, task))
    except KeyboardInterrupt:
        exit()
