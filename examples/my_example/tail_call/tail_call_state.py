#!/usr/bin/python3

from __future__ import print_function
from bcc import BPF
from bcc.utils import printb
from ctypes import *

# load BPF program
b = BPF(src_file="tail_call_state.c",debug=0)

main_fn = b.load_func("do_tail_call", BPF.SOCKET_FILTER)
tail_fn = b.load_func("tail_call", BPF.SOCKET_FILTER)

prog_array = b.get_table("prog_array")
prog_array[c_int(2)] = c_int(tail_fn.fd)

b.attach_raw_socket(main_fn,"lo")

# format output
while 1:
    try:
        (task, pid, cpu, flags, ts, msg) = b.trace_fields()
        printb(b"%s %s" % (msg, task))
    except KeyboardInterrupt:
        exit()
