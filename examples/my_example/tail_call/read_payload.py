#!/usr/bin/python3

from __future__ import print_function
from typing import Any
from bcc import BPF
from bcc.utils import printb
import ctypes as ct

# Load BPF program
b = BPF(src_file="read_payload.c",debug=0)

# Load Functions
main_fn = b.load_func("read_metric", BPF.SOCKET_FILTER)

b.attach_raw_socket(main_fn,"lo")

print("Message:")
# format output
while 1:
    try:
        (task, pid, cpu, flags, ts, msg) = b.trace_fields()
        printb(b"%s %s" % (task, msg))
    except KeyboardInterrupt:
        exit()
