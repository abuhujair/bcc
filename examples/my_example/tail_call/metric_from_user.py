#!/usr/bin/python3

from __future__ import print_function
from typing import Any
from bcc import BPF
from bcc.utils import printb
import ctypes as ct

# Load BPF program
b = BPF(src_file="metric_from_user.c",debug=0)

# Load Functions
main_fn = b.load_func("read_metric", BPF.SOCKET_FILTER)
# tail_fn = b.load_func("tail_call", BPF.SOCKET_FILTER)

# Program Array
# prog_array = b.get_table("prog_array")
# prog_array[ct.c_int(2)] = ct.c_int(tail_fn.fd)

# User Metric_map
TAG_LENGTH = 10
class MetricKey(ct.Structure):
    _pack_ = 1
    _fields_ = [
        ("src_port", ct.c_uint16)
    ]
class MetricData(ct.Structure):
    _pack_ = 1
    _fields_ = [
        ("tag", ct.c_char*TAG_LENGTH),
        ("tag_length",ct.c_uint8),
        ("tag_lps", ct.c_uint8*TAG_LENGTH),
    ]

    def __init__(self, tag, tag_lps) -> None:
        self.tag = tag.encode('utf-8')
        self.tag_length = ct.c_uint8(len(tag))
        self.tag_lps = (ct.c_uint8*TAG_LENGTH)(*tag_lps)
        super().__init__()

def calculateLPS(tag):
    tag_lps = [0]*TAG_LENGTH
    for i in range(1,len(tag)):
        if tag[tag_lps[i-1]] == tag[i]:
            tag_lps[i] = tag_lps[i-1]+1
    return tag_lps

mKey = MetricKey()
mKey.src_port = ct.c_uint16(80)

tag = '\"id\":'
mData = MetricData(tag,calculateLPS(tag))

user_metric = b["user_metric"]
user_metric[mKey] = mData


b.attach_raw_socket(main_fn,"lo")

print("Message:")
# format output
while 1:
    try:
        (task, pid, cpu, flags, ts, msg) = b.trace_fields()
        printb(b"%s" % (msg))
    except KeyboardInterrupt:
        exit()
