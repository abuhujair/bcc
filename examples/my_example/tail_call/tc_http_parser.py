from bcc import BPF
from bcc.utils import printb

from pyroute2 import IPRoute
from pyroute2 import IPDB
import traceback
import ctypes as ct
import socket


# def print_skb_event(cpu, data, size):
#     class Data(ct.Structure):
#         _fields_ =  [ ("payload_offset", ct.c_uint32),
#                       ("payload_length", ct.c_uint32) ]

#     class SkbEvent(ct.Structure):
#         _fields_ =  [ ("magic", ct.c_uint32),
#                       ("raw", ct.c_ubyte * (size - ct.sizeof(ct.c_uint32))) ]

#     skb_event = ct.cast(data, ct.POINTER(SkbEvent)).contents
#     print("%-3s 0x%08x" %
#             (cpu,
#             skb_event.magic))

bpf = BPF(src_file="tc_http_parser.c",debug=0)
fn = bpf.load_func("tcp_header_parser",BPF.SCHED_CLS)

tail_fn1000 = bpf.load_func("http_payload_parser1000", BPF.SCHED_CLS)
tail_fn100 = bpf.load_func("http_payload_parser100", BPF.SCHED_CLS)
tail_fn10 = bpf.load_func("http_payload_parser10", BPF.SCHED_CLS)

prog_array = bpf.get_table("prog_array")
prog_array[ct.c_int(2)] = ct.c_int(tail_fn1000.fd)
prog_array[ct.c_int(3)] = ct.c_int(tail_fn100.fd)
prog_array[ct.c_int(4)] = ct.c_int(tail_fn10.fd)

ipr = IPRoute()

lo_idx = ipr.link_lookup(ifname="lo")[0]

try:
    ipr.tc("add","ingress",lo_idx,"ffff:")
except Exception as e:
    print(e)

try:
    ipr.tc("add-filter", "bpf", lo_idx, ":2", fd = fn.fd, name = fn.name, parent = "ffff:",action = "ok", classid = 1)
except Exception as e:
    print(traceback.format_exc())
    ipr.tc("del","clsact",lo_idx,"ffff:")
    exit(0)


# bpf["skb_events"].open_perf_buffer(print_skb_event)
print("%-3s %-10s" % ("CPU", "Magic"))

st = ""
while True:
    try:
        (task, pid, cpu, flags, ts, msg) = bpf.trace_fields()
        if len(msg)!=2:
            if st!="":
                print((bytes.fromhex(st)).decode('utf-8'))
                print(len(st))
                st = ""
            printb(b"%s" % (msg))
        else:
            st += msg.decode('utf-8')
    except KeyboardInterrupt:
        ipr.tc("del","ingress",lo_idx,"ffff:")
        print("")
        exit()
