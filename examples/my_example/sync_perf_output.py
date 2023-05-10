from __future__ import print_function

from bcc import BPF
from bcc.utils import printb

#BPF Program
prog = """
#include <uapi/linux/ptrace.h>
#include <linux/sched.h>

BPF_HASH(last);

struct data_t {
    u32 pid;
    u64 ts;
    // char comm[TASK_COMM_LEN];
    u64 delta;
};
BPF_PERF_OUTPUT(trace);

int do_trace(struct pt_regs *ctx) {
    struct data_t data = {};
    u64 ts, *tsp, delta, key = 0;

    // attempt to read stored timestamp
    tsp = last.lookup(&key);
    if (tsp != NULL) {
        ts = bpf_ktime_get_ns();
        delta = ts - *tsp;
        if (delta < 1000000000) {
            // output if time is less than 1 second
            data.pid = bpf_get_current_pid_tgid();
            data.ts = ts;
            data.delta = delta;
            // bpf_get_current_comm(&data.comm, sizeof(data.comm));
            trace.perf_submit(ctx, &data, sizeof(data));
            // bpf_trace_printk("%d\\n", delta / 1000000);
        }
        last.delete(&key);
    }

    // update stored timestamp
    ts = bpf_ktime_get_ns();
    last.update(&key, &ts);
    return 0;
}
"""

b = BPF(text=prog)
b.attach_kprobe(event=b.get_syscall_fnname("sync"), fn_name="do_trace")
print("Tracing for quick sync's... Ctrl-C to end")

# # format output
# start = 0
# while 1:
#     try:
#         (task, pid, cpu, flags, ts, ms) = b.trace_fields()
#         if start == 0:
#             start = ts
#         ts = ts - start
#         printb(b"At time %.2f s: multiple syncs detected, last %s ms ago" % (ts, ms))
#     except KeyboardInterrupt:
#         exit()

# process event
start = 0
def print_event(cpu, data, size):
    global start
    event = b["trace"].event(data)
    if start == 0:
        start = event.ts
    ts = event.ts - start
    printb(b"At time %d s: multiple syncs detected, last %d ms ago" % (ts/1000000, event.delta/1000000))

# loop with callback to print_event
b["trace"].open_perf_buffer(print_event)
while 1:
    try:
        b.perf_buffer_poll()
    except KeyboardInterrupt:
        exit()
