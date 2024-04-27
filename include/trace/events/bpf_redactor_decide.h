#undef TRACE_SYSTEM
#define TRACE_SYSTEM bpf_redactor_decide

#if !defined(_TRACE_BPF_REDACTOR_DECIDE_H) || defined(TRACE_HEADER_MULTI_READ)
#define _TRACE_BPF_REDACTOR_DECIDE_H

#include <linux/tracepoint.h>

struct redactor_ctx;

TRACE_EVENT(bpf_redactor_decide,
	    TP_PROTO(const struct redactor_ctx *ctx),
	    TP_ARGS(ctx),
	    TP_STRUCT__entry(
			     __field(const struct redactor_ctx*, ctx)
			     ),
	    TP_fast_assign(
			   __entry->ctx = ctx;
			   ),
	    
	    TP_printk("bpf_redactor_decide %d", 0)
);

#endif

#include <trace/define_trace.h>
