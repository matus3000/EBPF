#undef TRACE_SYSTEM
#define TRACE_SYSTEM bpf_redactor_decide

#if !defined(_TRACE_BPF_REDACTOR_DECIDE_H) || defined(TRACE_HEADER_MULTI_READ)
#define _TRACE_BPF_REDACTOR_DECIDE_H

#include <linux/tracepoint.h>
#include <linux/fs_bpf_redactor.h>

TRACE_EVENT(bpf_redactor_decide, TP_PROTO(const struct redactor_ctx *ctx),
	    TP_ARGS(ctx),
	    TP_STRUCT__entry(
		    __field(loff_t, offset)
		    __field(size_t, size)
		    __field(u64, flags)
		    __field(umode_t, mode)
		    __field(uid_t, uid_val)
		    __field(gid_t, gid_val)
		    ),
	    TP_fast_assign(__entry->offset = ctx->offset;
			   __entry->size = ctx->size;
			   __entry->flags = ctx->flags;
			   __entry->mode = ctx->mode;
			   __entry->uid_val = ctx->uid.val;
			   __entry->gid_val = ctx->gid.val;),

	    TP_printk("bpf_redactor_decide %d", 0));

#endif

#include <trace/define_trace.h>
