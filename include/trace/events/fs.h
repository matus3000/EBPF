/* SPDX-License-Identifier: GPL-2.0 */

#undef TRACE_SYSTEM
#define TRACE_SYSTEM fs

#if !defined(_TRACE_FS_H) || defined(TRACE_HEADER_MULTI_READ)
#define _TRACE_FS_H

#include <linux/tracepoint.h>

struct redactor_ctx;

TRACE_EVENT(bpf_redacator_decide,
	    TP_PROTO(const struct redactor_ctx *ctx),
	    TP_ARGS(ctx),
	    TP_STRUCT__entry(
			     __field(const struct redactor_ctx*, ctx)
			     ),
	    TP_fast_assign(
			   __entry->ctx = ctx;
			   ),
	    
	    TP_printk("bpf_redactor_decide")
);

TRACE_EVENT(bpf_redactor_redact,
	TP_PROTO(const struct redactor_ctx *ctx),
	TP_ARGS(ctx),
	TP_STRUCT__entry(
			__field(const struct redactor_ctx*, ctx)
	),
	TP_fast_assign(
		       __entry->ctx = ctx;
	),
	TP_printk("bpf_redactor_redact")
);

#endif

#include <trace/define_trace.h>
