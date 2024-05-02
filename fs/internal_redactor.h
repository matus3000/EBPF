#ifndef FS_INTERNAL_REDACTOR_H
#define FS_INTERNAL_REDACTOR_H

#include <linux/fs_bpf_redactor.h>

struct internal_ctx {
	struct redactor_ctx ctx;
	char * buf; 
};


struct tracepoint;
struct file;
int run_bpf_redactor(struct tracepoint* tp, void *ctx);
int increment_redactor_count(struct file *file, int inc);
int zero_redactor_count(struct file *file);

#endif
