#ifndef FS_BPF_REDACTOR
#define FS_BPF_REDACTOR

#include <linux/uidgid.h>

struct redactor_ctx {
union {
        struct {
                loff_t offset;
                size_t size;
        };
        struct {
                u64 flags;
                umode_t mode;
                kuid_t uid;
                kgid_t gid;
        };
};
};

int bpf_redactor_decide(struct redactor_ctx *);
int bpf_redactor_redact(struct redactor_ctx *);

#endif
