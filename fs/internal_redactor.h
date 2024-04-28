
struct tracepoint;
struct file;
int run_bpf_redactor(struct tracepoint* tp, void *ctx);
int increment_redactor_count(struct file *file, int inc);
int zero_redactor_count(struct file *file);

