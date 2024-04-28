#include "linux/stddef.h"
#include <linux/printk.h>
#include <linux/bpf.h>
#include <linux/filter.h>
#include <linux/kmod.h>
#include <linux/module.h>
#include <linux/fs_bpf_redactor.h>

#include "internal_redactor.h"


int bpf_prog_test_run_redactor(struct bpf_prog *prog,
			 const union bpf_attr *kattr,
			 union bpf_attr __user *uattr)
{
	printk("MB - BPF_PROG_TEST_RUN_REDACTOR");
	return 0;
}

const struct bpf_prog_ops redactor_prog_ops = {
	.test_run = bpf_prog_test_run_redactor,
};


static bool redactor_is_valid_access(int off, int size, enum bpf_access_type type,
			       const struct bpf_prog *prog,
			       struct bpf_insn_access_aux *info)
{
	if (off < 0 || off >= sizeof(struct redactor_ctx))
		return false;

	if (type == BPF_WRITE)
		return false;

	if (off == offsetof(struct redactor_ctx, offset)) {
		printk("MB - redactor_is_valid_access - offset with size %d)", size);
		if (size == sizeof_field(struct redactor_ctx, offset)){
			return true;
		}
	}
	if (off == offsetof(struct redactor_ctx, size)) {
		printk("MB - redactor_is_valid_access - size with size %d)", size);
		if (size == sizeof_field(struct redactor_ctx, size)){
			return true;
		}
	}
	if (off == offsetof(struct redactor_ctx, flags)) {
		printk("MB - redactor_is_valid_access - flags with size %d)", size);
		if (size == sizeof_field(struct redactor_ctx, flags)){
			return true;
		}
	}
	if (off == offsetof(struct redactor_ctx, mode)) {
		printk("MB - redactor_is_valid_access - mode with size %d)", size);
		if (size == sizeof_field(struct redactor_ctx, mode)){
			return true;
		}
	}
	if (off == offsetof(struct redactor_ctx, uid)) {
		printk("MB - redactor_is_valid_access - uid with size %d)", size);
		if (size == sizeof_field(struct redactor_ctx, uid)){
			return true;
		}
	}
	if (off == offsetof(struct redactor_ctx, gid)) {
		printk("MB - redactor_is_valid_access - gid with size %d)", size);
		if (size == sizeof_field(struct redactor_ctx, gid)){
			return true;
		}
	}

	return false;
}

static const struct bpf_func_proto *
bpf_redactor_func_proto(enum bpf_func_id func_id, const struct bpf_prog *prog)
{
	return bpf_base_func_proto(func_id);
}


int bpf_redactor_decide(struct redactor_ctx *x)
{
  return 0;
}

int bpf_redactor_redact(struct redactor_ctx *prg)
{
  return 0;
}


const struct bpf_verifier_ops redactor_verifier_ops = {
	.is_valid_access	= redactor_is_valid_access,
	.get_func_proto		= bpf_redactor_func_proto,
};

int
run_bpf_redactor(struct tracepoint* tp, void *ctx)
{
	int iter_probe;
	rcu_read_lock();
	int result = -EINVAL;

	struct tracepoint_func* funcs = rcu_dereference(tp->funcs);
	if (funcs)
	{
		pr_info("run_bpf_redactor - MB - Funkcje istnieją");

		for (iter_probe = 0; funcs[iter_probe].func; iter_probe++)
		{
			
		}
		pr_info("run_bpf_redactor - MB - number of attached functions %d", iter_probe);
		
		for (iter_probe = 0; funcs[iter_probe].func; iter_probe++)
		{
			struct bpf_prog* prog = funcs[iter_probe].data;
			if (prog->type == BPF_PROG_TYPE_REDACTOR)
			{
			  result = bpf_prog_run(prog, ctx);
			  break;
			}
		}
		
	}
	rcu_read_unlock();
	pr_info("run_bpf_redactor - MB - result %d", result);
	
	return result;
}
