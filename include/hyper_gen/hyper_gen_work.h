#ifndef _HYPER_GEN_WORK_H
#define _HYPER_GEN_WORK_H


#define WORK_PENDING 0  //for repeat work
#define WORK_STARTED 1  //for oneshot work

struct hyper_gen_work;
typedef void (*hyper_gen_work_fn_t)(struct hyper_gen_work *work);

struct hyper_gen_work {
	struct llist_node node;
	hyper_gen_work_fn_t fn;
	void *opaque;
	unsigned long flags;
};

void hyper_gen_commit_work(struct hyper_gen_work *work);

#endif

