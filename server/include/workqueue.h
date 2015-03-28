#ifndef __WORKQUEUE_H__
#define __WORKQUEUE_H__

#include <pthread.h>

/* local */
#include <list.h>
#include <mutex.h>

enum {
	WORK_STRUCT_PENDING_BIT = 0,
	WORK_STRUCT_RUNNING_BIT = 1,
	WORK_STRUCT_STOPPED_BIT = 2,
	WORK_STRUCT_PENDING = (1 << WORK_STRUCT_PENDING_BIT),
	WORK_STRUCT_RUNNING = (1 << WORK_STRUCT_RUNNING_BIT),
	WORK_STRUCT_STOPPED = (1 << WORK_STRUCT_STOPPED_BIT),
};

struct work_struct;
typedef void (*work_func_t)(struct work_struct *work);

struct work_struct {
	work_func_t func;
	void *data;
	int flags;

	TAILQ_ENTRY(work_struct) entries;
};

struct workqueue_struct {
	pthread_t thread;
	const char *name;
	mutex_t mutex;
	cond_t cond;
	TAILQ_HEAD(work_list, work_struct) list;
};

#define INIT_WORK(work, fn)						\
	do {										\
		work.func = fn;							\
		work.data = NULL;						\
		work.flags = 0;							\
	} while (0)

#endif	/* __WORKQUEUE_H__ */
