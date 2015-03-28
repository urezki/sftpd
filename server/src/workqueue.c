#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

/* local */
#include <workqueue.h>
#include <debug.h>

static void *
worker_thread(void *arg)
{
	struct workqueue_struct *wq;
	struct work_struct *work;
	int rv;

	wq = (struct workqueue_struct *) arg;
	rv = pthread_detach(wq->thread);
	if (rv)
		handle_error("pthread_detach error\n");

	while (1) {
		mutex_lock(&wq->mutex);
		if (!TAILQ_EMPTY(&wq->list)) {
			work = TAILQ_FIRST(&wq->list);
			work->flags = WORK_STRUCT_RUNNING;
			TAILQ_REMOVE(&wq->list, work, entries);
		} else {
			/* wait, till signal wakes up */
			cond_wait_unlock_lock_mutex(wq->cond, wq->mutex);
		}
		mutex_unlock(&wq->mutex);

		if (work) {
			work->func(work->data);
			work = NULL;
		}
	}

	return NULL;
}

struct workqueue_struct *
create_single_work_thread(const char *name)
{
	struct workqueue_struct *wq;
	int rv;

	wq = calloc(1, sizeof(*wq));
	if (wq == NULL)
		handle_error("calloc error\n");

	wq->name = name;
	INIT_CONDITION(wq->cond);
	(void) mutex_init(&wq->mutex, NULL);
	TAILQ_INIT(&wq->list);

	rv = pthread_create(&wq->thread, NULL, worker_thread, (void *) wq);
	if (rv)
		handle_error("pthread_create error\n");

	return wq;
}

static int
do_queue_work(struct workqueue_struct *wq, struct work_struct *work)
{
	int rv = 0;

	if (work->flags != WORK_STRUCT_PENDING) {
		work->flags = WORK_STRUCT_PENDING;
		TAILQ_INSERT_TAIL(&wq->list, work, entries);
		rv = 1;
	}

	return rv;
}

/**
 * returns 0 if @work is already in @wq, 1 otherwise
 */
int queue_work(struct workqueue_struct *wq, struct work_struct *work)
{
	int ret = 0;

	if (wq && work) {
		mutex_lock(&wq->mutex);
		ret = do_queue_work(wq, work);
		if (ret)
			cond_send_signal(wq->cond);
		mutex_unlock(&wq->mutex);
	}

	return ret;
}

#ifdef TEST
static void
work_func_1(struct work_struct *work)
{
	fprintf(stdout, "--> %s:%d\n", __func__, __LINE__);
}

static void
work_func_2(struct work_struct *work)
{
	fprintf(stdout, "--> %s:%d\n", __func__, __LINE__);
}

int main(int argc, char **argv)
{
	struct workqueue_struct *wq;
	struct work_struct work_1;
	struct work_struct work_2;

	INIT_WORK(work_1, work_func_1);
	INIT_WORK(work_2, work_func_2);

	wq = create_single_work_thread("worker/1");

	while (1) {
		(void) queue_work(wq, &work_1);
		(void) queue_work(wq, &work_2);
		usleep(700000);
	}

	return 0;
}
#endif
