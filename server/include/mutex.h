#ifndef __MUTEX_H__
#define __MUTEX_H__

typedef pthread_mutex_t mutex_t;
typedef pthread_cond_t cond_t;

/* condition wrappers */
#define cond_wait_unlock_lock_mutex(c, m) pthread_cond_wait(&c, &m)
#define cond_send_signal(c) pthread_cond_signal(&c)

#define INIT_CONDITION(cond)									\
	do {														\
		cond_t tmp = PTHREAD_COND_INITIALIZER;					\
		cond = tmp;												\
	} while (0)

/* mutex wrappers */
#define mutex_init(m, attr)	pthread_mutex_init((m), (attr))
#define mutex_lock(m) pthread_mutex_lock(m)
#define mutex_unlock(m)	pthread_mutex_unlock(m)

#endif	/* __MUTEX_H__ */
