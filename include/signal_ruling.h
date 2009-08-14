#ifndef __SIGNAL_RULING_H__
#define __SIGNAL_RULING_H__

extern void signal_handle(int sig);
extern void signal_unhandle(int sig);
extern int signal_is_pending(int sig);
extern void signal_clear(int sig);
extern void signal_ignore(int sig);

#endif	/* __SIGNAL_RULING_H__ */
