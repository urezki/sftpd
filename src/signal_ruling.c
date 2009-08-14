#include <stdio.h>
#include <signal.h>
#include <errno.h>
#include <stddef.h>

static volatile sig_atomic_t __caught_signals[NSIG];

static void
__signal_handler(int sig)
{
	__caught_signals[sig] = 1;
}

static void
__set_signal_handler(int sig, void (*handler)(int))
{
	struct sigaction act;

	act.sa_flags = 0;
	sigemptyset(&act.sa_mask);
	act.sa_handler = handler;

	while (sigaction(sig, &act, NULL) && errno == EINTR) ;
}

void
signal_handle(int sig)
{
	__set_signal_handler(sig, __signal_handler);
}

void
signal_clear(int sig)
{
	__caught_signals[sig] = 0;
}

void
signal_unhandle(int sig)
{
	signal_clear(sig);
	__set_signal_handler(sig, SIG_DFL);
}

void
signal_ignore(int sig)
{
	signal_clear(sig);
	__set_signal_handler(sig, SIG_IGN);
}

int
signal_is_pending(int sig)
{
	return __caught_signals[sig];
}

