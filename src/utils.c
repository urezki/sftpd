#include <stdio.h>
#include <sys/types.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <debug.h>

/* local headers */
#include <list.h>
#include <mem.h>

void
set_euid(uid_t euid)
{
	FUNC_ENTRY();

	if (seteuid(euid) < 0)
		PRINT_DEBUG("seteuid [%d] failed with errno %u: %s\n",
				  euid, errno, strerror(errno));
	
	FUNC_EXIT_VOID();
}

void
reset_euid(void)
{
	FUNC_ENTRY();

	if (seteuid(0) < 0)
		PRINT_DEBUG("seteuid failed with errno %d: %s\n",
				  errno, strerror(errno));

	FUNC_EXIT_VOID();
}

void
set_egid(gid_t egid)
{
	FUNC_ENTRY();
	
	if (setegid(egid) < 0)
		PRINT_DEBUG("setegid [%d] failed with errno %u: %s\n",
				  egid, errno, strerror(errno));
	
	FUNC_EXIT_VOID();
}

void
reset_egid(void)
{
	FUNC_ENTRY();

	if (setegid(0) < 0)
		PRINT_DEBUG("setegid failed with errno %d: %s\n",
				  errno, strerror(errno));
	
	FUNC_EXIT_VOID();
}
