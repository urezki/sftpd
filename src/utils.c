#define _ATFILE_SOURCE
#include <stdio.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <dirent.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>

/* local headers */
#include <list.h>
#include <mem.h>
#include <debug.h>

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

/*
 * return zero if success like rmdir
 */
int
remove_folder(const char *dir)
{
	struct dirent *drnt;
	char path[4096] = {'\0'};
	struct stat st;
	int ret = -1;
	int dir_fd;
	DIR *d;

	d = opendir(dir);
	if (d) {
		dir_fd = dirfd(d);
		while ((drnt = readdir(d))) {
			if ((drnt->d_name[0] == '.' && drnt->d_name[1] == '\0') ||
				((drnt->d_name[0] == '.' && drnt->d_name[1] == '.') && drnt->d_name[2] == '\0'))
				continue;

			ret = fstatat(dir_fd, drnt->d_name, &st, AT_SYMLINK_NOFOLLOW);
			if (ret == 0) {
				if (S_ISDIR(st.st_mode)) {
					snprintf(path, sizeof(path) - 1, "%s/%s", dir, drnt->d_name);
					remove_folder(path);
				} else {
					unlinkat(dir_fd, drnt->d_name, 0);
				}
			}
		}

		ret = rmdir(dir);
		closedir(d);
	}

	return ret;
}
