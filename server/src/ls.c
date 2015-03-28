#define _ATFILE_SOURCE
#include <fcntl.h>
#include <sys/stat.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <sys/time.h>
#include <dirent.h>
#include <time.h>
#include <errno.h>

#include <debug.h>
#include <mem.h>

#define MAX_UID_LEN 5
#define MAX_GID_LEN 5

static char *
get_perm(mode_t st_mode, char *perm)
{
	int i; 

	/* clean */
	for (i = 0; i < 9; i++)
		*(perm + i) = '-';

	*(perm + 0) = '?';
	switch (st_mode & S_IFMT) {
		case S_IFDIR: *(perm + 0)  = 'd'; break;
		case S_IFREG: *(perm + 0)  = '-'; break;
		case S_IFLNK: *(perm + 0)  = 'l'; break;
		case S_IFBLK: *(perm + 0)  = 'b'; break;
		case S_IFCHR: *(perm + 0)  = 'c'; break;
		case S_IFSOCK: *(perm + 0) = 's'; break;
		case S_IFIFO: *(perm + 0)  = 'p'; break;
	}

	(st_mode & S_IRUSR) ? (*(perm + 1) = 'r'):
		(*(perm + 1) = '-');
	(st_mode & S_IWUSR) ? (*(perm + 2) = 'w'):
		(*(perm + 2) = '-');
	(st_mode & S_IXUSR) ? (*(perm + 3) = 'x'):
		(*(perm + 3) = '-');
	(st_mode & S_IRGRP) ? (*(perm + 4) = 'r'):
		(*(perm + 4) = '-');
	(st_mode & S_IWGRP) ? (*(perm + 5) = 'w'):
		(*(perm + 5) = '-');
	(st_mode & S_IXGRP) ? (*(perm + 6) = 'x'):
		(*(perm + 6) = '-');
	(st_mode & S_IROTH) ? (*(perm + 7) = 'r'):
		(*(perm + 7) = '-');
	(st_mode & S_IWOTH) ? (*(perm + 8) = 'w'):
		(*(perm + 8) = '-');
	(st_mode & S_IXOTH) ? (*(perm + 9) = 'x'):
		(*(perm + 9) = '-');

	*(perm + 10) = '\0';
	return perm;
}

static int
get_file_attr(DIR *d, const char *f_name, struct stat *st)
{
	int dir_fd;
	int ret;

	if (d) {
		dir_fd = dirfd(d);
		if (dir_fd != -1) {
			ret = fstatat(dir_fd, f_name, st, AT_SYMLINK_NOFOLLOW);
			if (ret == 0)
				return 1;
			else
				PRINT_DEBUG("fstatat error: %s\n", strerror(errno));
		} else {
			PRINT_DEBUG("dirfd error: %s\n", strerror(errno));
		}
	}

	return 0;
}

static struct dirent *
get_dirent_entry(DIR *dir_name)
{
	struct dirent *d = NULL;

	if (dir_name != NULL) {
		d = readdir(dir_name);
		if (d == NULL) {
			return NULL;
		} else if (d->d_name[0] == '.' && d->d_name[1] == '\0') {
			d = get_dirent_entry(dir_name);
		}
	}

	return d;
}

static int
get_mtime(time_t time, char *mtime, int mtime_len)
{
	const char *date_format = "%b %d %H:%M";
	struct timeval c_time;
	struct tm *tm = NULL;
	
	if (gettimeofday(&c_time, NULL) != -1 && mtime_len > 0) {
		if (time > c_time.tv_sec ||
		    (c_time.tv_sec - time) > 60 * 60 * 24 * 182) {
			date_format = "%b %d  %Y";
		}

		tm = localtime(&time);
		strftime(mtime, mtime_len - 1, date_format, tm);
		return 1;
	}

	return 0;
}

int
build_list_line(const char *name, struct stat *st, char *line, int l_size, int short_l)
{
	char mtime[20] = {'\0'};
	char perm[11] = {'\0'};
	int ret = -1;

	if (!short_l) {
		/* Permissions */
		(void) get_perm(st->st_mode, perm);
		/* time of last modification */
		(void) get_mtime(st->st_mtime, mtime, sizeof(mtime));
		/* build the line */
		ret = snprintf(line, l_size - 1, "%s%4u %-*u  %-*u %*ld %s %s\r\n",
					   perm, (unsigned int) st->st_nlink, MAX_UID_LEN, st->st_uid,
					   MAX_GID_LEN, st->st_gid, 10, st->st_size, mtime, name);
	} else {
		ret = snprintf(line, l_size - 1, "%s\r\n", name);
	}

	return ret;
}

char *
get_file_list_chunk(DIR *dir, int nfiles, int short_list)
{
	struct dirent *d = NULL;
	char line[400] = {'\0'};
	char *chunk = NULL;
	int len = 0;

	if (nfiles > 0) {
		chunk = (char *) calloc(nfiles * sizeof(line), sizeof(char));
		if (chunk == NULL)
			FATAL_ERROR("error: %s\n", strerror(errno));

		for (int i = 0; i < nfiles; i++) {
			d = get_dirent_entry(dir);
			if (d != NULL) {
				struct stat st;
				int ret;

				ret = get_file_attr(dir, d->d_name, &st);
				if (ret) {
					if (short_list == 0) {
						len += build_list_line(d->d_name, &st, line, sizeof(line), 0);
					} else {
						len += build_list_line(d->d_name, &st, line, sizeof(line), 1);
					}

					/* attach to the chunk */
					(void) strcat(chunk, line);
				}
			}
		}

		if (len > 0)
			return chunk;
	}

	if (chunk)
		free(chunk);

	return NULL;
}
