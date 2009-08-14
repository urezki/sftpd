#include <sys/stat.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <dirent.h>
#include <langinfo.h>
#include <sys/time.h>
#include <sys/socket.h>
#include <netinet/in.h>

#include <grp.h>
#include <pwd.h>
#include <time.h>

#include <list.h>
#include <sock_utils.h>
#include <debug.h>
#include <sftpd.h>
#include <ls.h>
#include <mem.h>

#define MAX_UID_LEN 5
#define MAX_GID_LEN 5

#define R 000000001		/* read */
#define W 000000010		/* write */
#define X 000000100		/* execute */

static char *
get_perm(mode_t st_mode, char *perm)
{
	int i; 
	
	for (i = 0; i < 9; i++)
		*(perm + i) = '-';
	
	*(perm + 0) = '?';
	switch (st_mode & S_IFMT)
	{
		case S_IFDIR: *(perm + 0) = 'd';
			break;
		case S_IFREG: *(perm + 0) = '-';
			break;
		case S_IFLNK: *(perm + 0) = 'l';
			break;
		case S_IFBLK: *(perm + 0) = 'b';
			break;
		case S_IFCHR: *(perm + 0) = 'c';
			break;
		case S_IFSOCK: *(perm + 0) = 's';
			break;
		case S_IFIFO: *(perm + 0) = 'p';
			break;
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
get_file_attr(char *file_name, char *dir_name, struct stat *st)
{
	size_t file_len = 0;
	size_t dir_len = 0;
	char *file_path;
	int retval = -1;
	
	file_len = strlen(file_name);
	dir_len = strlen(dir_name);
	
	if (file_name > 0 && dir_name > 0) {
		file_path = (char *) malloc(file_len + dir_len + 2);
		if (file_path != NULL) {
			snprintf(file_path, dir_len + file_len + 2, "%s/%s%c",
				 dir_name, file_name, '\0');
			
			retval = stat(file_path, st);
			if (retval < 0)
				PRINT_DEBUG("error: %s %d\n", __FUNCTION__, __LINE__);
			free(file_path);
		} else {
			PRINT_DEBUG("error: %s %d\n", __FUNCTION__, __LINE__);
		}
		
	} else {
		PRINT_DEBUG("error: %s %d\n", __FUNCTION__, __LINE__);
	}
	
	return retval;
}

static int
feel_node(__str *str_node, char *dir_name, char *f_name,
	   unsigned int f_len, off_t *max_size_len)
{
	struct stat st;
	int retval = 0;
	
	/* calloc (f_len + 1) for '\0' !!! */
	str_node->f_name = calloc(f_len + 1, sizeof(char));
	if (!str_node->f_name)
		FATAL_ERROR("error allocating memory\n");
	
	strncpy(str_node->f_name, f_name, f_len);
	str_node->f_name[f_len] = '\0';
	str_node->f_len = f_len;
		
	retval = get_file_attr(f_name, dir_name, &st);
	if (retval != -1) {
		str_node->uid = st.st_uid;
		str_node->gid = st.st_gid;
		str_node->st_nlink = st.st_nlink;
		str_node->st_size = st.st_size;
		str_node->time = st.st_mtime;
		str_node->mode = st.st_mode;
		if (st.st_size > *max_size_len)
			*max_size_len = st.st_size;
	} else {
		PRINT_DEBUG("error: %s %d\n", __FUNCTION__, __LINE__);
		free(str_node->f_name);
		str_node->f_name = NULL;
	}
	
	return retval;
}

static struct dirent *
next_entry(DIR *dir_name)
{
	struct dirent *next_dnt;
	
	if (dir_name != NULL) {
		next_dnt = readdir(dir_name);
		if (next_dnt == NULL)
			return NULL;
		else if (next_dnt->d_name[0] == '.' && next_dnt->d_name[1] == '\0')
		{
			next_dnt = next_entry(dir_name);
		}
	}
	
	return next_dnt;
}

static __str **
do_readdir(char *dir_name, off_t *max_size_len, int *file_count)
{
	struct dirent *pp = NULL;
	DIR *open_dir = NULL;
	struct stat st;
	__str **list = NULL;
	
	int guess_size = 0;
	int retval = 0;
	
	*file_count = 0;
	retval = stat(dir_name, &st);
	open_dir = opendir(dir_name);
	
	if (retval < 0 || opendir == NULL || !S_ISDIR(st.st_mode)) {
		PRINT_DEBUG("error: %s %d\n", __FUNCTION__, __LINE__);
		goto out;
	}
	
	/* magic number */
	guess_size = st.st_size / 20;
	if (guess_size == 0)
		guess_size = 50;
	
	list = (__str **) calloc(guess_size, sizeof(__str *));
	if (list == NULL) {
		PRINT_DEBUG("error: %s %d\n", __FUNCTION__, __LINE__);
		goto out;
	}
	
	while (1) {
		if (guess_size == *file_count) {
			__str **new_pp;

			new_pp = (__str **) realloc(list, 2 * guess_size * sizeof(__str *));
			if (new_pp == NULL && !(list = NULL)) {
				PRINT_DEBUG("error: %s %d\n", __FUNCTION__, __LINE__);
				goto out;
			}
			
			list = new_pp;
			guess_size *= 2;
		}

		if ((pp = next_entry(open_dir)) == NULL)
			break;
		
		list[*file_count] = (__str *) calloc(1, sizeof(__str));
		if (list[*file_count] != NULL) {
			retval = feel_node(list[*file_count], dir_name, pp->d_name,
					   pp->d_reclen, max_size_len);
			if (retval == -1) {
				PRINT_DEBUG("error: %s %d\n", __FUNCTION__, __LINE__);
				free(list[*file_count]);
				continue;
			}
		} else {
			PRINT_DEBUG("error: %s %d\n", __FUNCTION__, __LINE__);
			list = NULL;
			goto out;
		}
		
		(*file_count)++;
	} /* while (1) */
	
	/* last element */
	list[*file_count] = NULL;
out:
	if (closedir(open_dir) < 0)
		PRINT_DEBUG("error: %s %d\n", __FUNCTION__, __LINE__);
	
	return list;
}

static size_t
calculate_of_byte(__str **str_list, int m_size)
{
	size_t count_of_byte = 0;
	register int i = 0;
	
	if (str_list != NULL) {
		/* size of build_data */
		while (*(str_list + i) != NULL) {
			count_of_byte += 35 + 10 + MAX_UID_LEN + MAX_GID_LEN + m_size;
			count_of_byte += str_list[i]->f_len;
			i++;
		}
	}
	
	return count_of_byte;
}

static char *
get_file_date(time_t time)
{
	static char date_buf[20] = { '\0' };
	char *date_format = "%b %d %H:%M";
	struct timeval c_time;
	struct tm *tm = NULL;
	
	if (gettimeofday(&c_time, NULL) != -1) {
		if (time > c_time.tv_sec ||
		    (c_time.tv_sec - time) > 60*60*24*182) {
			date_format = "%b %d  %Y";
		}
		
		tm = localtime(&time);
		strftime(date_buf, sizeof(date_buf) - 1, date_format, tm);
	} else {
		PRINT_DEBUG("error: %s %d\n", __FUNCTION__, __LINE__);
		return NULL;
	}
	
	return date_buf;
}

static char *
build_data(__str **str_list, int *len, off_t *max_size_len)
{
	size_t alloc_size = 0;
	char tmp[20] = { '\0' };
	char *file_list = NULL;
	int m_size = 0;
	
	m_size = snprintf(tmp, 20, "%ld", *max_size_len);
	alloc_size = calculate_of_byte(str_list, m_size);
	
	if (alloc_size > 0) {
		file_list = (char *) calloc(alloc_size, sizeof(char));
		if (file_list != NULL) {
			char tmp_buf[400] = { '\0' };
			char perm[11] = { '\0' };
			char *date = NULL;
			int i = 0;
			int j = 0;
			
			*len = 0;
			while (*(str_list + i) != NULL) {
				date = get_file_date(str_list[i]->time);
				(void) snprintf(tmp_buf, sizeof(tmp_buf) - 1, "%s%4u %-*u  %-*u %*ld %s %s\r\n",
							 get_perm(str_list[i]->mode, perm), (unsigned int) str_list[i]->st_nlink,
							 MAX_UID_LEN, str_list[i]->uid, MAX_GID_LEN,
							 str_list[i]->gid, m_size + 1,
							 str_list[i]->st_size, date,
							 str_list[i]->f_name ? str_list[i]->f_name:"NULL"
					);
				
				j = 0;
				while (tmp_buf[j] != '\0') {
					*(file_list + (*len)) = tmp_buf[j];
					(*len)++;
					j++;
				}
				
				i++;
			}
			
			*(file_list + (*len)) = '\0';
			
		} else {
			PRINT_DEBUG("error: %s %d\n", __FUNCTION__, __LINE__);
		}
	}
	
	return file_list;
}

static void
free_list(__str **list, int count_l)
{
	int i = 0;
	
	while (*(list + i) != NULL) {
		if (list[i]->f_name)
			free(list[i]->f_name);

		free(list[i]);
		i++;
	}
	
	free(list);
}

int
do_list(struct connection *c)
{
	off_t max_size_len = 0;
	__str **pp = NULL;
	int file_count = 0;
	
	pp = do_readdir(c->curr_dir, &max_size_len, &file_count);
	if (pp != NULL) {
		char *file_list = NULL;
		int len = 0;
		
		/* build tree of file's */
		file_list = build_data(pp, &len, &max_size_len);
		if (file_list != NULL) {
			send_cmd(c->sock_fd, 150, "ASCII MODE");
			send_data(c->transport->socket, file_list, len, 0);
			send_cmd(c->sock_fd, 226, "ASCII Transfer complete");
		} else {
			PRINT_DEBUG("error: %s %d\n", __FUNCTION__, __LINE__);
			goto error;
		}
		
		free(file_list);
		free_list(pp, file_count);
	} else {
		PRINT_DEBUG("error: %s %d\n", __FUNCTION__, __LINE__);
		goto error;
	}
	
	return 0;
error:
	return -1;
}
