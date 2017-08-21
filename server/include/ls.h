#ifndef __LS_H__
#define __LS_H__

/* flags for LIST cmd */
#define L_FOLD	0x00000001		/* list folder */
#define L_FILE	0x00000004		/* list one file */
#define L_NLST	0x00000008		/* list without ext. info */

struct list_opt {
	char path[PATH_MAX];
	struct stat st;
	void *target_dir;
	int l_flags;
};

extern char *get_file_list_chunk(DIR *, int, int);
extern int build_list_line(const char *name, struct stat *st, char *line, int l_size);

#endif	/* __LS_H__ */
