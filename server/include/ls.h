#ifndef __LS_H__
#define __LS_H__

/* flags for LIST cmd */
#define L_CURR	0x00000001		/* list current folder */
#define L_ABSL	0x00000002		/* list absolute folder */
#define L_FILE	0x00000004		/* list one file */
#define L_SHRT	0x00000008		/* list without ext. info */

struct list_opt {
	int l_flags;
	void *dir;
	int fd;
};

extern char *get_file_list_chunk(DIR *, int, int);
extern int build_list_line(const char *name, struct stat *st, char *line, int l_size, int short_l);

#endif	/* __LS_H__ */
