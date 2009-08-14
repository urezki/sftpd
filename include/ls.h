// File: ls.h 
// Headers file
// Created: Mon Sep 25 17:27:02 UTC 2006

typedef struct __str_
{
	char *f_name;		       /* file name */
	unsigned int f_len;	       /* file len */
	
	uid_t uid;
	gid_t gid;
	unsigned int st_nlink;
	off_t st_size;
	time_t time;
	mode_t mode;
} __str;

/* prototip's */
extern int do_list(connection *conn);
