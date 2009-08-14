#ifndef __FTPD_H__
#define __FTPD_H__

#define DATA_PORT	20
#define RECV_BUF_SIZE	4096

/* connection specific flags */
#define C_AUTH	0x00000001
#define C_KILL	0x00000002

/* transport specific flags */
#define T_FREE	0x00000001
#define T_PORT	0x00000002
#define T_PASV	0x00000004
#define T_LIST	0x00000008
#define T_RETR	0x00000010
#define T_STOR	0x00000020
#define T_KILL	0x00000040

#define SET_FLAG(X,Y)	(X = (X^X) | Y)
#define QUERY_FLAG(X,Y)	(X & Y)
#define CLEAR_FLAG(X,Y)	(X &= ~Y)

struct connection {
	char recv_buf[RECV_BUF_SIZE];
	int recv_buf_len;
	char user_name[256];
	char user_pass[256];
	char root_dir[256];
	char curr_dir[256];
	int sock_fd;

	uid_t uid;
	gid_t gid;

	time_t c_atime;	/* last access time*/
	int c_flags;

	struct transport *transport;
	TAILQ_ENTRY(connection) entries;
};

struct transport {
	struct sockaddr_in r_info;
	struct stat st;

	int socket;
	int data_port;

	int local_fd;
	off_t offset;

	int t_flags;
};

struct ftpd {
	unsigned int client_count;
	fd_set write_ready;
	fd_set read_ready;
	int srv_socket;
};

typedef struct connection connection;
typedef struct transport transport;
typedef struct ftpd ftpd;

extern struct ftpd *srv;

#endif  /* __FTPD_H__ */
