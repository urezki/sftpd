#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <sys/ioctl.h>
#include <time.h>
#include <errno.h>
#include <signal.h>
#include <sys/sendfile.h>

/* local headers */
#include <list.h>
#include <sock_utils.h>
#include <signal_ruling.h>
#include <debug.h>
#include <sftpd.h>
#include <cmds.h>
#include <mem.h>

#define DEV_NULL "/dev/null"

/*
 * Head of the client list
 */
static TAILQ_HEAD(cli_list, connection) conn_list;

/* global variable */
struct ftpd *srv = NULL;

static ftpd *init_sftpd(void);
/* static void init_daemon(void); */
static int process_timeouted_sockets(int);
static void process_commands(fd_set *, int *);
static void process_transfers(fd_set *, fd_set *, int *);
static int process_clients_marked_as_destroy(void);

static connection *add_connection(int);
static void destroy_connection(connection *);
static void destroy_transport(connection *);
static int clear_bad_fd();

static inline void download_file(struct connection *);
static inline void upload_file(struct connection *);

static void
accept_client(int socket, fd_set *r_fd, int *n_ready)
{
	struct sockaddr_in r_addr;
	connection *conn = NULL;
	socklen_t cli_len;
	int conn_fd;

	/*
	 * We have to process situation when clients
	 * send RST packet, but we are waiting for a connection
	 * from other side ...
	 */
	if (FD_ISSET(socket, r_fd) && *n_ready > 0) {
		cli_len = sizeof(r_addr);
		conn_fd = accept(socket, (struct sockaddr *)&r_addr, &cli_len);
		if (conn_fd != -1) {
			activate_nodelay(conn_fd);
			conn = add_connection(conn_fd);
			if (conn != NULL)
				send_cmd(conn->sock_fd, 220, "I'm ready");
		} else {
			PRINT_DEBUG("accept() error: %s\n", strerror(errno));
		}

		(*n_ready)--;
	}
}

static void
check_received_signals(void)
{
	if (signal_is_pending(SIGTERM) || signal_is_pending(SIGHUP)) {
		struct connection *c;

		TAILQ_FOREACH(c, &conn_list, entries) {
			destroy_connection(c);
		}

		close(srv->srv_socket);
		free(srv);
		exit(1);				/* finish up */
	}
}

static int
wait_for_events(ftpd *sftpd, fd_set *r_fd, fd_set *w_fd, int sec)
{
	struct timeval time;
	int n_ready;

	*r_fd = sftpd->read_ready;
	*w_fd = sftpd->write_ready;

	time.tv_sec = sec;
	time.tv_usec = 0;

	n_ready = select(FD_SETSIZE, r_fd, w_fd, NULL, &time);
	if (n_ready < 0) {
		if (errno == EBADF) {
			PRINT_DEBUG("'select()' failed with errno %d: %s\n",
						  errno, strerror(errno));
			/* 
			 * We mark bad descriptors, and below
			 * will clean it up.
			 */
			clear_bad_fd();
		}

		sleep(1);
	}

	return n_ready;
}

int main(int argc, char **argv)
{
	fd_set r_fd;
	fd_set w_fd;
	int n_ready;

	/* srv is global */
	srv = init_sftpd();

	while (1) {
		/* wait for any events, max is 1 min. */
		n_ready = wait_for_events(srv, &r_fd, &w_fd, 60);

		/* check signals */
		check_received_signals();

		/* deal with exist transfers */
		process_transfers(&r_fd, &w_fd, &n_ready);

		/* process FTP's commands */
		process_commands(&r_fd, &n_ready);

		/*
		 * We allow 10 minutes to users, for to do
		 * something, after that clients are dropped.
		 */
		process_timeouted_sockets(10);
		process_clients_marked_as_destroy();

		/* accept new clients, if they are */
		accept_client(srv->srv_socket, &r_fd, &n_ready);
	}

	return 0;
}

static connection *
add_connection(int s)
{
	struct connection *new_conn = NULL;
	struct transport *tr = NULL;

	FUNC_ENTRY();

	if (srv->client_count < FD_SETSIZE) {
		/* adding new client's socket */
		FD_SET(s, &(srv->read_ready));

		new_conn = (connection *) calloc(1, sizeof(connection));
		tr = (transport *) calloc(1, sizeof(transport));
		if (new_conn == NULL || tr == NULL)
			FATAL_ERROR("error allocating memory\n");

		new_conn->c_atime = time(NULL);
		new_conn->sock_fd = s;
		new_conn->c_flags = 0;	/* reset flag */

		SET_FLAG(tr->t_flags, T_FREE);
		new_conn->transport = tr;

		TAILQ_INSERT_TAIL(&conn_list, new_conn, entries);
		srv->client_count++;
	} else {
		PRINT_DEBUG("There are %d connections, it's too much\n",
					srv->client_count);
		send_cmd(s, 230, "Too many connections.");
		close_socket(s);
	}

	FUNC_EXIT_PTR(new_conn);
	return new_conn;
}

static void
destroy_connection(connection *conn)
{
	struct connection *c;

	FUNC_ENTRY();

	TAILQ_FOREACH(c, &conn_list, entries) {
		if (c == conn) {
			FD_CLR(conn->sock_fd, &(srv->read_ready));
			close_socket(conn->sock_fd);
			srv->client_count--;
			TAILQ_REMOVE(&conn_list, c, entries);
			destroy_transport(conn);
			free(conn->transport);
			free(conn);
			break;	  /* !!! */
		}
	}

	FUNC_EXIT_VOID();
}

static void
destroy_transport(connection *conn)
{
	struct transport *t;

	FUNC_ENTRY();

	t = conn->transport;
	if (!QUERY_FLAG(t->t_flags, T_FREE)) {
		close_socket(t->socket);
		/*
		 * If t_flags is RETR or STOR, it means that we have already
		 * opened local file, that is why we have to close it,
		 * otherwise we don't have to do it.
		 */
		if (QUERY_FLAG(t->t_flags, T_RETR)) {
			close(t->local_fd);
			FD_CLR(t->socket, &srv->write_ready);
		} else if (QUERY_FLAG(t->t_flags, T_STOR)) {
			close(t->local_fd);
			FD_CLR(t->socket, &srv->read_ready);
		}

		/*
		 * We have to clean transport before next using !!!
		 */
		bzero(t, sizeof(transport));
		SET_FLAG(t->t_flags, T_FREE);
	}

	FUNC_EXIT_VOID();
}

/* static void */
/* init_daemon(void) */
/* { */
/* 	int i = 0; */

/* 	FUNC_ENTRY(); */
	
/* 	if (fork() != 0)                /\* quit first parent *\/ */
/* 		exit(0); */
/* 	if (setsid() < 0) */
/* 		perror("setsid"); */

/* 	if (fork() != 0)                /\* quit second parent *\/ */
/* 		exit(0); */
	
/* 	chdir("/"); */
/* 	umask(0); */

/* 	for (i = 0; i < 64; i++) */
/* 		close(i); */

/* 	i = open(DEV_NULL, O_RDWR); /\* stdin *\/ */
/* 	dup(i);						/\* stdout *\/ */
/* 	dup(i);						/\* stderr *\/ */

/* 	FUNC_EXIT_VOID(); */
/* } */

static ftpd *
init_sftpd(void)
{
	ftpd *sftpd = NULL;
	
	FUNC_ENTRY();

	signal_handle(SIGHUP);
	signal_handle(SIGTERM);
	signal_ignore(SIGPIPE);

	/* allocate memory for our new ftp server */
	sftpd = (ftpd *) calloc(1, sizeof(ftpd));
	if (sftpd == NULL)
		FATAL_ERROR("error allocating memory\n");
	
	/* init some stuff */
	sftpd->client_count = 0;
	sftpd->srv_socket = -1;

	sftpd->srv_socket = start_tcp_listen(21, 4, 30);
	if (sftpd->srv_socket == -1)
		FATAL_ERROR("error starting tcp listen\n");

	FD_ZERO(&(sftpd->read_ready));
	FD_ZERO(&(sftpd->write_ready));
	FD_SET(sftpd->srv_socket, &(sftpd->read_ready));

	/* initialize list */
	TAILQ_INIT(&conn_list);

	FUNC_EXIT_PTR(sftpd);
	return sftpd;
}

static int
process_timeouted_sockets(int time_m)
{
	struct connection *c;
	int processed = 0;
	int allow_time;
	time_t now;

	FUNC_ENTRY();

	now = time(NULL);
	allow_time = time_m * 60;

	TAILQ_FOREACH(c, &conn_list, entries) {
		if (difftime(now, c->c_atime) > allow_time) {
			if (!QUERY_FLAG(c->c_flags, C_KILL)) {
				send_cmd(c->sock_fd, 421, "Timeout! Closing connection.");
				SET_FLAG(c->c_flags, C_KILL);
				processed++;
			}
		}
	}

	FUNC_EXIT_INT(processed);
	return processed;
}

static void
process_commands(fd_set *r_fd, int *n_ready)
{
	struct connection *c;
	int processed = 0;
	int avail_b;

	FUNC_ENTRY();

	TAILQ_FOREACH(c, &conn_list, entries) {
		/* skip sockets which are not ready */
		if (!FD_ISSET(c->sock_fd, r_fd))
			continue;
		/*
		 * If we want to remove connection from the list
		 * and free memory which was allocated, we must
		 * set C_KILL flag.
		 */
		if (QUERY_FLAG(c->c_flags, C_KILL))
			continue;

		ioctl(c->sock_fd, FIONREAD, &avail_b);
		if (avail_b > 0 && avail_b < RECV_BUF_SIZE) {
			int read_count;

			read_count = recv_data(c->sock_fd, c->recv_buf, avail_b, 0);
			/* modify last access */
			c->c_atime = time(NULL);
			parse_cmd(c);
		} else {
			/* 
			 * Here we process two sitations: when buffer is
			 * more than RECV_BUF_SIZE bytes; and when there
			 * is no data.
			 */
			if (avail_b > RECV_BUF_SIZE)
				send_cmd(c->sock_fd, 503, "Buffer is overflowed, sorry.");

			SET_FLAG(c->c_flags, C_KILL);
		}

		if (++processed == *n_ready) {
			(*n_ready)--;
			break;
		}
	}

	FUNC_EXIT_VOID();
}

static int
process_clients_marked_as_destroy(void)
{
	struct connection *c;
	struct transport *t;
	int processed = 0;

	FUNC_ENTRY();

restart:
	TAILQ_FOREACH(c, &conn_list, entries) {
		t = c->transport;

		if (QUERY_FLAG(c->c_flags, C_KILL)) {
			destroy_connection(c);
			processed++;
			goto restart;
		} else if (QUERY_FLAG(t->t_flags, T_KILL)) {
			destroy_transport(c);
			processed++;
		}
	}

	FUNC_EXIT_INT(processed);
	return processed;
}

static void
process_transfers(fd_set *r_fd, fd_set *w_fd, int *n_ready)
{
	struct connection *c;
	struct transport *t;
	int processed = 0;

	FUNC_ENTRY();

	TAILQ_FOREACH(c, &conn_list, entries) {
		t = c->transport;

		/* skip who is FREE or KILL */
		if (QUERY_FLAG(t->t_flags, (T_FREE | T_KILL)))
			continue;

		if (processed == *n_ready)
			break;

		/* skip transfers which are not ready */
		if (!FD_ISSET(t->socket, w_fd) &&
		    !FD_ISSET(t->socket, r_fd))
			continue;

		if (QUERY_FLAG(t->t_flags, T_RETR)) {
			c->c_atime = time(NULL);
			download_file(c);
			(*n_ready)--;
			processed++;
		} else if (QUERY_FLAG(t->t_flags, T_STOR)) {
			c->c_atime = time(NULL);
			upload_file(c);
			(*n_ready)--;
		} else {
			/* BUG */
		}
	}

	FUNC_EXIT_VOID();
}

static int
clear_bad_fd(void)
{
	struct connection *c;
	struct transport *t;

	int processed = 0;
	int ret;

	FUNC_ENTRY();

	TAILQ_FOREACH(c, &conn_list, entries) {
		t = c->transport;

		ret = check_socket(c->sock_fd);
		if (ret == -1) {
			SET_FLAG(c->c_flags, C_KILL);
			processed++;
		} else {
			if (!QUERY_FLAG(t->t_flags, T_FREE)) {
				ret = check_socket(t->socket);
				if (ret == -1) {
					SET_FLAG(t->t_flags, T_KILL);
					processed++;
				}
			}
		}
	}

	FUNC_EXIT_INT(processed);
	return processed;
}

static inline void
download_file(struct connection *c)
{
	struct transport *t;
	int n;

	FUNC_ENTRY();

	t = c->transport;
	n = sendfile(t->socket, t->local_fd, &t->offset, t->st.st_blksize);
	if (n > 0)
		goto again;

	send_cmd(c->sock_fd, 226, "Transfer complete.");
	destroy_transport(c);
again:
	FUNC_EXIT_VOID();
}

static inline void
upload_file(struct connection *c)
{
	struct transport *t;
	char buf[65536];
	int avail;
	int size;

	FUNC_ENTRY();

	t = c->transport;
	ioctl(t->socket, FIONREAD, &avail);
	avail = avail > 65536 ? 65536:avail < 0 ? 0:avail;

	size = recv_data(t->socket, buf, avail, 0);	
	if (size > 0) {
		int n = write(t->local_fd, buf, size);
		if (n == size)
			goto again;
		else if (n < 0) {
			/* ??? */
		}
	}

	send_cmd(c->sock_fd, 226, "Transfer complete.");
	destroy_transport(c);
again:
	FUNC_EXIT_VOID();
}
