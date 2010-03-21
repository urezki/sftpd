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
#include <dirent.h>

/* local headers */
#include <list.h>
#include <sock_utils.h>
#include <signal_ruling.h>
#include <debug.h>
#include <ls.h>
#include <sftpd.h>
#include <cmds.h>
#include <hash.h>
#include <mem.h>

#define PID_FILE "/var/run/sftpd.pid"
#define DEV_NULL "/dev/null"

/*
 * Head of the client list
 */
static TAILQ_HEAD(cli_list, connection) conn_list;

/* global variable */
struct ftpd *srv = NULL;

static void
print_usage(char **argv)
{
	fprintf(stderr, "\n"
			"Usage: %s [OPTION]\n"
			"    -d    run server as daemon (background mode)\n"
			"    -h    show this help message\n"
			, argv[0]);

	exit(1);
}

static int
unlink_pid_file(const char *full_path)
{
	int ret;

	ret = unlink(full_path);
	if (ret < 0)
		PRINT_DEBUG("unlink error: %s\n", strerror(errno));

	return ret;
}

static int
create_pid_file(const char *full_path)
{
	FILE *pidfile;
	int pidfd;
	int pid;
	int ret;

	pidfd = open(full_path, O_EXCL|O_CREAT|O_WRONLY, S_IRUSR|S_IWUSR|S_IRGRP|S_IROTH);
	if (pidfd != -1) {
		pidfile = fdopen(pidfd, "w");
		if (pidfile) {
			fchmod(pidfd, S_IRUSR|S_IWUSR|S_IRGRP|S_IROTH);
			fprintf(pidfile, "%d\n", getpid());
			fclose(pidfile);
		} else {
			close(pidfd);
			PRINT_DEBUG("fdopen error: %s\n", strerror(errno));
			pidfd = -1;
		}
	} else {
		if (errno == EEXIST) {
			pidfile = fopen(full_path, "r+");
			if (pidfile) {
				(void) fscanf(pidfile, "%d", &pid);
				(void) fclose(pidfile);

				ret = kill(pid, 0);
				if (ret < 0 && errno == ESRCH) {
					PRINT_DEBUG("pid file %s exists, but the process is not alive",
								full_path);

					ret = unlink_pid_file(full_path);
					if (ret == 0)
						return create_pid_file(full_path);
				}
			}
		}

		PRINT_DEBUG("open %s error: %s\n", full_path, strerror(errno));
	}

	return pidfd;
}

static void
init_daemon(void)
{
	int i = 0;

	FUNC_ENTRY();

	if (fork() != 0)                /* quit first parent */
		exit(0);
	if (setsid() < 0)
		perror("setsid");

	if (fork() != 0)                /* quit second parent */
		exit(0);

	chdir("/");
	umask(0);

	for (i = 0; i < 64; i++)
		close(i);

	i = open(DEV_NULL, O_RDWR); /* stdin */
	dup(i);						/* stdout */
	dup(i);						/* stderr */

	i = create_pid_file(PID_FILE);
	if (i < 0)
		exit(-1);

	FUNC_EXIT_VOID();
}

static ftpd *
init_sftpd(int argc, char **argv)
{
	ftpd *sftpd = NULL;
	int fork_flag = 0;
	int ret;
	int ch;

	FUNC_ENTRY();

	while ((ch = getopt(argc, argv, "dh")) != -1) {
		switch (ch) {
		case 'd':
			fork_flag = 1;
			break;

		case 'h':
			print_usage(argv);
			break;

		default:
			;
		}
	}

	if (fork_flag)
		init_daemon();

	signal_handle(SIGHUP);
	signal_handle(SIGTERM);
	signal_ignore(SIGPIPE);

	/* allocate memory for our new ftp server */
	sftpd = (ftpd *) calloc(1, sizeof(ftpd));
	if (sftpd == NULL)
		FATAL_ERROR("error allocating memory\n");

	/*
	 * Create hash table with size 100, in spite of we
	 * have approximately 29 FTP commands, by this way
	 * we tend to avoid collisions.
	 */
	sftpd->cmd_hash_table = hash_create(100);
	if (sftpd->cmd_hash_table == NULL)
		FATAL_ERROR("error allocating memory\n");

	/* adding to hash commands and their handlers */
	for (int i = 0; cmd_table[i].cmd_handler; i++) {
		ret = hash_add(sftpd->cmd_hash_table, cmd_table[i].cmd_name, (void *)&cmd_table[i]);
		if (ret == 0)
			FATAL_ERROR("error adding to the hash\n");
	}

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

		FLAG_SET(tr->t_flags, T_FREE);
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
destroy_transport(connection *conn)
{
	struct transport *t;

	FUNC_ENTRY();

	t = conn->transport;
	if (!FLAG_QUERY(t->t_flags, T_FREE)) {
		/* listing */
		if (FLAG_QUERY(t->t_flags, T_LIST)) {
			if (t->socket >= 0) {
				FD_CLR(t->socket, &srv->write_ready);
			} else {
				BUG();
			}

			if (t->l_opt.target_dir)
				closedir(t->l_opt.target_dir);
		} else if (FLAG_QUERY(t->t_flags, (T_RETR | T_STOR))) {
			/* downloading or uploading */
			if (t->socket >= 0) {
				if (FLAG_QUERY(t->t_flags, T_RETR))
					FD_CLR(t->socket, &srv->write_ready);
				else
					FD_CLR(t->socket, &srv->read_ready);
			} else {
				BUG();
			}

			if (t->local_fd >= 0)
				close(t->local_fd);
			else
				BUG();
		} else if (FLAG_QUERY(t->t_flags, T_ACPT)) {
			/* accepting */
			if (t->listen_socket >= 0) {
				FD_CLR(t->listen_socket, &srv->read_ready);
			} else {
				BUG();
			}

			close_socket(t->listen_socket);
		}

		if (t->socket >= 0)
			close_socket(t->socket);
		else
			BUG();

		/* clean transport before next using */
		bzero(t, sizeof(transport));
		FLAG_SET(t->t_flags, T_FREE);
	}

	FUNC_EXIT_VOID();
}

static void
destroy_connection(connection *conn)
{
	struct connection *c;

	FUNC_ENTRY();

	TAILQ_FOREACH(c, &conn_list, entries) {
		if (c == conn) {
			if (FD_ISSET(conn->sock_fd, &(srv->read_ready)))
				FD_CLR(conn->sock_fd, &(srv->read_ready));
			else
				BUG();

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
accept_connection(int socket, fd_set *r_fd, int *n_ready)
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
check_received_signals()
{
	if (signal_is_pending(SIGTERM) || signal_is_pending(SIGHUP)) {
		struct connection *c;

		TAILQ_FOREACH(c, &conn_list, entries) {
			destroy_connection(c);
		}

		unlink_pid_file(PID_FILE);
		hash_destroy(srv->cmd_hash_table);
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
		PRINT_DEBUG("'select()' failed with error: %s\n",
					strerror(errno));

		if (errno == EBADF) {
			struct connection *c;
			struct transport *t;
			int ret;

			/*
			 * if we get EBADF, it means that there is(are)
			 * bad descriptor(s) in the sets. So, find them
			 * and kill.
			 */
			TAILQ_FOREACH(c, &conn_list, entries) {
				t = c->transport;

				ret = check_socket(c->sock_fd);
				if (ret < 0) {
					FLAG_SET(c->c_flags, C_KILL);
				} else {
					if (!FLAG_QUERY(t->t_flags, T_FREE)) {
						ret = check_socket(t->socket);
						if (ret < 0) {
							FLAG_APPEND(t->t_flags, T_KILL);
						}
					}
				}
			}
		}

		sleep(1);
	}

	return n_ready;
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
			if (!FLAG_QUERY(c->c_flags, C_KILL)) {
				send_cmd(c->sock_fd, 421, "Timeout! Closing connection.");
				PRINT_DEBUG("Timeout! Closing connection.\n");
				FLAG_SET(c->c_flags, C_KILL);
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
		if (FLAG_QUERY(c->c_flags, C_KILL))
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
			if (avail_b > RECV_BUF_SIZE) {
				send_cmd(c->sock_fd, 503, "Buffer is overflowed, sorry.");
				PRINT_DEBUG("Buffer is overflowed, connection will be killed.\n");
			} else {
				/* it can happen when a client close a socket */
				PRINT_DEBUG("There is no data, connection will be killed.\n");
			}

			FLAG_SET(c->c_flags, C_KILL);
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

		if (FLAG_QUERY(c->c_flags, C_KILL)) {
			destroy_connection(c);
			processed++;
			goto restart;
		} else if (FLAG_QUERY(t->t_flags, T_KILL)) {
			destroy_transport(c);
			processed++;
		}
	}

	FUNC_EXIT_INT(processed);
	return processed;
}

static void
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
	FLAG_APPEND(t->t_flags, T_KILL);

again:
	FUNC_EXIT_VOID();
}

static void
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
	FLAG_APPEND(t->t_flags, T_KILL);

again:
	FUNC_EXIT_VOID();
}

static void
list_folder(struct connection *c)
{
	struct transport *t;
	int is_nlst;
	char *list;

	t = c->transport;
	is_nlst = FLAG_QUERY(t->l_opt.l_flags, L_NLST);

	if (FLAG_QUERY(t->l_opt.l_flags, L_FOLD)) {
		if (t->l_opt.target_dir == NULL) {
			t->l_opt.target_dir = opendir(t->l_opt.path);
			if (t->l_opt.target_dir == NULL)
				goto leave;
		}
	}

	list = get_file_list_chunk(t->l_opt.target_dir, 300, is_nlst);
	if (list) {
		send_data(t->socket, list, strlen(list), 0);
		free(list);
		return;
	}

leave:
	send_cmd(c->sock_fd, 226, "ASCII Transfer complete");
	FLAG_APPEND(t->t_flags, T_KILL);
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

		/* skip who is FREE, KILL, PORT or PASV */
		if (FLAG_QUERY(t->t_flags, (T_FREE | T_KILL | T_PORT | T_PASV)))
			continue;

		if (processed == *n_ready)
			break;

		/* skip transfers which are not ready */
		if (!FD_ISSET(t->socket, w_fd) &&
		    !FD_ISSET(t->socket, r_fd) &&
			!FD_ISSET(t->listen_socket, r_fd))
			continue;

		if (FLAG_QUERY(t->t_flags, T_LIST)) {
			if (FD_ISSET(t->socket, w_fd)) {
				c->c_atime = time(NULL);
				list_folder(c);
				(*n_ready)--;
				processed++;
			}
		} else if (FLAG_QUERY(t->t_flags, T_ACPT)) {
			if (FD_ISSET(t->listen_socket, r_fd)) {
				t->socket = accept_timeout(t->listen_socket, (SA *)&t->r_info, 5);
				if (t->socket != -1) {
					/* we are in PASV mode */
					activate_nonblock(t->socket);
					FD_CLR(t->listen_socket, &srv->read_ready);
					FLAG_SET(t->t_flags, T_PASV);
					close_socket(t->listen_socket);
				} else {
					/*
					 * listen_socket will be cleaned and closed
					 * by the 'destroy_transport' routine, don't
					 * use FD_CLR here.
					 */
					send_cmd(c->sock_fd, 500, "%s", strerror(errno));
					PRINT_DEBUG("%s\n", strerror(errno));
					FLAG_APPEND(t->t_flags, T_KILL);
				}

				c->c_atime = time(NULL);
				(*n_ready)--;
				processed++;
			}
		} else if (FLAG_QUERY(t->t_flags, T_RETR)) {
			if (FD_ISSET(t->socket, w_fd)) {
				c->c_atime = time(NULL);
				download_file(c);
				(*n_ready)--;
				processed++;
			}
		} else if (FLAG_QUERY(t->t_flags, T_STOR)) {
			if (FD_ISSET(t->socket, r_fd)) {
				c->c_atime = time(NULL);
				upload_file(c);
				(*n_ready)--;
			}
		}
	}

	FUNC_EXIT_VOID();
}

int main(int argc, char **argv)
{
	fd_set r_fd;
	fd_set w_fd;
	int n_ready;

	/* srv is global */
	srv = init_sftpd(argc, argv);

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
		accept_connection(srv->srv_socket, &r_fd, &n_ready);
	}

	return 0;
}
