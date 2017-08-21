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
#include <sys/time.h>
#include <sys/resource.h>

/* local headers */
#include <list.h>
#include <sock_utils.h>
#include <signal_ruling.h>
#include <debug.h>
#include <ls.h>
#include <sftpd.h>
#include <workqueue.h>
#include <cmds.h>
#include <hash.h>
#include <mem.h>

#define PID_FILE "/var/run/sftpd.pid"
#define DEV_NULL "/dev/null"

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
sftpd_probe(int argc, char **argv)
{
	struct rlimit rlim;
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

	rlim.rlim_cur = RLIM_INFINITY;
	rlim.rlim_max = RLIM_INFINITY;
	ret = setrlimit(RLIMIT_CORE, &rlim);
	if (ret)
		PRINT_DEBUG("'setrlimit()' failed with error: %s\n", strerror(errno));

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
	sftpd->cmd_table = hash_create(100);
	if (sftpd->cmd_table == NULL)
		FATAL_ERROR("error allocating memory\n");

	/* adding to hash commands and their handlers */
	for (int i = 0; cmd_table[i].cmd_handler; i++) {
		ret = hash_add(sftpd->cmd_table, cmd_table[i].cmd_name, (void *)&cmd_table[i]);
		if (ret == 0)
			FATAL_ERROR("error adding to the hash\n");
	}

	sftpd->srv_socket = start_tcp_listen(21, 4, 30);
	if (sftpd->srv_socket == -1)
		FATAL_ERROR("error starting tcp listen\n");

	FD_ZERO(&(sftpd->read_ready));
	FD_ZERO(&(sftpd->write_ready));
	FD_SET(sftpd->srv_socket, &(sftpd->read_ready));

	/* initialize list */
	TAILQ_INIT(&sftpd->client_list);

	FUNC_EXIT_PTR(sftpd);
	return sftpd;
}

static connection *
add_connection(struct ftpd *srv, int s)
{
	struct connection *new = NULL;
	struct transport *tr = NULL;

	FUNC_ENTRY();

	if (srv->client_count < FD_SETSIZE) {
		new = (connection *) calloc(1, sizeof(connection));
		tr = (transport *) calloc(1, sizeof(transport));
		if (new == NULL || tr == NULL)
			FATAL_ERROR("error allocating memory\n");

		new->c_atime = time(NULL);
		new->sock_fd = s;
		new->c_flags = 0;	/* reset flag */

		FLAG_SET(tr->t_flags, T_FREE);
		new->transport = tr;

		TAILQ_INSERT_TAIL(&srv->client_list, new, entries);

		/* add new client's socket */
		FD_SET(new->sock_fd, &(srv->read_ready));
		srv->client_count++;
	} else {
		PRINT_DEBUG("There are %d connections, it's too much\n",
					srv->client_count);
		send_cmd(s, 230, "Too many connections.");
		close_socket(s);
	}

	FUNC_EXIT_PTR(new);
	return new;
}

static void
destroy_transport(struct ftpd *srv, connection *conn)
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

		/* clean transport before next using */
		bzero(t, sizeof(transport));
		FLAG_SET(t->t_flags, T_FREE);
	}

	FUNC_EXIT_VOID();
}

static void
destroy_connection(struct ftpd *srv, connection *conn)
{
	struct connection *c;

	FUNC_ENTRY();

	TAILQ_FOREACH(c, &srv->client_list, entries) {
		if (c == conn) {
			if (FD_ISSET(conn->sock_fd, &(srv->read_ready)))
				FD_CLR(conn->sock_fd, &(srv->read_ready));
			else
				BUG();

			close_socket(conn->sock_fd);
			srv->client_count--;
			TAILQ_REMOVE(&srv->client_list, c, entries);
			destroy_transport(srv, conn);
			free(conn->transport);
			free(conn);
			break;	  /* !!! */
		}
	}

	FUNC_EXIT_VOID();
}

static void
accept_connection(struct ftpd *srv, int socket, fd_set *r_fd, int *n_ready)
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
			conn = add_connection(srv, conn_fd);
			if (conn != NULL)
				send_cmd(conn->sock_fd, 220, "I'm ready");
		} else {
			PRINT_DEBUG("accept() error: %s\n", strerror(errno));
		}

		(*n_ready)--;
	}
}

static void
sftpd_quit(struct ftpd *srv)
{
	struct connection *c;

	TAILQ_FOREACH(c, &srv->client_list, entries) {
		destroy_connection(srv, c);
	}

	unlink_pid_file(PID_FILE);
	hash_destroy(srv->cmd_table);
	close(srv->srv_socket);
	free(srv);
	exit(1);				/* finish up */
}

static void
handle_pending_signals(struct ftpd *srv)
{
	if (signal_is_pending(SIGTERM) || signal_is_pending(SIGHUP))
		sftpd_quit(srv);
}

static int
wait_for_events(ftpd *srv, fd_set *r_fd, fd_set *w_fd, int sec)
{
	struct timeval time;
	int n_ready;

	*r_fd = srv->read_ready;
	*w_fd = srv->write_ready;

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
			TAILQ_FOREACH(c, &srv->client_list, entries) {
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
process_timeouted_sockets(struct ftpd *srv, int time_m)
{
	struct connection *c;
	int processed = 0;
	int allow_time;
	time_t now;

	FUNC_ENTRY();

	now = time(NULL);
	allow_time = time_m * 60;

	TAILQ_FOREACH(c, &srv->client_list, entries) {
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
process_commands(struct ftpd *srv, fd_set *r_fd, int *n_ready)
{
	struct connection *c;
	int processed = 0;
	int avail_b;
	int n;

	FUNC_ENTRY();

	TAILQ_FOREACH(c, &srv->client_list, entries) {
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

		avail_b = bytes_available(c->sock_fd);
		if (avail_b > 0 && avail_b < RECV_BUF_SIZE) {
			n = recv_data(c->sock_fd, c->recv_buf, avail_b, 0);
			if (n > 0)
				c->recv_buf[n] = '\0';

			/* modify last access */
			c->c_atime = time(NULL);
			parse_cmd(srv, c);
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
process_clients_marked_as_destroy(struct ftpd *srv)
{
	struct connection *c;
	struct transport *t;
	int processed = 0;

	FUNC_ENTRY();

restart:
	TAILQ_FOREACH(c, &srv->client_list, entries) {
		t = c->transport;

		if (FLAG_QUERY(c->c_flags, C_KILL)) {
			destroy_connection(srv, c);
			processed++;
			goto restart;
		} else if (FLAG_QUERY(t->t_flags, T_KILL)) {
			destroy_transport(srv, c);
			processed++;
		}
	}

	FUNC_EXIT_INT(processed);
	return processed;
}

static void
kill_non_active_clients()
{
	/* TODO */
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
	int ret;

	t = c->transport;
	is_nlst = FLAG_QUERY(t->l_opt.l_flags, L_NLST);

	if (FLAG_QUERY(t->l_opt.l_flags, L_FOLD)) {
		if (t->l_opt.target_dir == NULL) {
			t->l_opt.target_dir = opendir(t->l_opt.path);
			if (t->l_opt.target_dir == NULL)
				goto leave;
		}
	} else if (FLAG_QUERY(t->l_opt.l_flags, L_FILE)) {
		char *arg = strrchr(c->recv_buf, ' ');
		char line[400] = {'\0'};

		ret = build_list_line(arg + 1, !is_nlst ?
				&t->l_opt.st:NULL, line, sizeof(line));
		if (ret > 0)
			(void) write(t->socket, line, ret);

		goto leave;
	}

	list = get_file_list_chunk(t->l_opt.target_dir, 300, !is_nlst);
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
process_transfers(struct ftpd *srv, fd_set *r_fd, fd_set *w_fd, int *n_ready)
{
	struct connection *c;
	struct transport *t;
	int processed;

	FUNC_ENTRY();

	processed = 0;

	TAILQ_FOREACH(c, &srv->client_list, entries) {
		t = c->transport;

		/* skip  FREE, KILL, PORT or PASV */
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

static int
do_main_loop(struct ftpd *s)
{
	int n_ready = 0;
	fd_set r_fd;
	fd_set w_fd;

	while (1) {
		/* wait for any events, max is 1 min. */
		n_ready = wait_for_events(s, &r_fd, &w_fd, 60);

		/* process signals */
		handle_pending_signals(s);

		/* process transfers */
		process_transfers(s, &r_fd, &w_fd, &n_ready);

		/* process commands */
		process_commands(s, &r_fd, &n_ready);

		kill_non_active_clients();

		/*
		 * We allow 10 minutes to users, for to do
		 * something, after that clients are dropped.
		 */
		process_timeouted_sockets(s, 10);
		process_clients_marked_as_destroy(s);

		/* accept new clients, if they are */
		accept_connection(s, s->srv_socket, &r_fd, &n_ready);
	}

	return 0;
}

int main(int argc, char **argv)
{
	struct ftpd *srv;

	srv = sftpd_probe(argc, argv);
	return do_main_loop(srv);
}
