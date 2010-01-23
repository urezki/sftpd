#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/select.h>
#include <strings.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <errno.h>
#include <shadow.h>
#include <pwd.h>

#include <sys/stat.h>
#include <sys/types.h>
#include <fcntl.h>
#include <time.h>
#include <sys/ioctl.h>

/* local headers */
#include <list.h>
#include <sock_utils.h>
#include <utils.h>
#include <debug.h>
#include <sftpd.h>
#include <cmds.h>
#include <mem.h>
#include <ls.h>

static void cmd_user(struct connection *);
static void cmd_pass(struct connection *);
static void cmd_port(struct connection *);
static void cmd_pasv(struct connection *);
static void cmd_list(struct connection *);
static void cmd_cdup(struct connection *);
static void cmd_retr(struct connection *);
static void cmd_size(struct connection *);
static void cmd_noop(struct connection *);
static void cmd_syst(struct connection *);
static void cmd_type(struct connection *);
static void cmd_stru(struct connection *);
static void cmd_quit(struct connection *);
static void cmd_feat(struct connection *);
static void cmd_abor(struct connection *);
static void cmd_stor(struct connection *);
static void cmd_dele(struct connection *);
static void cmd_help(struct connection *);
static void cmd_allo(struct connection *);
static void cmd_pwd(struct connection *);
static void cmd_cwd(struct connection *);
static void cmd_rmd(struct connection *);
static void cmd_mkd(struct connection *);

/* static void cmd_nlst(struct connection *); */
/* static void cmd_mode(struct connection *); */
/* static void cmd_mdtm(struct connection *); */

struct cmd_handler {
	char cmd_name[10];
	char arg;
	void (*cmd_handler)(struct connection *const);
	char need_root;
	char cmd_len;
};

static const struct cmd_handler cmd_table[] =
{
	{ "user", 1, cmd_user, 1, 4 },
	{ "pass", 1, cmd_pass, 1, 4 },
	{ "port", 1, cmd_port, 1, 4 },
	{ "pasv", 0, cmd_pasv, 0, 4 },
	{ "list", 0, cmd_list, 1, 4 },
	{ "cdup", 0, cmd_cdup, 0, 4 },
	{ "retr", 1, cmd_retr, 0, 4 },
	{ "size", 1, cmd_size, 0, 4 },
	{ "noop", 0, cmd_noop, 0, 4 },
	{ "syst", 0, cmd_syst, 0, 4 },
	{ "type", 0, cmd_type, 0, 4 },
	{ "abor", 0, cmd_abor, 0, 4 },
	{ "stru", 0, cmd_stru, 0, 4 },
	{ "quit", 0, cmd_quit, 0, 4 },
	{ "feat", 0, cmd_feat, 0, 4 },
	{ "help", 0, cmd_help, 0, 4 },
//	{ "mdtm", 0, cmd_mdtm, 0, 4 }, /* not implemented */
#ifdef UPLOAD_SUPPORT
	{ "stor", 0, cmd_stor, 0, 4 },
	{ "dele", 1, cmd_dele, 0, 4 },
	{ "rmd", 1, cmd_rmd, 0, 3 },
	{ "mkd", 1, cmd_mkd, 0, 3 },
#endif
//	{ "nlst", 0, cmd_nlst, 0, 4 }, /* not implemented */
//	{ "mode", 0, cmd_mode, 0, 4 }, /* not implemented */
	{ "allo", 0, cmd_allo, 0, 4 },
	{ "pwd", 0, cmd_pwd, 0, 3 },
	{ "cwd", 1, cmd_cwd, 0, 3 },
	{ " ", 0, NULL, 0, 0 }
};

static int
translate_path(const char *root, const char *cur, char *dst)
{
	char absolute_path[PATH_MAX] = {'\0'};
	char tmp_path[PATH_MAX] = {'\0'};
	char *dot;
	int n;

	if (root == NULL || cur == NULL || dst == NULL)
		return -1;

	if (*dst == '/' || *dst == '~') {
		/* 1) cd / 2) cd ~/ 3) cd ~ */
		n = snprintf(absolute_path, PATH_MAX, "%s%s", root,
					 *(dst + 1) == '/' ? dst + 2 : dst + 1);
	} else {
		/* 1) cd foo/ */
		n = snprintf(absolute_path, PATH_MAX, "%s%s", cur, dst);
	}

	/* /home/urezki/../ftp/.. */
	if ((dot = strrchr(absolute_path, '.')))
		if (*(dot - 1) == '.' && *(dot + 1) == '\0')
			strcat(absolute_path, "/");

	/*
	 * Here we can have following combinations:
	 * 1) /home/urezki/../ftp/../
	 * 2) /home/urezki/
	 */
	while ((dot = strstr(absolute_path, "/../"))) {
		char *s_pp = NULL;

		if (dot == absolute_path)
			s_pp = dot;
		else
			s_pp = (dot - 1);

		while (s_pp != absolute_path && *s_pp != '/')
			s_pp--;

		*(s_pp + 1) = '\0';

		snprintf(tmp_path, PATH_MAX, "%s%s", absolute_path, dot + 4);
		snprintf(absolute_path, PATH_MAX, "%s", tmp_path);
	}

	snprintf(dst, PATH_MAX, "%s", absolute_path);
	return 0;
}

static int
is_path_ok(struct connection *conn)
{
	char *cmd_arg;
	struct stat st;
	int ret;

	cmd_arg = strchr(conn->recv_buf, ' ');
	if (cmd_arg == NULL || cmd_arg[1] == '\0')
		goto fail;

	/* get pointer to the arg */
	cmd_arg = cmd_arg + 1;
	ret = translate_path(conn->root_dir, conn->curr_dir, cmd_arg);
	if (ret < 0)
		goto fail;

	/* check symbolic links */
	if (stat(cmd_arg, &st) != -1) {
		if (!S_ISLNK(st.st_mode)) {
			char buf[1024] = {'\0'};
			int len;

			len = readlink(cmd_arg, buf, sizeof(buf) - 1);
			if (len != -1) {
				buf[len] = '\0';
				*cmd_arg = '\0';
				strcat(cmd_arg, buf);
			}
		}
	}

	if (!strncmp(cmd_arg, conn->root_dir, strlen(conn->root_dir)))
		return 1;

fail:
	return 0;
}

static void
cmd_feat(struct connection *conn)
{
	const char *const feat = 
		"211-Features:\r\n"
		"   SIZE\r\n"
		"211 End\r\n";
	
	FUNC_ENTRY();
	
	/* sending informations about features. */
	send_data(conn->sock_fd, feat, strlen(feat), 0);
	
	FUNC_EXIT_VOID();
}

/**
 * recv_buf looks like: "USER anonymous'\0'"
 * recv_buf_len is 14, in this case.
 */
static void
cmd_user(struct connection *conn)
{
	char tmp_buf[120] = {'\0'};
	int rejected = 0;
	
	FUNC_ENTRY();
	
	if (strstr(conn->recv_buf, "anonymous") ||
	    strstr(conn->recv_buf, "ftp"))
	{
		(void) snprintf(tmp_buf, sizeof(tmp_buf), "%s", "Anonymous "
						"login ok, send your complete email address "
						"as your password");
		(void) strncpy(conn->user_name, "ftp", sizeof(conn->user_name));
	} else {
		char *user_name;
		
		/* skipping "USER " */
		user_name = strchr(conn->recv_buf, ' ');
		if (user_name != NULL && conn->recv_buf_len > 4) {
			(void) strncpy(conn->user_name, user_name + 1,
						   sizeof(conn->user_name));
			
			(void) snprintf(tmp_buf, sizeof(tmp_buf), "%s %s", "password "
							"required for", conn->user_name);
		} else {
			(void) snprintf(tmp_buf, sizeof(tmp_buf), "Invalid user name");
			rejected = 1;	  /* mark as was rejected */
		}
	}
	
	send_cmd(conn->sock_fd, !rejected ? 331:530, "%s", tmp_buf);
	FUNC_EXIT_VOID();
}

static void
cmd_pass(struct connection *conn)
{
	struct spwd *p_shadow;
	struct passwd *p;

	FUNC_ENTRY();

	p = getpwnam(conn->user_name);
	if (p != NULL) {
		char *user_pass;

		conn->uid = p->pw_uid;
		conn->gid = p->pw_gid;

		(void) strncpy(conn->root_dir, p->pw_dir, sizeof(conn->root_dir));
		if (conn->root_dir[strlen(conn->root_dir) - 1] != '/')
			(void) strcat(conn->root_dir, "/");

		(void) strncpy(conn->curr_dir, p->pw_dir, sizeof(conn->curr_dir));
		if (conn->curr_dir[strlen(conn->curr_dir) - 1] != '/')
			(void) strcat(conn->curr_dir, "/");

		user_pass = strchr(conn->recv_buf, ' ');

		/* in case of anonymous access */
		if (!strncmp(conn->user_name, "ftp", 3)) {
			SET_FLAG(conn->c_flags, C_AUTH);
		} else if (user_pass != NULL && conn->recv_buf_len > 4) {
			char *p_crypt;
			
			p_crypt = crypt(user_pass + 1, p->pw_passwd);
			if (p_crypt != NULL) {
				if (!strcmp(p_crypt, p->pw_passwd)) {
					SET_FLAG(conn->c_flags, C_AUTH);
				} else {
					/* checking shadow pass */
					p_shadow = getspnam(conn->user_name);
					if (p_shadow != NULL)
						p_crypt = crypt(user_pass + 1, p_shadow->sp_pwdp);
					if (p_crypt != NULL)
						if (!strcmp(p_crypt, p_shadow->sp_pwdp))
							SET_FLAG(conn->c_flags, C_AUTH);
				}
			}
		}
	}

	if (QUERY_FLAG(conn->c_flags, C_AUTH)) {
		send_cmd(conn->sock_fd, 230, "%s %s", conn->user_name, "logged in");
		PRINT_DEBUG("%s user logged in\n", conn->user_name);
		chdir(conn->root_dir);
	} else {
		send_cmd(conn->sock_fd, 530, "Login incorrect");
		PRINT_DEBUG("%s Login incorrect\n", conn->user_name);
	}

	FUNC_EXIT_VOID();
}

/**
 * cmd_port - this function find out the
 * port number, which should be used afterwards,
 * and than connect to the client.
 * 
 * for instance: PORT 192,168,5,12,4,1
 */
static void
cmd_port(struct connection *conn)
{
	char *ip_address = NULL;
	int data_port = 0;
	transport *t;
	int ret;
	
	FUNC_ENTRY();

	t = conn->transport;
	ip_address = strchr(conn->recv_buf, ' ');

	if (QUERY_FLAG(t->t_flags, T_FREE)) {
		short int a0, a1, a2, a3, p0, p1;

		ret = sscanf(ip_address + 1, "%3hu,%3hu,%3hu,%3hu,%3hu,%3hu",
					 &a0, &a1, &a2, &a3, &p0, &p1);
		
		data_port = p0 * 256 + p1;
		if (data_port > 1024 && ret == 6) {
			int len;
			
			t->socket = get_ipv4_socket();
			t->data_port = data_port;
			activate_reuseaddr(t->socket);
			
			t->r_info.sin_port = htons(DATA_PORT);
			t->r_info.sin_family = AF_INET;
			
			len = sizeof(t->r_info);
			bind(t->socket, (SA *)&t->r_info, len);
			
			t->r_info.sin_family = AF_INET;
			t->r_info.sin_port = htons(t->data_port);
			t->r_info.sin_addr.s_addr = htonl(
				((unsigned char)(a0) << 24) +
				((unsigned char)(a1) << 16) +
				((unsigned char)(a2) << 8)  +
				((unsigned char)(a3)));
			
			ret = connect_timeout(t->socket, (SA *)&t->r_info, 5);
			if (ret == 0) {
				/* we are in a port mode */
				SET_FLAG(t->t_flags, T_PORT);
				activate_nonblock(t->socket);

				send_cmd(conn->sock_fd, 220, "PORT command successful");
			} else {
				send_cmd(conn->sock_fd, 425, "Can't open data connection");
				PRINT_DEBUG("Can't connect to %s:%d\n", ip_address, data_port);
			}
		}
	} else {
		send_cmd(conn->sock_fd, 503, "Sorry, only one transfer at once.");
		PRINT_DEBUG("Sorry, only one transfer at once\n");
	}
	
	FUNC_EXIT_VOID();
}

static void
cmd_pasv(struct connection *conn)
{
	struct sockaddr_in addr;
	int listen_sock;
	transport *trans;
	socklen_t len;

	FUNC_ENTRY();

	trans = conn->transport;
	if (QUERY_FLAG(trans->t_flags, T_FREE)) {
		memset(&addr, 0, sizeof(addr));
		listen_sock = get_ipv4_socket();
		activate_reuseaddr(listen_sock);
		
		len = sizeof(addr);
		getsockname(conn->sock_fd, (struct sockaddr *)&addr, &len);
		
		addr.sin_port = 0;
		bind(listen_sock, (struct sockaddr *)&addr, sizeof(struct sockaddr));
		
		len = sizeof(addr);
		getsockname(listen_sock, (struct sockaddr *)&addr, &len);
		listen(listen_sock, 1);

		/* send that we are ready */
		send_cmd(conn->sock_fd, 227, "Entering passive mode (%u,%u,%u,%u,%u,%u)",
				 (htonl(addr.sin_addr.s_addr) & 0xff000000) >> 24,
				 (htonl(addr.sin_addr.s_addr) & 0x00ff0000) >> 16,
				 (htonl(addr.sin_addr.s_addr) & 0x0000ff00) >>  8,
				 (htonl(addr.sin_addr.s_addr) & 0x000000ff),
				 (htons(addr.sin_port) & 0xff00) >> 8,
				 (htons(addr.sin_port) & 0x00ff));

		/*
		 * listen_sock should be added to the poll, and checked by select,
		 * after that when socket is ready do accept.
		 */
		trans->socket = accept_timeout(listen_sock, (SA *)&trans->r_info, 5);
		if (trans->socket != -1) {
			/* we are in PASV mode */
			SET_FLAG(trans->t_flags, T_PASV);
			activate_nonblock(trans->socket);
		} else {
			send_cmd(conn->sock_fd, 500, "Accepting error, sorry");
			PRINT_DEBUG("Accepting error. sorry\n");
		}

		/* we needn't listen further */
		close_socket(listen_sock);
	} else {
		send_cmd(conn->sock_fd, 503, "Sorry, only one transfer at once.");
		PRINT_DEBUG("Sorry, only one transfer at once\n");
	}
	
	FUNC_EXIT_VOID();
}

static void
cmd_retr(struct connection *conn)
{
	transport *t;
	char *l_file;
	
	FUNC_ENTRY();
	
	t = conn->transport;
	if (!QUERY_FLAG(t->t_flags, (T_PORT | T_PASV))) {
		send_cmd(conn->sock_fd, 425, "You must use PASV or PORT before.");
		goto leave;
	}
		
	if (is_path_ok(conn)) {
		l_file = strchr(conn->recv_buf, ' ');
		t->local_fd = open(l_file + 1, O_RDONLY);
		if (t->local_fd != -1) {
			fstat(t->local_fd, &t->st);
			
			FD_SET(t->socket, &srv->write_ready);
			send_cmd(conn->sock_fd, 150, "Binary mode.");
			SET_FLAG(t->t_flags, T_RETR);
		} else {
			send_cmd(conn->sock_fd, 550, "%s", strerror(errno));
		}
	} else {
		errno = ENOENT;
		send_cmd(conn->sock_fd, 550, "%s", strerror(errno));
	}

	if (!QUERY_FLAG(t->t_flags, T_RETR))
		SET_FLAG(t->t_flags, T_KILL);

leave:
	FUNC_EXIT_VOID();
}

static void
cmd_allo(struct connection *conn)
{
	FUNC_ENTRY();
	
	send_cmd(conn->sock_fd, 202, "No storage allocation necessary.");
	
	FUNC_EXIT_VOID();
}

/**
 * cmd_rmd - remove directory
 * 
 * @conn: 
 */
static void
cmd_rmd(struct connection *conn)
{
	char *dir_name;
	int ret;

	FUNC_ENTRY();

	if (is_path_ok(conn)) {
		dir_name = strchr(conn->recv_buf, ' ') + 1;	
		ret = remove_folder(dir_name);
		if (ret == 0)
			send_cmd(conn->sock_fd, 250, "Directory deleted.");
		else
			send_cmd(conn->sock_fd, 550, "%s", strerror(errno));
	}

	FUNC_EXIT_VOID();
}

/**
 * cmd_mkd - make directory RFC ???
 * 
 * @conn: data struct that describes one connection.
 */
static void
cmd_mkd(struct connection *conn)
{
	char *dir_name;
	int ret;
	
	FUNC_ENTRY();
	
	if (is_path_ok(conn)) {
		dir_name = strchr(conn->recv_buf, ' ');	
		ret = mkdir(dir_name + 1, 0755);
		if (ret != -1)
			send_cmd(conn->sock_fd, 257, "%s created.", dir_name + 1);
		else
			send_cmd(conn->sock_fd, 550, "%s", strerror(errno));
	} else {
		send_cmd(conn->sock_fd, 550, "Bad path.");
	}

	FUNC_EXIT_VOID();
}

static void
cmd_stor(struct connection *conn)
{
	transport *t;
	
	FUNC_ENTRY();
	
	t = conn->transport;
	if (QUERY_FLAG(t->t_flags, (T_PORT | T_PASV))) {
		if (is_path_ok(conn)) {
			char *l_file = strchr(conn->recv_buf, ' ') + 1;

			t->local_fd = open(l_file, O_WRONLY | O_CREAT | O_TRUNC, 0666);
			if (t->local_fd != -1) {
				FD_SET(t->socket, &srv->read_ready);
				send_cmd(conn->sock_fd, 150, "Binary mode.");
				SET_FLAG(t->t_flags, T_STOR);
			} else {
				send_cmd(conn->sock_fd, 550, "%s", strerror(errno));
				SET_FLAG(t->t_flags, T_KILL);
			}
		}
	} else {
		send_cmd(conn->sock_fd, 425, "You must use PASV or PORT before.");
	}
	
	FUNC_EXIT_VOID();
}

static void
cmd_size(struct connection *conn)
{
	transport *tr;
	char *l_file;
	int ret;
	
	FUNC_ENTRY();
	
	tr = conn->transport;
	if (is_path_ok(conn)) {
		l_file = strchr(conn->recv_buf, ' ');
		ret = lstat(l_file + 1, &tr->st);
		if (ret != -1)
			send_cmd(conn->sock_fd, 213, "%u", tr->st.st_size);
		else
			send_cmd(conn->sock_fd, 550, "%s", strerror(errno));
	} else {
		errno = ENOENT;
		send_cmd(conn->sock_fd, 550, "%s", strerror(errno));
	}
	
	FUNC_EXIT_VOID();
}

/* static void */
/* cmd_mdtm(struct connection *conn) */
/* { */
/* 	FUNC_ENTRY(); */
	
	
	
/* 	FUNC_EXIT_VOID(); */
/* } */

static void
cmd_list(struct connection *conn)
{
	transport *t = conn->transport;

	FUNC_ENTRY();
	
	if (QUERY_FLAG(t->t_flags, (T_PORT | T_PASV))) {
		activate_nodelay(t->socket);
		do_list(conn);
		SET_FLAG(t->t_flags, T_KILL);
	}
	
	FUNC_EXIT_VOID();
}

/* static void */
/* cmd_nlst(struct connection *conn) */
/* { */
/* 	FUNC_ENTRY(); */
	
	
	
/* 	FUNC_EXIT_VOID(); */
/* } */

static void
cmd_dele(struct connection *conn)
{
	char *l_file;
	int ret;
	
	FUNC_ENTRY();
	
	if (is_path_ok(conn)) {
		l_file = strchr(conn->recv_buf, ' ') + 1;
		ret = unlink(l_file);
		if (ret != -1)
			send_cmd(conn->sock_fd, 250, "File deleted OK.");
		else
			send_cmd(conn->sock_fd, 550, "%s", strerror(errno));
	} else {
		errno = ENOENT;
		send_cmd(conn->sock_fd, 550, "%s", strerror(errno));
	}
	
	FUNC_EXIT_VOID();
}

static void
cmd_noop(struct connection *conn)
{
	FUNC_ENTRY();
	
	send_cmd(conn->sock_fd, 200, "NOOP command successful.");
	
	FUNC_EXIT_VOID();
}

static void
cmd_syst(struct connection *conn)
{
	FUNC_ENTRY();
	
	send_cmd(conn->sock_fd, 215, "UNIX Type: L8");
	
	FUNC_EXIT_VOID();
}

static void
cmd_type(struct connection *conn)
{
	FUNC_ENTRY();
	
	send_cmd(conn->sock_fd, 200, "TYPE ignored (always I)");
	
	FUNC_EXIT_VOID();
}

static void
cmd_abor(struct connection *conn)
{
	transport *t;
	
	FUNC_ENTRY();
	
	t = conn->transport;
	if (!QUERY_FLAG(t->t_flags, T_FREE)) {
		SET_FLAG(t->t_flags, T_KILL);
		send_cmd(conn->sock_fd, 426, "Transport aborted.");
	}
	
	send_cmd(conn->sock_fd, 226, "ABOR command processed OK.");
	FUNC_EXIT_VOID();
}

/* static void */
/* cmd_mode(struct connection *conn) */
/* { */
/* 	FUNC_ENTRY(); */
	

	
/* 	FUNC_EXIT_VOID(); */
/* } */

static void
cmd_help(struct connection *conn)
{
	FUNC_ENTRY();
	
	send_cmd(conn->sock_fd, 414, "Hi, i can't help you.");
	
	FUNC_EXIT_VOID();
}

static void
cmd_stru(struct connection *conn)
{
	FUNC_ENTRY();
	
	send_cmd(conn->sock_fd, 200, "STRU ignored (always F)");
	
	FUNC_EXIT_VOID();
}

static void
cmd_quit(struct connection *conn)
{
	FUNC_ENTRY();
	
	send_cmd(conn->sock_fd, 221, "Goodbay.");
	SET_FLAG(conn->c_flags, C_KILL);
	
	FUNC_EXIT_VOID();
}

/**
 * cmd_pwd - returning the current working dirrectory
 * of the user.
 */
static void
cmd_pwd(struct connection *conn)
{
	int root_len;
	
	FUNC_ENTRY();
	
	root_len = strlen(conn->root_dir);
	send_cmd(conn->sock_fd, 257, "Current dir is \"%s\"",
			 conn->curr_dir + (root_len - 1));
	
	FUNC_EXIT_VOID();
}

static void
cmd_cdup(struct connection *conn)
{
	char path[PATH_MAX];
	int retval;

	FUNC_ENTRY();

	retval = chdir("..");
	if (retval != -1) {
		int root_len = strlen(conn->root_dir);
		
        /* get absolute path */
		(void) getcwd(path, sizeof(path));
		if (path[strlen(path) - 1] != '/')
			strcat(path, "/");
		
		if (strncmp(path, conn->root_dir, root_len)) {
			/* 
			 * if we are going to visit outside
			 * we don't have to change current
			 * directory.
			 */

			/* What does RFC say in such situations ??? */
			send_cmd(conn->sock_fd, 550, "CDUP was undone.");

			/* go back home */
			chdir(conn->curr_dir);
		} else {
			strncpy(conn->curr_dir, path, sizeof(conn->curr_dir));
			send_cmd(conn->sock_fd, 250, "CDUP successfull.");
		}
	}
	
	FUNC_EXIT_VOID();
}

/**
 * cmd_cwd - changing the current working dirrectory
 * of the user.
 */
static void
cmd_cwd(struct connection *conn)
{
	char path[PATH_MAX];
	int root_len;
	int ret;
	
	FUNC_ENTRY();

	if (is_path_ok(conn)) {
		ret = chdir(strchr(conn->recv_buf, ' ') + 1);
		if (ret == -1) {
			send_cmd(conn->sock_fd, 550, "%s", strerror(errno));
			goto exit;
		}

		root_len = strlen(conn->root_dir);
		
		/* get absolute path */
		(void) getcwd(path, sizeof(path));
		if (path[strlen(path) - 1] != '/')
			strcat(path, "/");
		/* 
		 * We must check path, because of symlinks,
		 * and if everything is OK, we can change curr_dir.
		 */
		if (!strncmp(conn->root_dir, path, root_len)) {
			strncpy(conn->curr_dir, path, sizeof(conn->curr_dir));
			send_cmd(conn->sock_fd, 250, "CWD successfull.");
			goto exit;
		} else {
			/* go back to the current dir */
			chdir(conn->curr_dir);
		}
	}
	
	send_cmd(conn->sock_fd, 550, "No such File or Directory.");

exit:
	FUNC_EXIT_VOID();
}

int
parse_cmd(connection *conn)
{
	const struct cmd_handler *h;
	int processed = 0;
	int buf_len;

	FUNC_ENTRY();

	/* 
	 * remove '\r' and '\n' from the recv_buf.
	 */
	buf_len = strcspn(conn->recv_buf, "\r\n");
	conn->recv_buf[buf_len] = '\0';
	conn->recv_buf_len = buf_len; 

	h = cmd_table;

	do {
		if (!strncasecmp(conn->recv_buf, h->cmd_name, h->cmd_len)) {
			if (QUERY_FLAG(conn->c_flags, C_AUTH) ||
			    !strncasecmp(conn->recv_buf, "USER", h->cmd_len) ||
			    !strncasecmp(conn->recv_buf, "PASS", h->cmd_len) ||
			    !strncasecmp(conn->recv_buf, "FEAT", h->cmd_len) ||
			    !strncasecmp(conn->recv_buf, "QUIT", h->cmd_len))
			{
				/*
				 * At first, we must set root UID and root GUID,
				 * and than we will set what we really need on demand.
				 */
				reset_euid();
				reset_egid();

				/*
				 * If a client has already logged in and root permission
				 * really doesn't need we must change euid and egid.
				 */
				if (QUERY_FLAG(conn->c_flags, C_AUTH) && !h->need_root) {
					set_egid(conn->uid);
					set_euid(conn->gid);
				}

				h->cmd_handler(conn);
			} else {
				send_cmd(conn->sock_fd, 503, "You must login, at first.");
			}

			processed++;
			break;
		}
	} while ((++h)->cmd_handler != NULL);

	/* if a client sends bad cmd, we let him know. */
	if (processed == 0) {
		send_cmd(conn->sock_fd, 500, "Bad cmd.");
		PRINT_DEBUG("Bad command: %s\n", conn->recv_buf);
	}

	FUNC_EXIT_INT(processed);
	return processed;
}
