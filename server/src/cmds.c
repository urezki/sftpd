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
#include <dirent.h>

/* local headers */
#include <list.h>
#include <sock_utils.h>
#include <utils.h>
#include <debug.h>
#include <ls.h>
#include <sftpd.h>
#include <cmds.h>
#include <hash.h>
#include <mem.h>
#include <str.h>

static int
convert_to_absolute_path(const char *root, const char *cur,
			const char *cmd_arg, char *out)
{
	char tmp_path[PATH_MAX] = {'\0'};
	char *dot;
	int n;

	if (root == NULL || cur == NULL)
		return -1;

	if (cmd_arg) {
		if (*cmd_arg == '/' || *cmd_arg == '~') {
			/* 1) cd / 2) cd ~/ 3) cd ~ */
			n = snprintf(out, PATH_MAX, "%s%s", root,
					*(cmd_arg + 1) == '/' ? cmd_arg + 2 : cmd_arg + 1);
		} else {
			/* 2) cd foo/ */
			n = snprintf(out, PATH_MAX, "%s%s", cur, cmd_arg);
		}
	} else {
		n = snprintf(out, PATH_MAX, "%s", cur);
	}

	if (n)
		;

	/* /home/urezki/../ftp/.. */
	if ((dot = strrchr(out, '.')))
		if (*(dot - 1) == '.' && *(dot + 1) == '\0')
			strcat(out, "/");

	/*
	 * Here we can have following combinations:
	 * 1) /home/urezki/../ftp/../
	 * 2) /home/urezki/
	 */
	while ((dot = strstr(out, "/../"))) {
		char *s_pp = NULL;

		if (dot == out)
			s_pp = dot;
		else
			s_pp = (dot - 1);

		while (s_pp != out && *s_pp != '/')
			s_pp--;

		*(s_pp + 1) = '\0';

		snprintf(tmp_path, PATH_MAX, "%s%s", out, dot + 4);
		snprintf(out, PATH_MAX, "%s", tmp_path);
	}

	return 0;
}

static int
convert_path_to_abs_and_check(struct connection *conn)
{
	char abs_path[PATH_MAX] = {'\0'};
	char *cmd_arg;
	struct stat st;
	int ret;

	cmd_arg = strchr(conn->recv_buf, ' ');
	if (cmd_arg)
		cmd_arg += 1;

	/*
	 * We may pass NULL as cmd_path argument. In that case
	 * current directory of the user should be reported.
	 */
	ret = convert_to_absolute_path(conn->root_dir,
					conn->curr_dir, cmd_arg, abs_path);
	if (ret < 0)
		goto fail;

	/* check symbolic links */
	if (stat(abs_path, &st) != -1) {
		if (!S_ISLNK(st.st_mode)) {
			char buf[1024] = {'\0'};
			int len;

			len = readlink(abs_path, buf, sizeof(buf) - 1);
			if (len != -1) {
				buf[len] = '\0';
				*abs_path = '\0';
				strcat(abs_path, buf);
			}
		}
	}

	if (!strncmp(abs_path, conn->root_dir, strlen(conn->root_dir))) {
		char cmd[MAX_CMD_LEN] = {'\0'};
		int i = 0;

		/* get command name */
		for (i = 0; conn->recv_buf[i] != ' ' && conn->recv_buf[i] != '\0'; i++) {
			if (i < (sizeof(cmd) - 1))
				cmd[i] = conn->recv_buf[i];
		}

		snprintf(conn->recv_buf, PATH_MAX - i, "%s %s", cmd, abs_path);

		return 1;
	}

fail:
	return 0;
}

static void
cmd_feat(void *srv, struct connection *conn)
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
cmd_user(void *srv, struct connection *conn)
{
	char tmp_buf[120] = {'\0'};
	int rejected = 0;

	FUNC_ENTRY();

	FLAG_CLEAR(conn->c_flags, C_AUTH);

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
cmd_pass(void *srv, struct connection *conn)
{
	struct spwd *p_shadow;
	struct passwd *p;

	FUNC_ENTRY();

	if (FLAG_QUERY(conn->c_flags, C_AUTH))
		return;

	p = getpwnam(conn->user_name);
	if (p != NULL) {
		char *user_pass;

		user_pass = strchr(conn->recv_buf, ' ');

		/* in case of anonymous access */
		if (!strncmp(conn->user_name, "ftp", 3)) {
			FLAG_SET(conn->c_flags, C_AUTH);
		} else if (user_pass != NULL && conn->recv_buf_len > 4) {
			char *p_crypt;

			p_crypt = crypt(user_pass + 1, p->pw_passwd);
			if (p_crypt) {
				if (!strcmp(p_crypt, p->pw_passwd))
					FLAG_SET(conn->c_flags, C_AUTH);
			} else {
				/* checking shadow pass */
				p_shadow = getspnam(conn->user_name);
				if (p_shadow)
					p_crypt = crypt(user_pass + 1, p_shadow->sp_pwdp);

				if (p_crypt)
					if (!strcmp(p_crypt, p_shadow->sp_pwdp))
						FLAG_SET(conn->c_flags, C_AUTH);
			}
		}
	}

	if (FLAG_QUERY(conn->c_flags, C_AUTH)) {
		conn->uid = p->pw_uid;
		conn->gid = p->pw_gid;

		(void) strncpy(conn->root_dir, p->pw_dir,
				sizeof(conn->root_dir));

		if (conn->root_dir[strlen(conn->root_dir) - 1] != '/')
			(void) strcat(conn->root_dir, "/");

		(void) strncpy(conn->curr_dir, p->pw_dir,
				sizeof(conn->curr_dir));

		if (conn->curr_dir[strlen(conn->curr_dir) - 1] != '/')
			(void) strcat(conn->curr_dir, "/");

		send_cmd(conn->sock_fd, 230, "%s %s", conn->user_name, "logged in");
		chdir(conn->root_dir);
		PRINT_DEBUG("%s user logged in\n", conn->user_name);
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
cmd_port(void *srv, struct connection *conn)
{
	char *ip_address = NULL;
	int data_port = 0;
	transport *t;
	int socket;
	int ret;
	int len;

	FUNC_ENTRY();

	t = conn->transport;
	ip_address = strchr(conn->recv_buf, ' ');

	if (FLAG_QUERY(t->t_flags, T_FREE) && ip_address) {
		short int a0, a1, a2, a3, p0, p1;

		ret = sscanf(ip_address + 1, "%3hu,%3hu,%3hu,%3hu,%3hu,%3hu",
					 &a0, &a1, &a2, &a3, &p0, &p1);

		data_port = p0 * 256 + p1;
		if (data_port > 1024 && ret == 6) {
			socket = get_ipv4_socket();
			if (socket < 0)
				goto failed_with_errno;

			t->data_port = data_port;
			activate_reuseaddr(socket);

			t->r_info.sin_port = htons(DATA_PORT);
			t->r_info.sin_family = AF_INET;

			len = sizeof(t->r_info);
			ret = bind(socket, (SA *)&t->r_info, len);
			if (ret != 0) {
				close_socket(socket);
				goto failed_with_errno;
			}

			t->r_info.sin_family = AF_INET;
			t->r_info.sin_port = htons(t->data_port);
			t->r_info.sin_addr.s_addr = htonl(
				((unsigned char)(a0) << 24) +
				((unsigned char)(a1) << 16) +
				((unsigned char)(a2) << 8)  +
				((unsigned char)(a3)));

			ret = connect_timeout(socket, (SA *)&t->r_info, 5);
			if (ret != 0) {
				close_socket(socket);
				goto failed_with_errno;
			}

			/* we are in a port mode */
			t->socket = socket;
			FLAG_SET(t->t_flags, T_PORT);
			activate_nonblock(t->socket);
			send_cmd(conn->sock_fd, 220, "PORT command successful");
			goto end;
		}
	} else {
		send_cmd(conn->sock_fd, 503, "Sorry, only one transfer at once.");
		PRINT_DEBUG("Sorry, only one transfer at once\n");
		goto end;
	}

failed_with_errno:
	send_cmd(conn->sock_fd, 503, "%s", strerror(errno));
end:
	FUNC_EXIT_VOID();
}

static void
cmd_pasv(void *srv, struct connection *conn)
{
	struct sockaddr_in addr;
	int listen_sock;
	transport *t;
	socklen_t len;
	int ret;

	FUNC_ENTRY();

	t = conn->transport;
	if (FLAG_QUERY(t->t_flags, T_FREE)) {
		listen_sock = get_ipv4_socket();
		if (listen_sock < 0)
			goto failed_with_errno;

		activate_reuseaddr(listen_sock);
		memset(&addr, 0, sizeof(addr));

		len = sizeof(addr);
		getsockname(conn->sock_fd, (struct sockaddr *)&addr, &len);

		addr.sin_port = 0;
		ret = bind(listen_sock, (struct sockaddr *)&addr, sizeof(struct sockaddr));
		if (ret != 0) {
			close_socket(listen_sock);
			goto failed_with_errno;
		}

		len = sizeof(addr);
		getsockname(listen_sock, (struct sockaddr *)&addr, &len);
		ret = listen(listen_sock, 1);
		if (ret != 0) {
			close_socket(listen_sock);
			goto failed_with_errno;
		}

		/* we are ready */
		send_cmd(conn->sock_fd, 227, "Entering passive mode (%u,%u,%u,%u,%u,%u)",
				 (htonl(addr.sin_addr.s_addr) & 0xff000000) >> 24,
				 (htonl(addr.sin_addr.s_addr) & 0x00ff0000) >> 16,
				 (htonl(addr.sin_addr.s_addr) & 0x0000ff00) >>  8,
				 (htonl(addr.sin_addr.s_addr) & 0x000000ff),
				 (htons(addr.sin_port) & 0xff00) >> 8,
				 (htons(addr.sin_port) & 0x00ff));

		t->listen_socket = listen_sock;
		FD_SET(t->listen_socket, &((ftpd *)srv)->read_ready);
		FLAG_SET(t->t_flags, T_ACPT);
		goto end;
	} else {
		send_cmd(conn->sock_fd, 503, "Sorry, only one transfer at once.");
		PRINT_DEBUG("Sorry, only one transfer at once\n");
		goto end;
	}

failed_with_errno:
	send_cmd(conn->sock_fd, 503, "%s", strerror(errno));
end:
	FUNC_EXIT_VOID();
}

static void
cmd_retr(void *srv, struct connection *conn)
{
	transport *t;
	char *l_file;
	
	FUNC_ENTRY();
	
	t = conn->transport;
	if (!FLAG_QUERY(t->t_flags, (T_PORT | T_PASV))) {
		send_cmd(conn->sock_fd, 425, "You must use PASV or PORT before.");
		goto leave;
	}
		
	if (convert_path_to_abs_and_check(conn)) {
		l_file = strchr(conn->recv_buf, ' ');
		t->local_fd = open(l_file + 1, O_RDONLY);
		if (t->local_fd != -1) {
			fstat(t->local_fd, &t->st);
			
			FD_SET(t->socket, &((ftpd *)srv)->write_ready);
			send_cmd(conn->sock_fd, 150, "Binary mode.");
			FLAG_SET(t->t_flags, T_RETR);
		} else {
			send_cmd(conn->sock_fd, 550, "%s", strerror(errno));
		}
	} else {
		send_cmd(conn->sock_fd, 550, "%s", strerror(ENOENT));
	}

	if (!FLAG_QUERY(t->t_flags, T_RETR))
		FLAG_APPEND(t->t_flags, T_KILL);

leave:
	FUNC_EXIT_VOID();
}

static void
cmd_allo(void *srv, struct connection *conn)
{
	FUNC_ENTRY();
	
	send_cmd(conn->sock_fd, 202, "No storage allocation necessary.");
	
	FUNC_EXIT_VOID();
}

#ifdef UPLOAD_SUPPORT
static void
cmd_stor(void *srv, struct connection *conn)
{
	transport *t;

	FUNC_ENTRY();

	t = conn->transport;
	if (FLAG_QUERY(t->t_flags, (T_PORT | T_PASV))) {
		if (convert_path_to_abs_and_check(conn)) {
			char *l_file = strchr(conn->recv_buf, ' ') + 1;

			t->local_fd = open(l_file, O_WRONLY | O_CREAT | O_TRUNC, 0666);
			if (t->local_fd != -1) {
				FD_SET(t->socket, &((ftpd *) srv)->read_ready);
				send_cmd(conn->sock_fd, 150, "Binary mode.");
				FLAG_SET(t->t_flags, T_STOR);
			} else {
				send_cmd(conn->sock_fd, 550, "%s", strerror(errno));
				FLAG_APPEND(t->t_flags, T_KILL);
			}
		}
	} else {
		send_cmd(conn->sock_fd, 425, "You must use PASV or PORT before.");
	}

	FUNC_EXIT_VOID();
}

static void
cmd_dele(void *srv, struct connection *conn)
{
	char *l_file;
	int ret;

	FUNC_ENTRY();

	if (convert_path_to_abs_and_check(conn)) {
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

/**
 * cmd_rmd - remove directory
 * 
 * @conn: 
 */
static void
cmd_rmd(void *srv, struct connection *conn)
{
	char *dir_name;
	int ret;

	FUNC_ENTRY();

	if (convert_path_to_abs_and_check(conn)) {
		dir_name = strchr(conn->recv_buf, ' ') + 1;	
		ret = remove_folder(dir_name);
		if (ret == 0)
			send_cmd(conn->sock_fd, 250, "Directory deleted.");
		else
			send_cmd(conn->sock_fd, 550, "%s", strerror(errno));
	} else {
		send_cmd(conn->sock_fd, 550, "sorry bad path");
	}

	FUNC_EXIT_VOID();
}

/**
 * cmd_mkd - make directory RFC ???
 * 
 * @conn: data struct that describes one connection.
 */
static void
cmd_mkd(void *srv, struct connection *conn)
{
	char *dir_name;
	int ret;
	
	FUNC_ENTRY();
	
	if (convert_path_to_abs_and_check(conn)) {
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
#endif	/* UPLOAD_SUPPORT */

static void
cmd_size(void *srv, struct connection *conn)
{
	transport *tr;
	char *l_file;
	int ret;
	
	FUNC_ENTRY();
	
	tr = conn->transport;
	if (convert_path_to_abs_and_check(conn)) {
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

/**
 * If the pathname specifies a directory the server should
 * transfer a list of files in the specified directory. If
 * the pathname specifies a file then the server should send
 * current information on the file. A null argument implies
 * the user's current working or default directory.
 */
static void
cmd_list(void *srv, struct connection *c)
{
	char *path;
	transport *t;
	int ret;

	t = c->transport;

	if (!FLAG_QUERY(t->t_flags, (T_PORT | T_PASV)))
		goto use_port_or_pasv;

	if (!convert_path_to_abs_and_check(c))
		goto no_such_file_or_dir;

	path = strchr(c->recv_buf, ' ');
	BUG_ON(!path);
	path += 1;

	ret = stat(path, &t->l_opt.st);
	if (ret != 0)
		goto no_such_file_or_dir;

	ret = snprintf(t->l_opt.path, sizeof(t->l_opt.path) - 1, "%s", path);
	if (ret > 0)
		t->l_opt.path[ret] = '\0';

	if (S_ISDIR(t->l_opt.st.st_mode)) {
		FLAG_APPEND(t->l_opt.l_flags, L_FOLD);
	} else {
		FLAG_APPEND(t->l_opt.l_flags, L_FILE);
	}

	send_cmd(c->sock_fd, 150, "ASCII MODE");
	FD_SET(t->socket, &((ftpd *) srv)->write_ready);
	FLAG_SET(t->t_flags, T_LIST);
	return;

use_port_or_pasv:
	send_cmd(c->sock_fd, 550, "sorry, use PORT or PASV first");
	return;

no_such_file_or_dir:
	send_cmd(c->sock_fd, 550, "%s", strerror(ENOENT));
	FLAG_APPEND(t->t_flags, T_KILL);
	return;
}

static void
cmd_nlst(void *srv, struct connection *c)
{
	transport *t = c->transport;

	FLAG_SET(t->l_opt.l_flags, L_NLST);
	return cmd_list(srv, c);
}

static void
cmd_noop(void *srv, struct connection *conn)
{
	FUNC_ENTRY();
	
	send_cmd(conn->sock_fd, 200, "NOOP command successful.");
	
	FUNC_EXIT_VOID();
}

static void
cmd_syst(void *srv, struct connection *conn)
{
	FUNC_ENTRY();

	send_cmd(conn->sock_fd, 215, "UNIX Type: L8");

	FUNC_EXIT_VOID();
}

static void
cmd_type(void *srv, struct connection *conn)
{
	FUNC_ENTRY();
	
	send_cmd(conn->sock_fd, 200, "TYPE ignored (always I)");
	
	FUNC_EXIT_VOID();
}

static void
cmd_abor(void *srv, struct connection *conn)
{
	transport *t;
	
	FUNC_ENTRY();
	
	t = conn->transport;

	/* if it's not FREE */
	if (FLAG_QUERY(t->t_flags, T_FREE)) {
		FLAG_APPEND(t->t_flags, T_KILL);
		send_cmd(conn->sock_fd, 426, "Transport aborted.");
	}
	
	send_cmd(conn->sock_fd, 226, "ABOR command processed OK.");
	FUNC_EXIT_VOID();
}

static void
cmd_help(void *srv, struct connection *conn)
{
	FUNC_ENTRY();
	
	send_cmd(conn->sock_fd, 414, "Hi, i can't help you.");
	
	FUNC_EXIT_VOID();
}

static void
cmd_stru(void *srv, struct connection *conn)
{
	FUNC_ENTRY();
	
	send_cmd(conn->sock_fd, 200, "STRU ignored (always F)");
	
	FUNC_EXIT_VOID();
}

static void
cmd_quit(void *srv, struct connection *conn)
{
	FUNC_ENTRY();
	
	send_cmd(conn->sock_fd, 221, "Goodbay.");
	FLAG_SET(conn->c_flags, C_KILL);
	
	FUNC_EXIT_VOID();
}

/**
 * cmd_pwd - returning the current working dirrectory
 * of the user.
 */
static void
cmd_pwd(void *srv, struct connection *conn)
{
	int root_len;
	
	FUNC_ENTRY();
	
	root_len = strlen(conn->root_dir);
	send_cmd(conn->sock_fd, 257, "Current dir is \"%s\"",
			 conn->curr_dir + (root_len - 1));
	
	FUNC_EXIT_VOID();
}

static void
cmd_cdup(void *srv, struct connection *conn)
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

/* static void */
/* cmd_mdtm(void *srv, struct connection *conn) */
/* { */
/* 	FUNC_ENTRY(); */

/* 	FUNC_EXIT_VOID(); */
/* } */

/**
 * cmd_cwd - changing the current working dirrectory
 * of the user.
 */
static void
cmd_cwd(void *srv, struct connection *conn)
{
	char path[PATH_MAX];
	int root_len;
	int ret;
	
	FUNC_ENTRY();

	if (convert_path_to_abs_and_check(conn)) {
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

void
parse_cmd(void *srv, connection *conn)
{
	const struct cmd_handler *h;
	struct hash_entry *entry;
	char key[MAX_CMD_LEN] = {'\0'};
	int i = 0;

	FUNC_ENTRY();

	/*
	 * remove '\r' or '\n' from the recv_buf
	 */
	i = str_strcspn(conn->recv_buf, "\r\n");
	conn->recv_buf[i] = '\0';
	conn->recv_buf_len = i;

	/* get key, i.e. command name */
	for (i = 0; conn->recv_buf[i] != ' ' && conn->recv_buf[i] != '\0'; i++) {
		if (i < (sizeof(key) - 1))
			key[i] = conn->recv_buf[i];
	}

	/*
	 * convert to apper case
	 */
	str_contac(key);

	entry = hash_lookup(((ftpd *) srv)->cmd_table, key);
	if (entry) {
		h = (const struct cmd_handler *) entry->data;
		if (FLAG_QUERY(conn->c_flags, C_AUTH) || !h->need_auth) {
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
			if (FLAG_QUERY(conn->c_flags, C_AUTH) && !h->need_root) {
				set_egid(conn->uid);
				set_euid(conn->gid);
			}

			h->cmd_handler(srv, conn);
		} else {
			send_cmd(conn->sock_fd, 503, "You must login, at first.");
		}
	} else {
		send_cmd(conn->sock_fd, 500, "Bad cmd.");
		PRINT_DEBUG("Bad command: %s\n", conn->recv_buf);
	}

	FUNC_EXIT_VOID();
}

const struct cmd_handler cmd_table[] =
{
	{ "USER", 1, cmd_user, 1, 0, 4, 0 },
	{ "PASS", 1, cmd_pass, 1, 0, 4, 0 },
	{ "PORT", 1, cmd_port, 1, 1, 4, 0 },
	{ "PASV", 0, cmd_pasv, 0, 1, 4, 0 },
	{ "LIST", 1, cmd_list, 1, 1, 4, 1 },
	{ "NLST", 1, cmd_nlst, 1, 1, 4, 1 },
	{ "CDUP", 0, cmd_cdup, 0, 1, 4, 0 },
	/* { "MDTM", 1, cmd_mdtm, 0, 1, 4, 1 }, */
	{ "RETR", 1, cmd_retr, 0, 1, 4, 1 },
	{ "SIZE", 1, cmd_size, 0, 1, 4, 1 },
	{ "NOOP", 0, cmd_noop, 0, 1, 4, 0 },
	{ "SYST", 0, cmd_syst, 0, 0, 4, 1 },
	{ "TYPE", 0, cmd_type, 0, 1, 4, 0 },
	{ "ABOR", 0, cmd_abor, 0, 1, 4, 0 },
	{ "STRU", 0, cmd_stru, 0, 1, 4, 1 },
	{ "QUIT", 0, cmd_quit, 0, 0, 4, 0 },
	{ "FEAT", 0, cmd_feat, 0, 0, 4, 0 },
	{ "HELP", 0, cmd_help, 0, 1, 4, 0 },
#ifdef UPLOAD_SUPPORT
	{ "STOR", 0, cmd_stor, 0, 1, 4, 1 },
	{ "DELE", 1, cmd_dele, 0, 1, 4, 1 },
	{ "RMD",  1, cmd_rmd,  0, 1, 3, 1 },
	{ "MKD",  1, cmd_mkd,  0, 1, 3, 1 },
#endif
	{ "ALLO", 0, cmd_allo, 0, 1, 4, 0 },
	{ "PWD",  0, cmd_pwd,  0, 1, 3, 0 },
	{ "CWD",  1, cmd_cwd,  0, 1, 3, 0 },
	{ " ",    0, NULL, 0,  0, 0, 0    }
};
