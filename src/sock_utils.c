#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <fcntl.h>
#include <stdarg.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <errno.h>

/* local headers */
#include <debug.h>
#include <sock_utils.h>
#include <list.h>
#include <mem.h>

/**
 * send_data - sending a message to a socket,
 * return the number of characters sent, otherwise -1.
 * 
 * @s:     socket;
 * @buf:   buffer where the message should be stored;
 * @len:   length of the message;
 * @flags: flags which we passing to send.
 */
int
send_data(int s, const void *buf, int len, int flags)
{
	int total = 0;
	int ret = 0;
	int n = 0;
	
	FUNC_ENTRY();
	
	for (total = 0; total < len; total += n) {
		n = send(s, buf + total, len - total, flags);
		if (n < 0) {
			PRINT_DEBUG("Write to socket failed with errno %d: %s\n",
						errno, strerror(errno));
			break;
		}
	}
	
	ret = ((n < 0) ? -1 : total);
	
	FUNC_EXIT_INT(ret);
	return ret;
}

/**
 * recv_data - receive a message from a socket,
 * return the number of bytes received, or -1
 * if an error obtained, also 0 will be recived
 * when the peer has performed an orderly shutdown.
 * 
 * @s:     socket;
 * @buf:   buffer where the message will be stored;
 * @len:   length of the message;
 * @flags: flags which we passing to recv.
 */
int
recv_data(int s, void *buf, int len, int flags)
{
	int total = 0;
	int ret = 0;
	int n = 0;

	FUNC_ENTRY();

	for (total = 0; total < len; total += n) {
		n = recv(s, buf + total, len - total, flags);
		if (n <= 0) {
			PRINT_DEBUG("Read from socket failed with errno %d: %s\n",
						errno, strerror(errno));
			break;
		}
	}

	ret = ((n == 0) ? 0 : (n < 0) ? -1 : total);

	FUNC_EXIT_INT(ret);
	return ret;
}

/**
 * send_cmd - send a message to socket, but
 * also it is able to build format string 
 * like printf.
 *
 * @s:      socket;
 * @cmd:    codes which ftp protocol uses;
 * @format: string that specifies how subsequent arguments are converted.
 */
void
send_cmd(int s, const int cmd, const char *const format, ...)
{
	char buf[256] = {'\0'};
	char fmt[256] = {'\0'};
	va_list args;
	int err;
	int i;
		
	FUNC_ENTRY();
	
	snprintf(fmt, sizeof(fmt), "%03u %s\r\n",
			 cmd, format);
	
	va_start(args, format);
	i = vsnprintf(buf, sizeof(buf), fmt, args);
	va_end(args);
	
	err = send_data(s, buf, i, 0);
	
	FUNC_EXIT_VOID();
}

/**
 * get_remote_info - get name of connected peer socket.
 * On success, zero is returned, otherwise -1.
 * 
 * @s:    socket;
 * @name: pointer which will contain some information.
 */
int
get_remote_info(int s, struct sockaddr *name)
{
	unsigned int sock_len = 0;
	int ret = 0;

	FUNC_ENTRY();

	sock_len = sizeof(struct sockaddr);
	ret = getpeername(s, name, &sock_len);
	
	if (ret == -1)
		PRINT_DEBUG("getpeername failed with errno %d: %s\n",
				  errno, strerror(errno));

	FUNC_EXIT_INT(ret);
	return ret;
}

/**
 * start_tcp_listen - starts listen a port number.
 * On success, listen socket is returned, otherwise -1.
 * 
 * @port_number: port number which be listened;
 * @ip_ver:      IPv4 or IPv6;
 * @backlog:     maximum length the queue of pending,
 *               connections may grow to.
 */
int
start_tcp_listen(int port_number, int ip_ver, int backlog)
{
	struct sockaddr_in serv_addr;
	int listenfd = 0;
	int retval = 0;
	int len = 0;
	
	FUNC_ENTRY();
	
	if (ip_ver == 4)
		listenfd = get_ipv4_socket();
	else if (ip_ver == 6)
		listenfd = get_ipv6_socket();

	bzero(&serv_addr, sizeof(serv_addr));    

	if (listenfd != -1) {
		serv_addr.sin_family = AF_INET;
		serv_addr.sin_addr.s_addr = htonl(INADDR_ANY);
		serv_addr.sin_port = (backlog) ? htons(port_number):0;
		
		if (((struct sockaddr *)&serv_addr)->sa_family == PF_INET)
			len = sizeof(struct sockaddr_in);
		else if (((struct sockaddr *)&serv_addr)->sa_family == PF_INET6)
			len = sizeof(struct sockaddr_in6);

		activate_reuseaddr(listenfd);

		retval = bind(listenfd, (struct sockaddr *)&serv_addr, len);
		if (retval != -1) {
			retval = listen(listenfd, backlog);
			if (retval < 0) {
				PRINT_DEBUG("listen failed with errno %d: %s\n",
						  errno, strerror(errno));
				listenfd = -1;
			}
		} else {
			PRINT_DEBUG("bind failed with errno %d: %s\n",
					  errno, strerror(errno));
			listenfd = -1;
		}
	}
	
	FUNC_EXIT_INT(listenfd);
	return listenfd;
}

/**
 * accept_timeout - accepting connection from the client.
 * On successful connected socked is returned, otherwise -1.
 *
 * @s:      socket;
 * @r_addr: will contain info about remote host;
 * @sec:    wait time.
 */
int
accept_timeout(int s, struct sockaddr *r_addr, unsigned int sec)
{
	int connect_fd = 0;
	int retval = 0;
	fd_set r_fd;
	fd_set w_fd;
	
	FUNC_ENTRY();
	
	do {
		FD_ZERO(&r_fd);
		FD_SET(s, &r_fd);
		
		w_fd = r_fd;
		
		if (sec > 0) {
			struct timeval time;
			
			time.tv_sec = sec;
			time.tv_usec = 0;
			
			retval = select(s + 1, &r_fd, &w_fd, NULL, &time);
		} else {
			retval = select(s + 1, &r_fd, &w_fd, NULL, NULL);
		}
		
	} while (retval < 0 && errno == EINTR);
	
	if (retval > 0) {
		socklen_t len = sizeof(*r_addr);
		
		connect_fd = accept(s, r_addr, &len);
		retval = (connect_fd > 0) ? connect_fd : -1;
	} else if (retval == 0) {
		PRINT_DEBUG("warning: accept timeout!\n");
		retval = -1;
	} else {
		PRINT_DEBUG("select failed with errno %d: %s\n",
				  errno, strerror(errno));
	}
	
	FUNC_EXIT_INT(retval);
	return retval;
}

/**
 * connect_timeout - connect to the client.
 * On success 0 is returned, otherwise -1.
 * 
 * @s:      socket;
 * @r_addr: information about remote client;
 * @sec:    how much time we should wait.
 */
int
connect_timeout(int s, struct sockaddr *r_addr, int sec)
{
	struct sockaddr remote_addr;
	socklen_t sock_len = 0;
	int retval;
	
	FUNC_ENTRY();
	
	if (sec > 0)
		activate_nonblock(s);
	
	sock_len = sizeof(remote_addr);
	retval = connect(s, r_addr, sock_len);
		
	if (retval < 0 && errno == EINPROGRESS) {
		struct timeval timeout;
		fd_set r_fd;
		fd_set w_fd;
		int n;

		do {
			FD_ZERO(&r_fd);
			FD_SET(s, &r_fd);
			w_fd = r_fd;
			
			timeout.tv_sec = sec;
			timeout.tv_usec = 0;
			
			n = select(s + 1, &r_fd, &w_fd, NULL, &timeout);
		} while (n < 0 && errno == EINTR);

		if (n > 0) {
			/* We have to check the socket for error */
			if (FD_ISSET(s, &r_fd) || (FD_ISSET(s, &w_fd)))
				retval = check_socket(s);
		} else if (n == 0) {
			PRINT_DEBUG("No data within %d seconds\n", sec);
		} else {
			PRINT_DEBUG("select failed with errno %d: %s\n",
					  errno, strerror(errno));
		}
	}
	
	if (sec > 0)
		deactivate_nonblock(s);

	FUNC_EXIT_INT(retval);
	return retval;
}


/**
 * check_socket - checking a socket on error.
 * 
 * @s: socket;
 */
int
check_socket(int s)
{
	socklen_t err_len = 0;
	int retval = 0;
	int error = 0;
	
	FUNC_ENTRY();
	
	err_len = sizeof(error);
	retval = getsockopt(s, SOL_SOCKET, SO_ERROR, &error, &err_len);
	if (retval < 0 || error != 0)
		PRINT_DEBUG("getsockopt failed with errno %d: %s\n",
				  errno, strerror(errno));
	
	FUNC_EXIT_INT(retval);
	return retval;
}

void
close_socket(int s)
{
	int ret;
	
	FUNC_ENTRY();
	
	ret = shutdown(s, SHUT_RDWR);
	if (ret)
		PRINT_DEBUG("shutdown failed with errno %d: %s\n",
				  errno, strerror(errno));
	close(s);

	FUNC_EXIT_VOID();
}

void
activate_nodelay(int s)
{
	int ret = 0;
	int nodelay = 1;
	
	FUNC_ENTRY();
	
	ret = setsockopt(s, IPPROTO_TCP, TCP_NODELAY, &nodelay,
				  sizeof(nodelay));
	if (ret != 0)
		PRINT_DEBUG("setsockopt failed with errno %d: %s\n",
				  errno, strerror(errno));
	
	FUNC_EXIT_VOID();
}

void
activate_cork(int s)
{
	int ret = 0;
	int on = 1;

	FUNC_ENTRY();
	
	ret = setsockopt(s, IPPROTO_TCP, TCP_CORK, &on, sizeof(on));
	if (ret != 0)
		PRINT_DEBUG("setsockopt failed with errno %d: %s\n",
				  errno, strerror(errno));

	FUNC_EXIT_VOID();
}

void
activate_reuseaddr(int s)
{
	int ret = 0;
	int on = 1;

	FUNC_ENTRY();
	
	ret = setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &on,
				  sizeof(on));
	if (ret != 0)
		PRINT_DEBUG("setsockopt failed with errno %d: %s\n",
				  errno, strerror(errno));

	FUNC_EXIT_VOID();
}

int
get_ipv4_socket(void)
{
	int ipv4_sock;

	FUNC_ENTRY();
	
	ipv4_sock = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP);
	if (ipv4_sock < 0)
		PRINT_DEBUG("socket failed with errno %d: %s\n",
				  errno, strerror(errno));

	FUNC_EXIT_INT(ipv4_sock);
	return ipv4_sock;
}

int
get_ipv6_socket(void)
{
	int ipv6_sock;

	FUNC_ENTRY();
	
	ipv6_sock = socket(PF_INET6, SOCK_STREAM, IPPROTO_TCP);
	if (ipv6_sock < 0)
		PRINT_DEBUG("socket failed with errno %d: %s\n",
				  errno, strerror(errno));
	
	FUNC_EXIT_INT(ipv6_sock);
	return ipv6_sock;
}


void
activate_nonblock(int s)
{
	int retval = -1;
	int flags = 0;

	FUNC_ENTRY();
	
	flags = fcntl(s, F_GETFL);
	if (flags > 0) {
		flags |= O_NONBLOCK;
		retval = fcntl(s, F_SETFL, flags);
	}
	
	if (retval < 0)
		PRINT_DEBUG("fcntl failed with errno %d: %s\n",
				  errno, strerror(errno));
	
	FUNC_EXIT_VOID();
}

void
deactivate_nonblock(int s)
{
	int retval = -1;
	int flags = 0;

	FUNC_ENTRY();
	
	flags = fcntl(s, F_GETFL);
	if (flags > 0) {
		flags &= ~O_NONBLOCK;
		retval = fcntl(s, F_SETFL, flags);
	}
	
	if (retval < 0)
		PRINT_DEBUG("fcntl failed with errno %d: %s\n",
				  errno, strerror(errno));
	
	FUNC_EXIT_VOID();
}
