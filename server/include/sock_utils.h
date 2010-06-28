#ifndef __SOCK_UTILS_H__
#define __SOCK_UTILS_H__

typedef struct sockaddr SA;

extern int send_data(int, const void *, int, int);
extern int recv_data(int, void *, int, int);
extern void send_cmd(int, const int, const char *const, ...);
extern int get_remote_info(int, struct sockaddr *);
extern int start_tcp_listen(int, int, int);
extern int connect_timeout(int, struct sockaddr *, int);
extern int accept_timeout(int, struct sockaddr *, unsigned int);
extern void activate_nonblock(int);
extern void deactivate_nonblock(int);
extern void activate_nodelay(int);
extern void activate_cork(int);
extern void activate_reuseaddr(int);
extern int get_ipv4_socket(void);
extern int get_ipv6_socket(void);
extern void close_socket(int);
extern int check_socket(int);
extern int bytes_available(int);

#endif
