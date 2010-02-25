#ifndef __CMDS_H__
#define __CMDS_H__

struct cmd_handler {
	char cmd_name[10];
	char arg;
	void (*cmd_handler)(struct connection *const);
	char need_root;
	int need_auth;
	char cmd_len;
};

extern const struct cmd_handler cmd_table[];
extern void parse_cmd(connection *conn);

#endif  /* __CMDS_H__ */
