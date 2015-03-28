#ifndef __CMDS_H__
#define __CMDS_H__

#define MAX_CMD_LEN 10

struct cmd_handler {
	char cmd_name[MAX_CMD_LEN];
	char arg;
	void (*cmd_handler)(void *, struct connection *const);
	char need_root;
	int need_auth;
	char cmd_len;
};

extern const struct cmd_handler cmd_table[];
extern void parse_cmd(void *, connection *conn);

#endif  /* __CMDS_H__ */
