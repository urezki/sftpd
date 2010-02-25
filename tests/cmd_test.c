#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <time.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <errno.h>
#include <err.h>		

static const char *const cmd_table[] =
{
	"USER", "PASS", "PORT", "PASV",
	"LIST", "CDUP", "RETR", "SIZE",
	"NOOP", "SYST", "TYPE", "ABOR",
	"STRU", "FEAT", "HELP", "STOR",
	"DELE", "RMD", "MKD", "ALLO",
	"PWD", "CWD", NULL
};

int main(int argc, char **argv)
{
	struct sockaddr_in r_addr;
	socklen_t sock_len;
	char tmp_buf[4096];
	int ipv4_sock;
	int cmd_count;
	int ret;
	int i = 0;

	if (argv[1] == NULL || argv[2] == NULL)
		err(-1, "use host port");

	ipv4_sock = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP);
	if (ipv4_sock < 0)
		err(-1, "socket failed with errno %d: %s\n",
			errno, strerror(errno));

	sock_len = sizeof(struct sockaddr);
	r_addr.sin_family = AF_INET;
	r_addr.sin_addr.s_addr = inet_addr(argv[1]);
	r_addr.sin_port = htons(atoi(argv[2]));

	ret = connect(ipv4_sock, (struct sockaddr *)&r_addr, sock_len);
	if (ret != 0)
		err(-1, "connect failed with errno %d: %s\n",
			errno, strerror(errno));

	(void) write(ipv4_sock, "USER anonymous\r\n", 16);
	(void) read(ipv4_sock, tmp_buf, sizeof(tmp_buf));
	(void) write(ipv4_sock, "PASS test@test.org\r\n", 20);
	(void) read(ipv4_sock, tmp_buf, sizeof(tmp_buf));

	for (cmd_count = 0; cmd_table[cmd_count]; cmd_count++)
		;

	srand(time(NULL));
	
	while (1) {
		int r_index = rand() % cmd_count;
		ret = snprintf(tmp_buf, sizeof(tmp_buf) - 1, "%s\r\n", cmd_table[r_index]);
		if (ret > 0)
			tmp_buf[ret] = '\0';

		ret = write(ipv4_sock, tmp_buf, ret);
		if (ret > 0) {
			ret = read(ipv4_sock, tmp_buf, sizeof(tmp_buf));
			if (ret > 0) {
				tmp_buf[ret] = '\0';
				fprintf(stdout, "got --> %s", tmp_buf);
			}
		} else {
			err(-1, "write failed with errno %d: %s\n",
				errno, strerror(errno));
		}

		if (i++ > 100) {
			srand(time(NULL));
			i = 0;
		}
	}

	return 0;
}
