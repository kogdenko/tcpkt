#include "core.h"

#define DEF_PORT ((unsigned short)7385)
#define DEF_RCVBUF 16384
#define DEF_SNDBUF 16384

enum command {
	CMD_ACCEPT,
	CMD_CLOSE,
	CMD_WAIT,
	CMD_RECV,
	CMD_SEND,
};

struct action {
	TAILQ_ENTRY(action) list;
	enum command cmd;
	unsigned int cnt;
};

TAILQ_HEAD(action_head, action);

struct action_head actions;

ssize_t
send_all(int sockfd, const void *buf, size_t len, int flags)
{
	ssize_t rc;
	size_t off;

	for (off = 0; off < len; off += rc) {
		rc = send(sockfd, (const uint8_t *)buf + off, len - off, flags);
		if (rc == -1) {
			if (errno == EINTR) {
				rc = 0;
			} else {
				return -1;
			}
		}
	}

	return off;
}

ssize_t
recv_all(int sockfd, void *buf, size_t len, int flags)
{
	ssize_t rc;
	size_t off;

	for (off = 0; off < len; off += rc) {
		rc = recv(sockfd, (uint8_t *)buf + off, len - off, flags);
		if (rc == 0) {
			break;
		} else if (rc == -1) {
			if (errno == EINTR) {
				rc = 0;
			} else {
				return -1;
			}
		}
	}
	return off;
}

static void
set_mss(int fd, int mss)
{
	if(setsockopt(fd, IPPROTO_TCP, TCP_MAXSEG, &mss, sizeof(mss))) {
		die(errno, "setsockopt(IPPROTO_TCP, TCP_MAXSEG, %d) failed", mss);
	}
}

static void
set_rcvbuf(int fd, unsigned int rcvbuf)
{
	if (setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &rcvbuf, sizeof(rcvbuf)) == -1) {
		die(errno, "setsockopt(SOL_SOCKET, SO_RCVBUF, %d) failed", rcvbuf);
	}
}

static void
set_sndbuf(int fd, unsigned int rcvbuf)
{
	if (setsockopt(fd, SOL_SOCKET, SO_SNDBUF, &rcvbuf, sizeof(rcvbuf)) == -1) {
		die(errno, "setsockopt(SOL_SOCKET, SO_SNDBUF, %d) failed", rcvbuf);
	}
}

static void
set_reuseaddr(int fd, int opt)
{
	if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) == -1) {
		die(errno, "setsockopt(SOL_SOCKET, SO_REUSEADDR, %d) failed", opt);
	}
}

static void
set_reuseport(int fd, int opt)
{
	if (setsockopt(fd, SOL_SOCKET, SO_REUSEPORT, &opt, sizeof(opt)) == -1) {
		die(errno, "setsockopt(SOL_SOCKET, SO_REUSEPORT, %d) failed", opt);
	}
}

static void
set_nodelay(int fd, int opt)
{
	if (setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &opt, sizeof(opt)) == -1) {
		die(errno, "setsockopt(IPPROTO_TCP, TCP_NODELAY, %d) failed", opt);
	}
}

static void
add_action(enum command cmd, char *val_str)
{
	struct action *action;

	action = xmalloc(sizeof(*action));
	action->cmd = cmd;
	action->cnt = strtoul(val_str, NULL, 10);
	TAILQ_INSERT_TAIL(&actions, action, list);
}

static void
validate_actions(int acceptn)
{
	struct action *action;
	int accepted, closed;

	closed = 0;
	accepted = 0;
	TAILQ_FOREACH(action, &actions, list) {
		if (action->cmd == CMD_WAIT) {
			continue;
		}
		if (closed) {
			die(0, "Can't operate on closed socket");
		}
		switch (action->cmd) {
		case CMD_ACCEPT:
			if (acceptn == 0) {
				die(0, "Can't accept: socket is not in LISTEN state");
			} else if (accepted) {
				die(0, "Duplicate accept action");
			}
			accepted = 1;
			break;
		case CMD_CLOSE:
			closed = 1;
			break;
		case CMD_RECV:
			if (acceptn && accepted == 0) {
				die(0, "Can't recv before accept");
			}
			break;
		case CMD_SEND:
			if (acceptn && accepted == 0) {
				die(0, "Can't send before accept");
			}
			break;
		default:
			assert(!"Unknown command");
		}
	}
}

static void
do_actions(int fd)
{
	int rc;
	uint8_t *buf;
	struct action *action;

	TAILQ_FOREACH(action, &actions, list) {
		switch (action->cmd) {
		case CMD_CLOSE:
			close(fd);
			return;
		case CMD_ACCEPT:
			fd = accept(fd, NULL, NULL);
			if (fd == -1) {
				die(errno, "accept() failed");
			}
			break;
		case CMD_WAIT:
			usleep(1000 * action->cnt);
			break;
		case CMD_RECV:
			if (action->cnt == 0) {
				rc = shutdown(fd, SHUT_RD);
				if (rc == -1) {
					die(errno, "shutdown(SHUT_RD) failed");
				}
			} else {
				buf = xmalloc(action->cnt);
				rc = recv_all(fd, buf, action->cnt, 0);
				if (rc < 0) {
					die(errno, "recv() failed");
				}
				free(buf);
			}
			break;
		case CMD_SEND:
			if (action->cnt == 0) {
				rc = shutdown(fd, SHUT_WR);
				if (rc == -1) {
					die(errno, "shutdown(SHUT_WR) failed");
				}
			} else {
				buf = xmalloc(action->cnt);
				rc = send_all(fd, buf, action->cnt, MSG_NOSIGNAL);
				if (rc < 0) {
					die(errno, "send() failed");
				}
				free(buf);
			}
			break;
		default:
			assert(!"Unknown command");
			break;
		}
	}
	buf = xmalloc(2048);
	do {
		rc = recv_all(fd, buf, 2048, 0);
		if (rc < 0) {
			die(errno, "recv() failed");
		}
	} while (rc > 0);
	free(buf);
	close(fd);
}

static void
invalid_argument(int opt, const char *val)
{
	die(0, "invalid argument '-%c': %s", opt, val);
}

static int
print_usage()
{
	printf(
	"Usage: tcput [options] {-l n}\n"
	"       tcput [options] {-C ip[:port]}\n"
	"\n"
	"\tOptions:\n"
	"\t-h            Print this help\n"
	"\t-d            Print debug messages\n"
	"\t-R rcvbuf     Set SO_RCVBUF (default:%u)\n"
	"\t-S sndbuf     Set SO_SNDBUF (default:%u)\n"
	"\t-M mss        Set TCP_MAXSEG\n"
	"\t-N            Set TCP_NODELAY\n"
	"\t-l aceepts    Listen mode\n"
	"\t-B ip[:port]  Bind to\n"
	"\t-C ip[:port]  Connect to\n"
	"\t-a            Add action accept\n"
	"\t-c            Add action close\n"
	"\t-w n          Add action wait #n msec\n"
	"\t-r n          Add action read #n bytes\n"
	"\t-s n          Add action send #n bytes\n"
	,
	DEF_RCVBUF,
	DEF_SNDBUF
	);

	return 4;
}

int
main(int argc, char **argv)
{
	int i, fd, rc, opt, acceptn, nodelay;
	unsigned int rcvbuf, sndbuf;
	uint16_t mss;
	struct sockaddr_in baddr, caddr;

	mss = 0;
	nodelay = 0;
	rcvbuf = DEF_RCVBUF;
	sndbuf = DEF_SNDBUF;
	acceptn = 0;
	memset(&baddr, 0, sizeof(baddr));
	baddr.sin_addr.s_addr = INADDR_ANY;
	memset(&caddr, 0, sizeof(caddr));
	TAILQ_INIT(&actions);
	while ((opt = getopt(argc, argv, "hdR:S:M:Nl:B:C:acw:r:s:")) != -1) {
		switch (opt) {
		case 'h':
			return print_usage();
		case 'd':
			debuging = 1;
			break;
		case 'R':
			rcvbuf = strtoul(optarg, NULL, 10);
			break;
		case 'S':
			sndbuf = strtoul(optarg, NULL, 10);
			break;
		case 'M':
			mss = strtoul(optarg, NULL, 10);
			break;
		case 'N':
			nodelay = 1;
			break;
		case 'l':
			baddr.sin_family = AF_INET;
			acceptn = strtoul(optarg, NULL, 10);
			if (acceptn == 0) {
				invalid_argument(opt, optarg);
			}
			break;
		case 'B':
			baddr.sin_family = AF_INET;
			rc = ipport_pton(AF_INET, optarg, &baddr.sin_addr, &baddr.sin_port);
			if (rc) {
				invalid_argument(opt, optarg);
			}
			break;
		case 'C':
			caddr.sin_family = AF_INET;
			rc = ipport_pton(AF_INET, optarg, &caddr.sin_addr, &caddr.sin_port);
			if (rc) {
				invalid_argument(opt, optarg);
			}
			break;
		case 'a':
			add_action(CMD_ACCEPT, "0");
			break;
		case 'c':
			add_action(CMD_CLOSE, "0");
			break;
		case 'w':
			add_action(CMD_WAIT, optarg);
			break;
		case 'r':
			add_action(CMD_RECV, optarg);
			break;
		case 's':
			add_action(CMD_SEND, optarg);
			break;
		}
	}
	fd = socket(AF_INET, SOCK_STREAM, 0);
	if (fd == -1) {
		die(errno, "socket(AF_INET, SOCK_STREAM) failed");
	}
	if (mss) {
		set_mss(fd, mss);
	}
	set_reuseaddr(fd, 1);
	set_reuseport(fd, 1);
	set_rcvbuf(fd, rcvbuf);
	set_sndbuf(fd, sndbuf);
	if (nodelay) {
		set_nodelay(fd, 1);
	}
	if (baddr.sin_family) {
		if (baddr.sin_port == 0) {
			baddr.sin_port = CPU_TO_BE16(DEF_PORT);
		}
		rc = bind(fd, (struct sockaddr *)&baddr, sizeof(baddr));
		if (rc == -1) {
			die(errno, "bind(%s:%hu) failed",
			    inet_ntoa(baddr.sin_addr),
			    BE16_TO_CPU(baddr.sin_port));
		}
	}
	validate_actions(acceptn);
	if (acceptn) {
		if (caddr.sin_family != 0) {
			return print_usage();
		}
		if (baddr.sin_family == 0) {
			return print_usage();
		}
		if (listen(fd, 5) == -1) {
			die(errno, "listen() failed");
		}
		for (i = 0; i < acceptn; ++i) {
			do_actions(fd);
		}
		close(fd);
	} else {
		if (caddr.sin_family == 0) {
			return print_usage();
		}
		if (caddr.sin_port == 0) {
			caddr.sin_port = CPU_TO_BE16(DEF_PORT);
		}
		rc = connect(fd, (struct sockaddr *)&caddr, sizeof(caddr));
		if (rc == -1) {
			die(errno, "connect(%s:%hu) failed",
				inet_ntoa(caddr.sin_addr),
				BE16_TO_CPU(caddr.sin_port));
		}
		do_actions(fd);
	}

	return 0;
}
