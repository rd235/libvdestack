/*
 * vdestack: run a network namespace as a library (and connect it to a vde network).
 * Copyright (C) 2016 Renzo Davoli, Davide Berardi. University of Bologna. <renzo@cs.unibo.it>
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 */

#include <stdio.h>
#include <fcntl.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <sched.h>
#include <limits.h>
#include <errno.h>
#include <sys/capability.h>
#include <sys/prctl.h>
#include <sys/ioctl.h>
#include <sys/signalfd.h>
#include <net/if.h>
#include <linux/if_tun.h>
#include <libvdeplug.h>
#include <poll.h>
#include <sys/signalfd.h>
#include <execs.h>
#include <dlfcn.h>
#include <vdestack.h>

/* workaround for legacy vde2 libvdeplug.h compatibility */
#ifndef VDE_ETHBUFSIZE
#define VDE_ETHBUFSIZE (9216 + 14 + 4)
#endif

/* just in case prctl.h is not providing these definitions */
#ifndef PR_CAP_AMBIENT
#define PR_CAP_AMBIENT      47
#endif
#ifndef PR_CAP_AMBIENT_RAISE
#define PR_CAP_AMBIENT_RAISE  2
#endif
#ifndef PR_CAP_AMBIENT_LOWER
#define PR_CAP_AMBIENT_LOWER  3
#endif

#define APPSIDE 0
#define DAEMONSIDE 1

#define CONNTYPE_NONE 0
#define CONNTYPE_VDE 1
#define CONNTYPE_VDESTREAM 2

#define DEFAULT_IF_NAME "vde0"

#define errExit(msg)    do { perror(msg); _exit(EXIT_FAILURE); } while(0)

#define CHILD_STACK_SIZE (256 * 1024)

struct vdestack {
	pid_t pid;
	int cmdpipe[2]; // socketpair for commands;
	pid_t cmdpid;
	int sfd;
	int conntype;
	union {
		VDECONN *vdeconn;
		int streamfd[2];
	} conn;
	char *child_stack;
	char ifname[];
};

struct vdecmd {
	char **argv;
	int domain;
	int type;
	int protocol;
};

struct vdereply {
	int rval;
	int err;
};


static struct vdestack *default_stack;
static int real_socket(int domain, int type, int protocol) {
	static int (*socket_next) ();
	if (socket_next == NULL)
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wpedantic"
		socket_next = dlsym(RTLD_NEXT, "socket");
#pragma GCC diagnostic pop
	return socket_next(domain, type, protocol);
}

int socket(int domain, int type, int protocol) {
	if (default_stack == NULL)
		return real_socket(domain, type, protocol);
	else
		return vde_msocket(default_stack, domain, type, protocol);
}

/********************************* DAEMON CODE *******************************/

static void grant_net_capabilities(void) {
	/* set the capability to allow net configuration */
	cap_value_t cap = CAP_NET_ADMIN;
	cap_t caps=cap_get_proc();
	cap_set_flag(caps, CAP_INHERITABLE, 1, &cap, CAP_SET);
	cap = CAP_NET_RAW;
	cap_set_flag(caps, CAP_INHERITABLE, 1, &cap, CAP_SET);
	cap = CAP_NET_BIND_SERVICE;
	cap_set_flag(caps, CAP_INHERITABLE, 1, &cap, CAP_SET);
	cap = CAP_NET_BROADCAST;
	cap_set_flag(caps, CAP_INHERITABLE, 1, &cap, CAP_SET);
	cap_set_proc(caps);
	cap_free(caps);
	prctl(PR_CAP_AMBIENT, PR_CAP_AMBIENT_RAISE, CAP_NET_ADMIN, 0, 0);
	prctl(PR_CAP_AMBIENT, PR_CAP_AMBIENT_RAISE, CAP_NET_RAW, 0, 0);
	prctl(PR_CAP_AMBIENT, PR_CAP_AMBIENT_RAISE, CAP_NET_BIND_SERVICE, 0, 0);
	prctl(PR_CAP_AMBIENT, PR_CAP_AMBIENT_RAISE, CAP_NET_BROADCAST, 0, 0);
}

static int open_tap(char *name) {
	struct ifreq ifr;
	int fd=-1;
	if((fd = open("/dev/net/tun", O_RDWR | O_CLOEXEC)) < 0)
		return -1;
	memset(&ifr, 0, sizeof(ifr));
	ifr.ifr_flags = IFF_TAP | IFF_NO_PI;
	strncpy(ifr.ifr_name, name, sizeof(ifr.ifr_name) - 1);
	if(ioctl(fd, TUNSETIFF, (void *) &ifr) < 0) {
		close(fd);
		return -1;
	}
	return fd;
}

static void uid_gid_map(pid_t pid) {
	char map_file[PATH_MAX];
	FILE *f;
	uid_t euid = geteuid();
	gid_t egid = getegid();
	snprintf(map_file, PATH_MAX, "/proc/%d/uid_map", pid);
	f = fopen(map_file, "w");
	if (f) {
		fprintf(f,"%d %d 1\n",euid,euid);
		fclose(f);
	}
	snprintf(map_file, PATH_MAX, "/proc/%d/setgroups", pid);
	f = fopen(map_file, "w");
	if (f) {
		fprintf(f,"deny\n");
		fclose(f);
	}
	snprintf(map_file, PATH_MAX, "/proc/%d/gid_map", pid);
	f = fopen(map_file, "w");
	if (f) {
		fprintf(f,"%d %d 1\n",egid,egid);
		fclose(f);
	}
}

/* process a cmd message:
	 open a socket in the vde namespace if cmd.argv == NULL
	 otherwise spawn a command (in background) */
static int runcmd (struct vdestack *stack) {
	struct vdecmd cmd;
	int n;
	if ((n = read(stack->cmdpipe[DAEMONSIDE], &cmd, sizeof(cmd))) > 0) {
		if (n == sizeof(cmd)) {
			if (cmd.argv == NULL) {
				struct vdereply reply;
				reply.rval = real_socket(cmd.domain, cmd.type, cmd.protocol);
				reply.err = errno;
				if (write(stack->cmdpipe[DAEMONSIDE], &reply, sizeof(reply)) < 0)
					return -1;
			} else {
				if ((stack->cmdpid = fork()) == 0) {
					prctl(PR_SET_PDEATHSIG, SIGKILL, 0, 0, 0);
					grant_net_capabilities();
					execv(cmd.argv[0],cmd.argv);
					_exit(2);
				}
			}
		}
	}
	return n;
}

/* get the exit status of a terminated command */
static int waitcmd(struct vdestack *stack) {
	struct signalfd_siginfo fdsi;
	if (read(stack->sfd, &fdsi, sizeof(struct signalfd_siginfo)) == sizeof(fdsi)) {
		if (fdsi.ssi_signo == SIGHUP)
			return 1;
		else {
			int status;
			waitpid(fdsi.ssi_pid, &status, 0);
			if (((pid_t) fdsi.ssi_pid) == stack->cmdpid) {
				struct vdereply reply;
				reply.rval = WEXITSTATUS(status);
				reply.err = 0;
				if (write(stack->cmdpipe[DAEMONSIDE], &reply, sizeof(reply)) < 0)
					return 1;
			}
		}
	}
	return 0;
}

#define COMMON_POLLFD(s) {(s)->cmdpipe[DAEMONSIDE], POLLIN, 0}, {(s)->sfd, POLLIN, 0}
static inline int common_poll (struct pollfd *pfd, struct vdestack *stack) {
	if (pfd[0].revents & POLLIN) {
		if (runcmd(stack) <= 0)
			return 1;
	}
	if (pfd[1].revents & POLLIN) 
		return waitcmd(stack);
	return 0;
}

static void notap(struct vdestack *stack) {
	struct pollfd pfd[] = {COMMON_POLLFD(stack)};
	while (poll(pfd, 1, -1) >= 0)
		if (common_poll(pfd, stack))
			break;
}

static void plug2tap(struct vdestack *stack, int tapfd) {
	int n;
	char buf[VDE_ETHBUFSIZE];
	VDECONN *conn = stack->conn.vdeconn; 
	struct pollfd pfd[] = {COMMON_POLLFD(stack),
		{tapfd, POLLIN, 0}, 
		{vde_datafd(conn), POLLIN, 0}
	};
	while (poll(pfd, sizeof(pfd)/sizeof(pfd[0]), -1) >= 0) {
		if (common_poll(pfd, stack))
			break;
		if (pfd[2].revents & POLLIN) {
			n = read(tapfd, buf, VDE_ETHBUFSIZE);
			if (n == 0) break;
			vde_send(conn, buf, n, 0);
		}
		if (pfd[3].revents & POLLIN) {
			n = vde_recv(conn, buf, VDE_ETHBUFSIZE, 0);
			if (n == 0) break;
			if ((write(tapfd, buf, n)) < 0) {
				if (errno = EIO)
					continue;
				else
					break;
			}
		}
	}
}

static ssize_t stream2tap_read(void *opaque, void *buf, size_t count) {
	int *tapfd = opaque;
	return write(*tapfd, buf, count);
}

static void stream2tap(struct vdestack *stack, int tapfd) {
	int n;
	unsigned char buf[VDE_ETHBUFSIZE];
	int *streamfd = stack->conn.streamfd;
	struct pollfd pfd[] = {COMMON_POLLFD(stack),
		{tapfd, POLLIN, 0}, 
		{streamfd[0], POLLIN, 0}
	};
	VDESTREAM *vdestream = vdestream_open(&tapfd, streamfd[1], stream2tap_read, NULL);
	while (poll(pfd, sizeof(pfd)/sizeof(pfd[0]), -1) >= 0) {
		if (common_poll(pfd, stack))
			break;
		if (pfd[2].revents & POLLIN) {
			n = read(tapfd, buf, VDE_ETHBUFSIZE);
			if (n == 0) break;
			vdestream_send(vdestream, buf, n);
		}
		if (pfd[3].revents & POLLIN) {
			n = read(streamfd[0], buf, VDE_ETHBUFSIZE);
			if (n == 0) break;
			vdestream_recv(vdestream, buf, n);
		}
	}
	vdestream_close(vdestream);
}

static void resetHandlers(void) {
	int sig;
	for (sig = 0; sig < _NSIG; sig++)
		signal(sig, SIG_DFL);
}

static int childFunc(void *arg)
{
	struct vdestack *stack = arg;
	int tapfd;
	sigset_t chldmask;

	resetHandlers();

	sigemptyset(&chldmask);
	sigaddset(&chldmask, SIGCHLD);
	sigaddset(&chldmask, SIGHUP);
	sigprocmask(SIG_BLOCK, &chldmask, NULL);
	stack->sfd = signalfd(-1, &chldmask, SFD_CLOEXEC);
	prctl(PR_SET_PDEATHSIG, SIGHUP, 0, 0, 0);

	/* printf("starting stack tid %d\n", stack->pid); */

	switch (stack->conntype) {
		case CONNTYPE_NONE:
			notap(stack);
			break;
		case CONNTYPE_VDE:
			if ((tapfd = open_tap(stack->ifname)) < 0)
				errExit("tap");
			plug2tap(stack, tapfd);
			break;
		case CONNTYPE_VDESTREAM:
			if ((tapfd = open_tap(stack->ifname)) < 0)
				errExit("tap");
			stream2tap(stack, tapfd);
			break;
		default:
			errExit("unknown conn type");
	}
	close(stack->sfd);
	close(stack->cmdpipe[DAEMONSIDE]);
	_exit(EXIT_SUCCESS);
}

/********************************* APP CODE *******************************/
struct vdestack *vde_addstack(char *vdenet, char *ifname) {
	char *ifnameok = ifname ? ifname : DEFAULT_IF_NAME;
	size_t ifnameoklen = strlen(ifnameok);
	struct vdestack *stack = malloc(sizeof(*stack) + ifnameoklen + 1);

	if (stack) {
		stack->child_stack = malloc(CHILD_STACK_SIZE);
		if (stack->child_stack == NULL)
			goto err_child_stack;

		if (socketpair(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC, 0, stack->cmdpipe) < 0)
			goto err_cmdpipe;
		stack->cmdpid = -1;
		stack->sfd = -1;
		strncpy(stack->ifname, ifnameok, ifnameoklen + 1);

		if (vdenet == NULL || vdenet[0] == 0)
			stack->conntype = CONNTYPE_NONE;
		else if (*vdenet == '=') {
			stack->conntype = CONNTYPE_VDESTREAM;
			if (coprocsp(vdenet+1, stack->conn.streamfd) < 0)
				goto err_vdenet;
		} else {
			stack->conntype = CONNTYPE_VDE;
			if ((stack->conn.vdeconn = vde_open(vdenet, "vdestack", NULL)) == NULL)
				goto err_vdenet;
		}

		/* start the networking deamon in a private net namespace, while
			 sharing memory and file descriptors */
		stack->pid = clone(childFunc, stack->child_stack + CHILD_STACK_SIZE,
				CLONE_VM | CLONE_FILES | CLONE_NEWUSER | CLONE_NEWNET | SIGCHLD, stack);
		if (stack->pid == -1)
			goto err_child;
		uid_gid_map(stack->pid); //is this required?
	}
	return stack;
err_child:
err_vdenet:
	close(stack->cmdpipe[APPSIDE]);
	close(stack->cmdpipe[DAEMONSIDE]);
err_cmdpipe:
	free(stack->child_stack);
err_child_stack:
	free(stack);
	return NULL;
}

void vde_default_stack(struct vdestack *stack) {
	default_stack = stack;
}

void vde_delstack(struct vdestack *stack) {
	if (stack == default_stack)
		default_stack = NULL;
	close(stack->cmdpipe[APPSIDE]);
	waitpid(stack->pid, NULL, 0);
	free(stack->child_stack);
	free(stack);
}

int vde_stack_onecmd(char **argv, void *opaquestack) {
	struct vdestack *stack = opaquestack;
	struct vdecmd cmd = {argv, 0, 0, 0};
	struct vdereply reply;

	if (write(stack->cmdpipe[APPSIDE],  &cmd, sizeof(cmd)) < 0 ||
			read(stack->cmdpipe[APPSIDE], &reply, sizeof(reply)) < 0)
		reply.rval = -1;

	return reply.rval;
}

/* parse the args, allowing multiple comma separated commands on a single line */
int vde_stackcmd(struct vdestack *stack, char *stackcmd) {
	return s2multiargv(stackcmd, vde_stack_onecmd, stack);
}

int vde_msocket(struct vdestack *stack, int domain, int type, int protocol) {
	struct vdecmd cmd = {NULL, domain, type, protocol};
	struct vdereply reply;

	if (write(stack->cmdpipe[APPSIDE],  &cmd, sizeof(cmd)) < 0 ||
			read(stack->cmdpipe[APPSIDE], &reply, sizeof(reply)) < 0)
		reply.rval = -1;

	if (reply.rval < 0) 
		errno = reply.err;
	return reply.rval;
}
