# libvdestack

A network namespace as a library, i.e.
Internet of Threads through Network Namespaces.

## Install libvdestack

libvdestack uses the cmake, so the standard procedure to compile and install the library is:
```
$ mkdir build
$ cd build
$ cmake ..
$ make
$ sudo make install
```

## Tutorial

By libvdestack a program can use  one  (or  even  several)
private  networking  protocol  stack(s), thus a program can be assigned
its own IP address(es), routing etc.

The header file needed to use libvdestack in your C programs is:
```
#include <libvdeplug.h>
```

The following function call creates a networking stack connected to a vxvde network.
```
struct vdestack *stack;
stack = vde_addstack("vxvde://224.1.2.3", NULL);
```

This stack has a localhost interface and virtual interface named "vde0" connected to the specified
vxvde network.

It is possible to create a socket of the vdestack in this way:
```
int sockfd = vde_msocket(stack, AF_INET6, SOCK_STREAM, 0);
```

The file descriptor returned by vde\_msocket is a standard socket descriptor, so all the functions
and system calls can be used on *sockfd* in the example as they could have been used on any other socket
opened by socket(2). In other words the single different call to use a vdestack socket instead
of a standard socket is the socket creation function: *vde_msocket* instead of *socket*.

Vdestack sockets can be inherited by fork(2). The common technique to fork a process for each
new connection descriptor returned by accept(2) can be applied to vdestack sockets, too.

It is possible to define several different stacks in a program and create sockets on each one of them
just by properly assigning the first argument of vde\_msocket. The usual networking stack is still
available using the socket(2) system call.

If required by the program:
```
vde_delstack(stack);
```
closes a stack.

It is possible to define a default stack:
```
vde_default_stack(stack);
```
The default stack will be used by any successive socket(2) call. (It is implemented by a shared library
		interposition of the *socket* interface function).

So after a user defines:
```
vde_default_stack(mystack);
```
The call:
```
fd = socket(AF_INET, SOCK_STREAM, 0);
```
is equivalent to:
```
fd = vde_msocket(mystack, AF_INET, SOCK_STREAM, 0);
```

Use
```
vde_default_stack(NULL);
```
to undefine the current default stack.

## Address/Route definition

Vdestack's virtual interfaces must be configured. IP address, netmask, routing must be properly set.

Libvdestack is a library which creates a network namespace. So a program using libvdestack is provided
with a specific instance of a kernel stack, thus all the libraries and system calls available for
the standard stack, can be used on a vdestack.

Unfortunately we have not yet found convenient libraries to set IP addresses and routes manually or by dhcp.
(Libnl and libnl-route should work, but the procedure to set addresses and routes is rather daunting).

Vde\_stackcmd runs a (configuration) command (or a sequence of comma separated configuration commands) in the
private networking namespace of a vdestack.

For example, an interface with a static ip address and a static default route can be defined as follows:
```
vde_stackcmd(stack,
        "/bin/busybox ip link set vde0 up;"
        "/bin/busybox ip addr add 10.0.0.2/24 dev vde0;"
        "/bin/busybox ip route add default via 10.0.0.254");
```

It is also possible to run a dhcp client to configure a vdestack interface:
```
vde_stackcmd(stack,
        "/bin/busybox ip link set vde0 up;"
        "/bin/busybox udhcpc -q -s /home/user/bin/dhcpscript -i vde0");
```

## A complete example:

The following source file implements a multiclient tcp echo server (using fork) running on a vdestack.
```
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <signal.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <netinet/in.h>
#include <vdestack.h>

struct vdestack *mystack;

static void getstatus(int signo) {
    int status;
    wait(&status);
}

int main(int arg, char *argv[]) {
    struct sockaddr_in servaddr, cliaddr;
    int fd, connfd;
    char buf[BUFSIZ];
    mystack = vde_addstack("vde://", NULL);
    vde_stackcmd(mystack,"/bin/busybox ip addr add 192.168.250.100/24 dev vde0;"
            "/bin/busybox ip link set vde0 up;"
            "/bin/busybox ip route add default via 192.168.250.1");
    signal(SIGCHLD, getstatus);

    fd = vde_msocket(mystack, AF_INET, SOCK_STREAM, 0);

    memset(&servaddr, 0, sizeof(servaddr));
    servaddr.sin_family = AF_INET;
    servaddr.sin_port = htons(5000);
    servaddr.sin_addr.s_addr = htonl(INADDR_ANY);

    if (bind(fd, (struct sockaddr *)&servaddr, sizeof(servaddr)) < 0)
        exit(1);

    listen (fd, 5);

    for ( ; ; ) {
        int n;
        socklen_t clilen = sizeof(cliaddr);
        connfd = accept (fd, (struct sockaddr *) &cliaddr, &clilen);

        switch (fork()) {
            case 0:
                close(fd);
                printf("new conn %d pid %d\n", connfd, getpid());
                while ( (n = recv(connfd, buf, BUFSIZ, 0)) > 0)  {
                    printf("pid %d GOT: %*.*s",getpid(),n,n,buf);
                    send(connfd, buf, n, 0);
                }
                printf("close conn %d pid %d\n", connfd, getpid());
                close(connfd);
                exit(0);
            default:
                close(connfd);
                break;
            case -1:
                exit(1);
        }
    }
    close(fd);
    vde_delstack(mystack);
}
```
