# libvdestack

A network namespace as a library, i.e.
Internet of Threads through Network Namespaces.

## Install libvdestack

libvdestack uses the auto-tools, so the standard procedure to compile and install the library is:
```
$ autoreconf -if
$ ./configure
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


