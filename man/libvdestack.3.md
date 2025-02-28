<!--
.\" Copyright (C) 2019 VirtualSquare. Project Leader: Renzo Davoli
.\"
.\" This is free documentation; you can redistribute it and/or
.\" modify it under the terms of the GNU General Public License,
.\" as published by the Free Software Foundation, either version 2
.\" of the License, or (at your option) any later version.
.\"
.\" The GNU General Public License's references to "object code"
.\" and "executables" are to be interpreted as the output of any
.\" document formatting or typesetting system, including
.\" intermediate and printed output.
.\"
.\" This manual is distributed in the hope that it will be useful,
.\" but WITHOUT ANY WARRANTY; without even the implied warranty of
.\" MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
.\" GNU General Public License for more details.
.\"
.\" You should have received a copy of the GNU General Public
.\" License along with this manual; if not, write to the Free
.\" Software Foundation, Inc., 51 Franklin St, Fifth Floor, Boston,
.\" MA 02110-1301 USA.
.\"
-->

# NAME

vde_addstack, vde_delstack, vde_stackcmd, vde_msocket - vde network namespace as a user library

# SYNOPSIS

`#include <vdestack.h>`

`struct vdestack *vde_addstack(char *`_vdenet_`, char *`_ifname_`);`

`void vde_delstack(struct vdestack *`_stack_`);`

`int vde_stackcmd(struct vdestack *`_stack_`, char *`_stackcmd_`);`

`int vde_msocket(struct vdestack *`_stack_`,int ` _domain_`, int ` _type_`, int ` _protocol_`);`

`void vde_default_stack(struct vdestack *`_stack_`);`

# DESCRIPTION

Libvdestack  implements the idea of Internet of Threads through network namespaces.  By libvdestack a program can use one
(or even several) private networking protocol stack(s), thus a program can be assigned its own  IP  address(es),  routing
etc.

  `vde_addstack`
: create  a private network namespace: _vdenet_ is the URL-like specification of a vde network as described in
:`vde_plug`(1). _ifname_ is the name of the interface in the network namespace. When _ifname_ is  NULL,  the  default  interface
:name is vde0.

  `vde_delstack`
: destroy a vdestack when it is no longer needed.

  `vde_stackcmd`
: run  a  command or a comma separated sequence of commands in the private network namespace.  The purpose of
: this function is to configure the networking parameters and options (e.g. IP address, routing).   For  security  reasons,
: commands must be specified using full pathnames. Do not use this function to start long lasting or non terminating programs,
: the caller waits for the termination of the command sequence.

  `vde_msocket`
: it has  the same semantics of `socket`(2) except that the socket is defined in the scope of the network namespace
: whose descriptor is the first argument. The remaining arguments are those defined in socket(2).

  `vde_default_stack`
: define  the  default  stack:  any successive socket(2) call will use the stack passed as parameter to
:  vde_default_stack. Use NULL to undefine the default stack.

# RETURN VALUE

`vde_addstack` returns a struct vdestack pointer which is used as a descriptor and thus passed as an argument to the  other
functions of this library. NULL is returned in case of error.

`vde_stackcmd`  returns the exit status of the command. If the stackcmd argument is a comma separated sequence of commands,
the execution terminates upon the first command whose exit status is not zero, and the exit status of that command is 
returned. Therefore when vde_stackcmd returns zero the entire sequence was successfully executed.

On success, `vde_msocket` returns a valid file descriptor. -1 is returned elseways and errno is set appropriately as described in socket(2).

# NOTES

Libvdestack fails if user namespaces have not been configured in the running kernel and enabled for users.  In Debian the
sysctl knob `kernel.unprivileged_userns_clone` must be set to 1.

# EXAMPLE

The following excerpt of C code shows the use of libvdestack:

```C
...
int fd;
int exit_status;
struct vdestack *stack = vde_addstack("vde://", NULL);
if (stack == NULL)
    ... error management
exit_status = vde_stackcmd(stack,
          "/bin/ip link set vde0 up;"
          "/bin/ip addr add 10.0.0.1/24 dev vde0;"
          "/bin/ip route add default via 10.0.0.254");
if (exit_status != 0)
   ... error management
fd = vde_msocket(stack, AF_INET, SOCK_STREAM, 0);
   ... fd can be used in any context in which a file descriptor returned by socket(2) can.
e.g. bind, accept, connect, read/write, send/recv ...
vde_delstack(stack);
```

# SEE ALSO

`socket`(2), `vde_plug`(1)

# BUGS

Bug reports should be addressed to *info@virtualsquare.org*

# AUTHOR
VirtualSquare. Project leader: Renzo Davoli.
