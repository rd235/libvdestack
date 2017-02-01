#ifndef VDESTACK_H
#define VDESTACK_H

struct vdestack;

struct vdestack *vde_addstack(char *vdenet, char *ifname);

void vde_delstack(struct vdestack *stack);

void vde_default_stack(struct vdestack *stack);

int vde_stackcmd(struct vdestack *stack, char *stackcmd);

int vde_msocket(struct vdestack *stack, int domain, int type, int protocol);

#endif
