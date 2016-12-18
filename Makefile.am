lib_LTLIBRARIES = libvdestack.la
man_MANS = libvdestack.3
include_HEADERS = vdestack.h

AM_CFLAGS = -Wall -O2 -I.

libvdestack_la_SOURCES = vdestack.c

libvdestack_la_LIBADD = -lcap -lexecs -lvdeplug

libvdestack_la_LDFLAGS = -version-number 0:1:0

install-data-hook:
	ln -sf libvdestack.3 $(DESTDIR)$(man3dir)/vde_addstack.3
	ln -sf libvdestack.3 $(DESTDIR)$(man3dir)/vde_delstack.3
	ln -sf libvdestack.3 $(DESTDIR)$(man3dir)/vde_stackcmd.3
	ln -sf libvdestack.3 $(DESTDIR)$(man3dir)/vde_msocket.3

uninstall-hook:
	rm -f $(DESTDIR)$(man3dir)/vde_addstack.3
	rm -f $(DESTDIR)$(man3dir)/vde_delstack.3
	rm -f $(DESTDIR)$(man3dir)/vde_stackcmd.3
	rm -f $(DESTDIR)$(man3dir)/vde_msocket.3
