## Process this file with automake to produce Makefile.in
## Created by Anjuta

SUBDIRS = src po

dumbado_noguidocdir = ${prefix}/doc/dumbado_nogui
dumbado_noguidoc_DATA = \
	README\
	COPYING\
	AUTHORS\
	ChangeLog\
	INSTALL\
	NEWS

AM_CFLAGS =\
	 -Wall\
	 -g\
	 -lpcap

INTLTOOL_FILES = intltool-extract.in \
	intltool-merge.in \
	intltool-update.in

EXTRA_DIST = $(dumbado_noguidoc_DATA) \
	$(INTLTOOL_FILES)

DISTCLEANFILES = intltool-extract \
	intltool-merge \
	intltool-update \
	po/.intltool-merge-cache


# Remove doc directory on uninstall
uninstall-local:
	-rm -r $(dumbado_noguidocdir)
