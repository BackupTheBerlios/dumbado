## Process this file with automake to produce Makefile.in
## Created by Anjuta

SUBDIRS = src po

dumbadodocdir = ${prefix}/doc/dumbado
dumbadodoc_DATA = \
	README\
	COPYING\
	AUTHORS\
	ChangeLog\
	INSTALL\
	NEWS


INTLTOOL_FILES = intltool-extract.in \
	intltool-merge.in \
	intltool-update.in

EXTRA_DIST = $(dumbadodoc_DATA) \
	$(INTLTOOL_FILES)

DISTCLEANFILES = intltool-extract \
	intltool-merge \
	intltool-update \
	po/.intltool-merge-cache

AM_CFLAGS = 


AM_CPPFLAGS = 

INCLUDES = 

AM_CXXFLAGS = 

# Remove doc directory on uninstall
uninstall-local:
	-rm -r $(dumbadodocdir)
