## Process this file with automake to produce Makefile.in

## Created by Anjuta

##uidir = $(datadir)/dumbado/ui
##ui_DATA = dumbado.ui

AM_CPPFLAGS = \
	-DPACKAGE_LOCALE_DIR=\""$(prefix)/$(DATADIRNAME)/locale"\" \
	-DPACKAGE_SRC_DIR=\""$(srcdir)"\" \
	-DPACKAGE_DATA_DIR=\""$(datadir)"\" \
	$(DUMBADO_CFLAGS)

AM_CFLAGS =\
	 -Wall\
	 -g\
	 -lpcap

bin_PROGRAMS = dumbado

dumbado_SOURCES = \
	callbacks.c \
	callbacks.h \
	main.c \
	dumbado.glade

dumbado_LDFLAGS = \
	-Wl,--export-dynamic

dumbado_LDADD = $(DUMBADO_LIBS)

##EXTRA_DIST = $(ui_DATA)

# Remove ui directory on uninstall
uninstall-local:
##	-rm -r $(uidir)
	-rm -r $(datadir)/dumbado
