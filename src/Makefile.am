bin_PROGRAMS = mkrpm

noinst_LTLIBRARIES = libmkrpm.la

libmkrpm_la_SOURCES = rpmtypes.h \
		      tagdb.c \
		      tagdb.h

mkrpm_SOURCES = mkrpm.c
mkrpm_LDADD = libmkrpm.la
