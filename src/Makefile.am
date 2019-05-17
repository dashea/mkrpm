include $(top_srcdir)/aminclude_static.am

bin_PROGRAMS = mkrpm

noinst_LTLIBRARIES = libmkrpm.la

libmkrpm_la_SOURCES = rpmtypes.h \
		      tagdb.c \
		      tagdb.h
libmkrpm_la_CPPFLAGS = $(CODE_COVERAGE_CPPFLAGS)
libmkrpm_la_CFLAGS = $(CODE_COVERAGE_CFLAGS)
libmkrpm_la_LIBADD = $(CODE_COVERAGE_LIBS)

mkrpm_SOURCES = mkrpm.c
mkrpm_LDADD = libmkrpm.la

clean-local: code-coverage-clean
distclean-local: code-coverage-dist-clean
