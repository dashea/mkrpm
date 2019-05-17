@VALGRIND_CHECK_RULES@

TESTS = test-tagdb

check_PROGRAMS = $(TESTS)

CFLAGS += -I$(top_srcdir)/src $(CMOCKA_CFLAGS)
LDADD = $(top_builddir)/src/libmkrpm.la $(CMOCKA_LIBS)

test_tagdb_SOURCES = test-tagdb.c
test_tagdb_LDFLAGS = -Wl,--wrap=abort -Wl,--wrap=calloc -Wl,--wrap=realloc
