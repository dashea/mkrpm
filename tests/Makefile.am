@VALGRIND_CHECK_RULES@

TESTS = test-metadata \
	test-output \
	test-tagdb

check_PROGRAMS = $(TESTS)

CFLAGS += -I$(top_srcdir)/src $(CMOCKA_CFLAGS)
LDADD = $(top_builddir)/src/libmkrpm.la $(CMOCKA_LIBS)

test_tagdb_SOURCES = test-tagdb.c
test_tagdb_LDFLAGS = -Wl,--wrap=abort -Wl,--wrap=calloc -Wl,--wrap=realloc

test_metadata_SOURCES = test-metadata.c
test_metadata_LDFLAGS = -Wl,--wrap=getpwuid -Wl,--wrap=getgrgid -Wl,--wrap=add_tag

test_output_SOURCES = test-output.c
test_output_LDFLAGS = -Wl,--wrap=fwrite
