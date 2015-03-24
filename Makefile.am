ACLOCAL_AMFLAGS = -Im4
AM_CFLAGS = -Wall -Wextra

lib_LTLIBRARIES = libspooky-c.la
libspooky_c_la_SOURCES = spooky-c.c
libspooky_c_la_LDFLAGS = -version-info 1:0:0

check_PROGRAMS = testspooky-c
testspooky_c_LDADD = -lrt libspooky-c.la

include_HEADERS = spooky-c.h

TESTS = testspooky-c
