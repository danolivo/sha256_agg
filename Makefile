# contrib/sha256_agg/Makefile

MODULE_big = sha256_agg
OBJS = \
	$(WIN32RES) \
	sha256_agg.o \
	sha256_impl.o

EXTENSION = sha256_agg
DATA = sha256_agg--1.0.sql
PGFILEDESC = "sha256_agg - ordered SHA-256 aggregate over table rows"

REGRESS = sha256_agg

EXTRA_CLEAN = test/sha256_selftest test/sha256_selftest_x86emu

ifdef USE_PGXS
PG_CONFIG = pg_config
PGXS := $(shell $(PG_CONFIG) --pgxs)
include $(PGXS)
else
subdir = contrib/sha256_agg
top_builddir = ../..
include $(top_builddir)/src/Makefile.global
include $(top_srcdir)/contrib/contrib-global.mk
endif

# The block kernels are the hot loop; keep them optimised even in -O0
# developer builds of the server (-O2 must come last on the command line).
sha256_impl.o: sha256_impl.c sha256_impl.h
	$(CC) $(CFLAGS) $(CPPFLAGS) -O2 -c -o $@ $<

# Standalone check of the SHA-256 kernels (no server needed).  The second
# binary runs the x86 SHA-NI kernel on top of a portable emulation of the
# intrinsics, so it can be checked on any host.
selftest: test/sha256_selftest.c sha256_impl.c sha256_impl.h
	$(CC) -O2 -I. -o test/sha256_selftest test/sha256_selftest.c sha256_impl.c
	./test/sha256_selftest
	$(CC) -O1 -DSHA256_X86_EMULATE -I. -o test/sha256_selftest_x86emu test/sha256_selftest.c sha256_impl.c
	./test/sha256_selftest_x86emu

.PHONY: selftest
