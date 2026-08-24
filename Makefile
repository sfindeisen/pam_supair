# pam_supair build

CC          ?= cc
CPPFLAGS    ?= -D_POSIX_C_SOURCE=200809L
CFLAGS      ?= -std=c11 -Wall -Wextra -O2
LDLIBS      ?= -lpam

# PAM module install directory (multiarch-aware default; override as needed,
# e.g. `make install SECURITYDIR=/usr/lib/x86_64-linux-gnu/security`).
MULTIARCH   ?= $(shell $(CC) -dumpmachine)
SECURITYDIR ?= /lib/$(MULTIARCH)/security
DESTDIR     ?=

MODULE = pam_supair.so
TEST   = test_supair

.PHONY: all install clean test

all: $(MODULE)

$(MODULE): pam_supair.c
	$(CC) $(CPPFLAGS) $(CFLAGS) -fPIC -shared -o $@ $< $(LDLIBS)

test: $(TEST)
	./$(TEST)

$(TEST): test_supair.c pam_supair.c
	$(CC) $(CPPFLAGS) $(CFLAGS) -o $@ test_supair.c

install: all
	install -d $(DESTDIR)$(SECURITYDIR)
	install -m 0644 $(MODULE) $(DESTDIR)$(SECURITYDIR)

clean:
	rm -f $(MODULE) $(TEST)
