.PHONY: all install clean test

all: pam_supair.c
	gcc -Wall -fPIC -c pam_supair.c
	gcc -Wall -shared -o pam_supair.so pam_supair.o -lpam

test: test_supair
	./test_supair

test_supair: test_supair.c pam_supair.c
	gcc -Wall -Wextra -o test_supair test_supair.c

install: all
	cp -v pam_supair.so /lib/x86_64-linux-gnu/security/

clean:
	rm pam_supair.so
	rm pam_supair.o
