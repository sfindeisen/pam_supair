.PHONY: all install clean

all: pam_supair.c
	gcc -Wall -fPIC -c pam_supair.c
	gcc -Wall -shared -o pam_supair.so pam_supair.o -lpam

install: all
	cp -v pam_supair.so /lib/x86_64-linux-gnu/security/

clean:
	rm pam_supair.so
	rm pam_supair.o
