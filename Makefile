.PHONY: all

all: pam_supair.c
	gcc -Wall -fPIC -c pam_supair.c
	gcc -Wall -shared -o pam_supair.so pam_supair.o -lpam

.PHONY: clean

clean:
	rm pam_supair.so
	rm pam_supair.o
