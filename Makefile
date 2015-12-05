# Thisis Makefile. Does make.
CC = gcc

LIBS = -lm -lpthread\
	/home/courses/cse533/Stevens/unpv13e/libunp.a\

FLAGS = -g -O2

CFLAGS = ${FLAGS} -I/home/courses/cse533/Stevens/unpv13e/lib

all: arp tour

arp: arp.o get_hw_addrs.o prhwaddrs.o
	${CC} ${FLAGS} -o arp arp.o get_hw_addrs.o prhwaddrs.o ${LIBS}
arp.o: arp.c
	${CC} ${CFLAGS} -c arp.c 
get_hw_addrs.o: get_hw_addrs.c
	${CC} ${CFLAGS} -c get_hw_addrs.c
prhwaddrs.o: prhwaddrs.c
	${CC} ${CFLAGS} -c prhwaddrs.c

tour: tour.o get_hw_addrs.o prhwaddrs.o
	${CC} ${FLAGS} -o tour tour.o get_hw_addrs.o prhwaddrs.o ${LIBS}
tour.o: tour.c
	${CC} ${CFLAGS} -c tour.c 

# pick up the thread-safe version of readline.c from directory "threads"

clean:
	rm arp tour arp.o tour.o prhwaddrs.o get_hw_addrs.o

