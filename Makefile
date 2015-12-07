# Thisis Makefile. Does make.
CC = gcc

LIBS = -lm -lpthread\
	/home/courses/cse533/Stevens/unpv13e/libunp.a\

FLAGS = -g -O2

CFLAGS = ${FLAGS} -I/home/courses/cse533/Stevens/unpv13e/lib

all: arp_nnigar tour_nnigar

arp_nnigar: arp.o get_hw_addrs.o prhwaddrs.o
	${CC} ${FLAGS} -o arp_nnigar arp.o get_hw_addrs.o prhwaddrs.o ${LIBS}
arp.o: arp.c
	${CC} ${CFLAGS} -c arp.c 
get_hw_addrs.o: get_hw_addrs.c
	${CC} ${CFLAGS} -c get_hw_addrs.c
prhwaddrs.o: prhwaddrs.c
	${CC} ${CFLAGS} -c prhwaddrs.c

tour_nnigar: tour.o get_hw_addrs.o prhwaddrs.o
	${CC} ${FLAGS} -o tour_nnigar tour.o get_hw_addrs.o prhwaddrs.o ${LIBS}
tour.o: tour.c
	${CC} ${CFLAGS} -c tour.c 

# pick up the thread-safe version of readline.c from directory "threads"

clean:
	rm arp_nnigar tour_nnigar arp.o tour.o prhwaddrs.o get_hw_addrs.o

