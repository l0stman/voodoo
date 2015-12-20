CC		= clang
CFLAGS		= -O0 -g -Wall -std=c99 -pedantic
#CFLAGS		= -O3 -Wall -std=c99 -pedantic -DNDEBUG
INCLUDES        = -I /usr/src/sys
TABLE_OBJS	= table_test.o table.o siphash/siphash.o utils.o err.o
SERVER_OBJS	= server.o err.o utils.o kqueue.o table.o siphash/siphash.o
CLIENT_OBJS	= client.o err.o utils.o kqueue.o cbuf.o
PROGNAMES	= server client table_test

all: $(PROGNAMES)

table_test: $(TABLE_OBJS)
	$(CC) -o $@ $(TABLE_OBJS)

server: $(SERVER_OBJS)
	$(CC) -o $@ $(SERVER_OBJS)

client: $(CLIENT_OBJS)
	$(CC) -o $@ $(CLIENT_OBJS)

siphash/siphash.o:
	cd siphash && make

.SUFFIXES: .o .c
.c.o:
	$(CC) $(CFLAGS) $(INCLUDES) -c $<

depend:
	$(CC) $(INCLUDES) -E -MM *.c > .depend

clean:
	rm -f *.o *.core *~ $(PROGNAMES)
	cd siphash && make clean

tags:
	find . -name '*.[ch]' -print | xargs etags
