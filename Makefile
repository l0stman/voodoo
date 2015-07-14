CC		= clang
CFLAGS		= -O0 -g -Wall -std=c99 -pedantic
#CFLAGS		= -O3 -Wall -std=c99 -pedantic -DNDEBUG
SERVER_OBJS	= server.o err.o utils.o kqueue.o
CLIENT_OBJS	= client.o err.o utils.o kqueue.o cbuf.o
PROGNAMES	= server client

all: $(PROGNAMES)
server: $(SERVER_OBJS)
	$(CC) -o $@ $(SERVER_OBJS)

client: $(CLIENT_OBJS)
	$(CC) -o $@ $(CLIENT_OBJS)

.SUFFIXES: .o .c
.c.o:
	$(CC) $(CFLAGS) -c $<

depend:
	$(CC) -E -MM *.c > .depend

clean:
	rm -f *.o *.core *~ $(PROGNAMES)

tags:
	find . -name '*.[ch]' -print | xargs etags
