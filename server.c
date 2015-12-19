#include <netinet/in.h>
#include <sys/queue.h>

#include <assert.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <strings.h>
#include <unistd.h>

#include "err.h"
#include "kqueue.h"
#include "table.h"
#include "utils.h"

#define CMDMAXSIZE      1024 /* Maximum size (with CRLF) of a single command */
#define NELEMS(x)	((sizeof(x))/(sizeof((x)[0])))
#define CRLF            "\x0d\x0a"

STAILQ_HEAD(queue, msg);
struct msg {
        const char      *bytes;
        size_t          len;
        unsigned int    refcnt;
        STAILQ_ENTRY(msg) msgs;
};

static struct queue *
queue(void)
{
        struct queue *q;

        q = malloc_or_die(sizeof(*q));
        STAILQ_INIT(q);
        return (q);
}

static inline void
free_queue(struct queue *q)
{
        free(q);
}

static struct msg *
msg(const char *bytes, size_t len)
{
        struct msg *m;

        m = malloc_or_die(sizeof(*m));
        m->bytes = bytes;
        m->len = len;
        m->refcnt = 0;
        return (m);
}

static inline void
free_msg(struct msg *m)
{
        free(m);
}

#define ERROR_ENTRIES                                                   \
        X(UEMPTY, "username is empty")                                  \
        X(UILLEGAL, "username contains illegal character")              \
        X(ULOGGED, "already logged in")                                 \
        X(UUSED, "username is already being used")                      \
        X(UNEXIST, "user doesn't exist")                                \
        X(CUNKNOWN, "unknown command")                                  \
        X(CTOOLONG, "command exceeds maximum length")                   \
        X(CNLOGGED, "not logged in")                                    \
        X(CJUNK, "there's trailing junk after command")                 \
        X(CHEMTPY, "channel name is empty")                             \
        X(CHILLEGAL, "channel name contains illegal character")         \
        X(CHSHARP, "channel name should start with #")                  \
        X(CHJOINED, "already joined the channel")                       \
        X(CHNJOINED, "haven't joined the channel")                      \
        X(MNORECIP, "message recipient is empty")                       \
        X(MNOSPACE, "absence of space after recipient's name")

#define X(a, b)	a,
enum error { ERROR_ENTRIES };
#undef X

#define M(m)    "ERROR " m CRLF
#define X(a, b) { M(b), sizeof(M(b))-1 },
struct {
        const char      *str;
        const size_t    len;
} error_msg[] = { ERROR_ENTRIES };
#undef M
#undef X

SLIST_HEAD(list_head, list);
struct list {
        const void              *elt;
        SLIST_ENTRY(list)       next;
};

static struct list *
list(const void *elt)
{
        struct list *lp;

        lp = malloc_or_die(sizeof(*lp));
        lp->elt = elt;
        return (lp);
}

#define LIST_FOREACH_ELT(var, head, ELT_TYPE, elt_var)                  \
        for ((var) = SLIST_FIRST((head));                               \
             (var) && ((elt_var) = ((ELT_TYPE *)((var)->elt)), 1);      \
             (var) = SLIST_NEXT((var), next))                           \

static void
free_list(struct list *lp)
{
        free(lp);
}

static void
list_remove(void *elt, struct list_head *head)
{
        struct list *cont, *lp;

        lp = SLIST_FIRST(head);
        if (lp->elt == elt) {
                cont = lp;
                SLIST_FIRST(head) = SLIST_NEXT(lp, next);
        } else {
                while (SLIST_NEXT(lp, next)->elt != elt)
                        lp = SLIST_NEXT(lp, next);
                cont = SLIST_NEXT(lp, next);
                SLIST_NEXT(lp, next) = SLIST_NEXT(cont, next);
        }
        free_list(cont);
}

struct user {
        char            *name;
        size_t          namelen;
        int             connfd;
        struct queue    *msg_queue;
        size_t          msg_offset;
        char            *cmdbuf;
        size_t          cmdlen;
        unsigned        write_enabled:1;
        unsigned        connected:1;
        unsigned        skip_curr_cmd:1;
        struct list_head channels;
};

static struct table *users;
static struct user *client;

struct channel {
        const char              *name;
        size_t                  len;
        struct list_head        users;
};

static struct table *channels;

struct channel *
channel(const char *name, size_t len)
{
        struct channel *c;

        c = malloc_or_die(sizeof(*c));
        c->name = name;
        c->len = len;
        SLIST_INIT(&(c->users));
        return (c);
}

struct channel *
chancpy(const char *name, size_t len)
{
        struct channel *c;

        c = malloc_or_die(sizeof(*c) + len);
        bcopy(name, c+1, len);
        c->name = (char *)(c+1);
        c->len = len;
        SLIST_INIT(&(c->users));
        return (c);
}

void
free_channel(struct channel *c)
{
        free(c);
}

static void
writeto(struct user *u, struct msg *m, int kq)
{

        m->refcnt++;
        STAILQ_INSERT_TAIL(u->msg_queue, m, msgs);
        if (!u->write_enabled) {
                struct kevent change;
                EV_SET(&change, u->connfd, EVFILT_WRITE,  EV_ENABLE, 0, 0, NULL);
                kevent_or_die(kq, &change, 1, NULL, 0, NULL);
                u->write_enabled = 1;
        }
}

static inline void
perror_to(struct user *u, enum error err, int kq)
{

        writeto(u, msg(error_msg[err].str, error_msg[err].len), kq);
}

static inline void
ok(struct user *u, int kq)
{
        static const char s[] = "OK" CRLF;
        writeto(u, msg(s, 4), kq);
}

static int
verify_name(const char *bytes, size_t len, struct user *user, int kq,
            enum error empty, enum error illegal)
{

        if (len == 0) {
                perror_to(user, empty, kq);
                return (1);
        }
        for (int i = 0; i < len; i++)
                if (bytes[i] == ' ') {
                        perror_to(user, illegal, kq);
                        return (1);
                }
        return (0);
}

static void
parse_login(const char *bytes, size_t len, struct user *user, int kq)
{

        if (verify_name(bytes, len, user, kq, UEMPTY, UILLEGAL))
                return;
        if (user->name != NULL) {
                perror_to(user, ULOGGED, kq);
                return;
        }
        if (table_get(users, bytes, len)) {
                perror_to(user, UUSED, kq);
                return;
        }
        user->name = malloc_or_die(len);
        bcopy(bytes, user->name, len);
        user->namelen = len;
        table_put(users, user->name, user->namelen, user);
        ok(user, kq);
}

static void
parse_join(const char *bytes, size_t len, struct user *user, int kq)
{
        struct channel *c;
        struct list *lp;
        struct user *u;

        if (verify_name(bytes, len, user, kq, CHEMTPY, CHILLEGAL))
                return;
        if (*bytes != '#') {
                perror_to(user, CHSHARP, kq);
                return;
        }
        if ((c = table_get(channels, bytes, len)) == NULL) {
                c = chancpy(bytes, len);
                table_put(channels, c->name, c->len, c);
        }
        LIST_FOREACH_ELT(lp, &(c->users), struct user, u)
                if (bequal(user->name, user->namelen, u->name, u->namelen)) {
                        perror_to(user, CHJOINED, kq);
                        return;
                }

        lp = list(c);
        SLIST_INSERT_HEAD(&(user->channels), lp, next);
        lp = list(user);
        SLIST_INSERT_HEAD(&(c->users), lp, next);
        ok(user, kq);
}

static void
rmuser(struct user *usr, struct channel *chan)
{

        list_remove(usr, &chan->users);
        if (SLIST_EMPTY(&(chan->users))) {
                table_del(channels, chan->name, chan->len);
                free_channel(chan);
        }
}

static void
parse_part(const char *bytes, size_t len, struct user *user, int kq)
{
        struct channel *c;
        struct list *lp;

        if (verify_name(bytes, len, user, kq, CHEMTPY, CHILLEGAL))
                return;
        if (*bytes != '#') {
                perror_to(user, CHSHARP, kq);
                return;
        }
        LIST_FOREACH_ELT(lp, &(user->channels), struct channel, c)
                if (bequal(c->name, c->len, bytes, len))
                        break;

        if (lp == NULL) {
                perror_to(user, CHNJOINED, kq);
                return;
        }
        rmuser(user, c);
        list_remove(c, &user->channels);
        ok(user, kq);
}

static void
parse_msg(const char *bytes, size_t len, struct user *user, int kq)
{
        static char chanhdr[] = "GOTROOMMSG ";
        static char usrhdr[] = "GOTUSERMSG ";
        static size_t ftrlen = sizeof(CRLF)-1;
        struct user *u;
        struct msg *m;
        size_t offset, hlen, rlen, size;
        char *buf, *hdr;

        if (len == 0) {
                perror_to(user, MNORECIP, kq);
                return;
        }
        for (rlen = 0; rlen < len; rlen++)
                if (bytes[rlen] == ' ')
                        break;
        if (rlen == len) {
                perror_to(user, MNOSPACE, kq);
                return;
        }
        if (bytes[0] == '#') {
                hdr = chanhdr;
                hlen = sizeof(chanhdr)-1;
                offset = 0;
        } else {
                hdr = usrhdr;
                hlen = sizeof(usrhdr)-1;
                offset = rlen+1;
        }
        size = hlen + (user->namelen+1) + (len-offset) + ftrlen;
        m = malloc_or_die(sizeof(*m) + size);
        buf = (char *)(m+1);
        bcopy(hdr, buf, hlen);
        buf += hlen;
        bcopy(user->name, buf, user->namelen);
        buf += user->namelen;
        *buf++ = ' ';
        bcopy(bytes+offset, buf, len-offset);
        bcopy(CRLF, buf+len-offset, ftrlen);
        m->bytes = (char *)(m+1);
        m->len = size;
        m->refcnt = 0;
        if (bytes[0] == '#') {
                struct channel *c;
                struct list *cp, *up;

                LIST_FOREACH_ELT(cp, &(user->channels), struct channel, c) {
                        if (bequal(c->name, c->len, bytes, rlen)) {
                                LIST_FOREACH_ELT(up, &(c->users), struct user, u)
                                        writeto(u, m, kq);
                                break;
                        }
                }
                if (cp == NULL) {
                        perror_to(user, CHNJOINED, kq);
                        free_msg(m);
                        return;
                }
        } else if ((u = table_get(users, bytes, rlen)) == NULL) {
                        perror_to(user, UNEXIST, kq);
                        free_msg(m);
                        return;
                }
        else
                writeto(u, m, kq);
        ok(user, kq);
}

static void cleanup_conn(struct user *);

static void
parse_logout(const char *bytes, size_t len, struct user *user, int kq)
{
        if (len > 0) {
                perror_to(user, CJUNK, kq);
                return;
        }
        cleanup_conn(user);
}

#define X(a, b) { a, sizeof(a)-1, b }
struct {
        const char              *name;
        const unsigned short    namelen;
        void (*parse)(const char *, size_t, struct user *, int);
} chatcmd[] = {
        X("LOGIN", parse_login),
        X("JOIN", parse_join),
        X("PART", parse_part),
        X("MSG", parse_msg),
        X("LOGOUT", parse_logout)
};
#undef X

/* Parse the command pointed by "bytes". CRLF has already been dropped. */
static void
parsecmd(const char *bytes, size_t len, struct user *user, int kq)
{
        const char *p, *end;
        size_t clen;

        for (p = bytes, end = bytes+len; *p != ' ' && p < end; p++)
                ;
        clen = p-bytes;
        for (int i = 0; i < NELEMS(chatcmd); i++)
                if (bequal(bytes, clen, chatcmd[i].name, chatcmd[i].namelen)) {
                        if (user->name == NULL &&
                            !bequal("LOGIN", 5, bytes, clen) &&
                            !bequal("LOGOUT", 6, bytes, clen)) {
                                perror_to(user, CNLOGGED, kq);
                                return;
                        }
                        if (p < end)
                                chatcmd[i].parse(p+1, end-p-1, user, kq);
                        else
                                chatcmd[i].parse(p, 0, user, kq);
                        return;
                }
        perror_to(user, CUNKNOWN, kq);
}

static void
accept_conn(int listenfd, int kq, struct user *client)
{
        struct kevent changelist[2];
        int connfd;

        if ((connfd = accept(listenfd, NULL, NULL)) == -1) {
                if (errno == ECONNABORTED || errno == EMFILE || errno == ENFILE)
                        return;
                err_sys("accept");
        }
        setnblock_or_die(connfd);
        EV_SET(changelist, connfd, EVFILT_WRITE, EV_ADD | EV_DISABLE, 0, 0, NULL);
        EV_SET(changelist+1, connfd, EVFILT_READ, EV_ADD, 0, 0, NULL);
        kevent_or_die(kq, changelist, 2, NULL, 0, NULL);
        bzero(client+connfd, sizeof(*client));
        client[connfd].connfd = connfd;
        client[connfd].msg_queue = queue();
        client[connfd].connected = 1;
        SLIST_INIT(&(client[connfd].channels));
}

static void
cleanup_conn(struct user *user)
{
        struct list *tmp, *lp;
        struct msg *m;

        while (!STAILQ_EMPTY(user->msg_queue)) {
                m = STAILQ_FIRST(user->msg_queue);
                STAILQ_REMOVE_HEAD(user->msg_queue , msgs);
                if (--m->refcnt == 0)
                        free_msg(m);

        }
        free_queue(user->msg_queue);
        if (user->name) {
                table_del(users, user->name, user->namelen);
                free(user->name);
        }
        if (user->cmdbuf)
                free(user->cmdbuf);
        SLIST_FOREACH_SAFE(lp, &(user->channels), next, tmp) {
                rmuser(user, (struct channel *)lp->elt);
                free_list(lp);
        }
        close(user->connfd);
        bzero(user, sizeof(*user));
}

static void
sendmsgs(int kq, struct kevent *ke, struct user *user)
{
        struct msg *m;
        size_t rem_space;

        rem_space = ke->data;
        while (rem_space > 0 && !STAILQ_EMPTY(user->msg_queue)) {
                size_t len;
                m = STAILQ_FIRST(user->msg_queue);
                len = m->len - user->msg_offset;
                if (len <= rem_space) {
                        rem_space -= len;
                        write(ke->ident, m->bytes+user->msg_offset, len);
                        user->msg_offset = 0;
                        STAILQ_REMOVE_HEAD(user->msg_queue, msgs);
                        if (--m->refcnt == 0) {
                                free_msg(m);
                        }
                } else {
                        write(ke->ident, m->bytes+user->msg_offset, rem_space);
                        user->msg_offset += rem_space;
                        break;
                }
        }

        if (STAILQ_EMPTY(user->msg_queue)) {
                struct kevent change;
                EV_SET(&change, ke->ident, EVFILT_WRITE, EV_DISABLE, 0, 0, NULL);
                kevent_or_die(kq, &change, 1, NULL, 0, NULL);
                user->write_enabled = 0;
        }
}

/*
 * Return the position after the first occurrence of CRLF in "bytes"
 * or -1 if there's no such occurrence.
 */
static inline
int crlf_pos(const char *bytes, ssize_t len)
{
        for (int i = 1; i < len; i++)
                if (bytes[i-1] == '\r' && bytes[i] == '\n')
                        return i+1;
        return -1;
}

static void
savecmd(int kq, struct user *usr, const char *cmd, ssize_t len, size_t size)
{
        if (usr->cmdlen+len < size) {
                if (usr->cmdbuf == NULL) {
                        usr->cmdbuf = malloc_or_die(size-1);
                        usr->cmdlen = 0;
                }
                bcopy(cmd, usr->cmdbuf+usr->cmdlen, len);
                usr->cmdlen += len;
        } else {
                perror_to(usr, CTOOLONG, kq);
                usr->cmdlen = 0;
                usr->skip_curr_cmd = 1;
        }
}

static void
recvcmds(int kq, struct kevent *ke, struct user *user)
{
        static char cmd[CMDMAXSIZE];
        ssize_t offset, nbytes, nread;
        int pos;

        for (nbytes = 0; nbytes < ke->data; nbytes += nread) {
                nread = read(ke->ident, cmd, NELEMS(cmd));
                offset = 0;

                if (user->cmdlen > 0) {
                        /* There's an incomplete command missing CRLF. */
                        if (user->cmdbuf[user->cmdlen-1] == '\r' &&
                            cmd[0] == '\n') {
                                parsecmd(user->cmdbuf, user->cmdlen-1, user, kq);
                                user->cmdlen = 0;
                                offset++;
                        } else if ((pos = crlf_pos(cmd, nread)) != -1) {
                                if (user->cmdlen+pos > NELEMS(cmd))
                                        perror_to(user, CTOOLONG, kq);
                                else {
                                        /* Drop CRLF from the command. */
                                        bcopy(cmd, user->cmdbuf + user->cmdlen,
                                              pos-2);
                                        parsecmd(user->cmdbuf, user->cmdlen+pos-2,
                                                 user, kq);
                                }
                                user->cmdlen = 0;
                                offset = pos;
                        } else {
                                savecmd(kq, user, cmd, nread, NELEMS(cmd));
                                continue;
                        }
                }
                while (offset < nread) {
                        if ((pos = crlf_pos(cmd+offset, nread)) == -1) {
                                if (!user->skip_curr_cmd)
                                        savecmd(kq, user, cmd+offset,
                                                nread-offset, NELEMS(cmd));
                                break;
                        }
                        if (!user->skip_curr_cmd)
                                parsecmd(cmd+offset, pos-2, user, kq);
                        else
                                user->skip_curr_cmd = 0;
                        offset += pos;
                }
        }

        if ((ke->flags & EV_EOF) && user->connected)
                cleanup_conn(user);
}

int
main(int argc, char **argv)
{
        struct sockaddr_in servaddr;
        struct kevent *eventlist;
        long nevents;
        int listenfd, optval, kq;

        listenfd = socket_or_die(AF_INET, SOCK_STREAM, 0);
        optval = 1;
        if (setsockopt(listenfd, SOL_SOCKET, SO_REUSEADDR, &optval,
                      sizeof(optval)) < 0)
               err_sys("setsockopt");
        bzero(&servaddr, sizeof(servaddr));
        servaddr.sin_family = AF_INET;
        servaddr.sin_addr.s_addr = htonl(INADDR_ANY);
        servaddr.sin_port = htons(8080);
        if (bind(listenfd, (struct sockaddr *)&servaddr, sizeof(servaddr)) < 0)
                err_sys("bind error");
        setnblock_or_die(listenfd);
        if (listen(listenfd, 1024) < 0)
                err_sys("listen error");

        if ((nevents = sysconf(_SC_OPEN_MAX)) < 0)
                err_sys("sysconf");
        client = malloc_or_die(sizeof(*client)*nevents);
        nevents *= 2;
        eventlist = malloc_or_die(sizeof(*eventlist)*nevents);

        kq = kqueue_or_die();
        EV_SET(eventlist, listenfd, EVFILT_READ, EV_ADD, 0, 0, NULL);
        kevent_or_die(kq, eventlist, 1, NULL, 0, NULL);

        users = default_table();
        channels = default_table();

        for (;;) {
                int n;

                n = kevent_or_die(kq, NULL, 0, eventlist, nevents, NULL);
                for (int i=0; i<n; i++) {
                        struct kevent *ke;
                        ke = eventlist+i;
                        if (ke->ident == listenfd)
                                accept_conn(listenfd, kq, client);
                        else if (ke->filter == EVFILT_WRITE &&
                                 client[ke->ident].connected)
                                sendmsgs(kq, ke, client+ke->ident);
                        else if (ke->filter == EVFILT_READ)
                                recvcmds(kq, ke, client+ke->ident);
                }
        }
        return (EXIT_SUCCESS);
}
