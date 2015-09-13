#include <netinet/in.h>

#include <strings.h>
#include <stdlib.h>
#include <unistd.h>

#include "cbuf.h"
#include "err.h"
#include "kqueue.h"
#include "utils.h"

#define MIN(a, b)       ((a) < (b) ? (a) : (b))

static struct cbuf *cmds;
static struct cbuf *input;
static struct cbuf *output;
static int sockfd;
static int read_enabled;

static size_t
input_to_cmds(void)
{
        size_t nbytes, rem, i;
        char c;

        rem = cmds->size - cmds->len;
        nbytes = 0;
        for (i = 0; nbytes < rem && i < input->len; i++) {
                if ((c = cref(input, i)) == '\n') {
                        if (cmds->len == cmds->size-1)
                                break; /* not enough space for CRLF */
                        cappend('\r', cmds);
                        cappend('\n', cmds);
                        nbytes += 2;
                } else {
                        cappend(c, cmds);
                        ++nbytes;
                }
        }
        input->offset = (input->offset + i) % input->size;
        input->len -= i;
        return (nbytes);
}

static void read_cmds(const struct kevent *, int);

static void
send_cmds(const struct kevent *ke, int kq)
{
        struct kevent change;

        cwrite(sockfd, cmds, MIN(ke->data, cmds->len));
        if (input_to_cmds() && !read_enabled) {
                EV_SET(&change, STDIN_FILENO, EVFILT_READ, EV_ENABLE, 0, 0,
                       (void *)read_cmds);
                kevent_or_die(kq, &change, 1, NULL, 0, NULL);
                read_enabled = 1;
        }
        if (cmds->len == 0) {
                EV_SET(&change, sockfd, EVFILT_WRITE, EV_DISABLE, 0, 0, NULL);
                kevent_or_die(kq, &change, 1, NULL, 0, NULL);
        }
}

static void
read_cmds(const struct kevent *ke, int kq)
{
        struct kevent change;

        if (ke->data == 0)
                exit(EXIT_FAILURE);
        cread(STDIN_FILENO, input, MIN(ke->data, input->size-input->len));
        if (cmds->len == 0) {
                EV_SET(&change, sockfd, EVFILT_WRITE, EV_ENABLE, 0, 0,
                       (void *)send_cmds);
                kevent_or_die(kq, &change, 1, NULL, 0, NULL);
        }
        if (input->len == input->size &&
            (cmds->len == cmds->size ||
             (cmds->len == cmds->size-1 && cref(input, 0) == '\n'))) {
                EV_SET(&change, STDIN_FILENO, EVFILT_READ, EV_DISABLE, 0, 0,NULL);
                kevent_or_die(kq, &change, 1, NULL, 0, NULL);
                read_enabled = 0;
        } else
                input_to_cmds();
}

static void
write_msgs(const struct kevent *ke, int kq)
{
        struct kevent change;

        cwrite(STDOUT_FILENO, output, MIN(ke->data, output->len));
        if (output->len == 0) {
                EV_SET(&change, STDOUT_FILENO, EVFILT_WRITE, EV_DISABLE, 0, 0,
                       NULL);
                kevent_or_die(kq, &change, 1, NULL, 0, NULL);
        }
}

static void
read_msgs(const struct kevent *ke, int kq)
{
        struct kevent change;

        if (ke->data == 0)
                err_quit("server terminated the connection");
        cread(sockfd, output, ke->data);
        if (output->len == ke->data) {
                EV_SET(&change, STDOUT_FILENO, EVFILT_WRITE, EV_ENABLE, 0, 0,
                (void *)write_msgs);
                kevent_or_die(kq, &change, 1, NULL, 0, NULL);
        }
}

int
main(void)
{
        typedef void (*fnp)(struct kevent *, int);
        struct sockaddr_in servaddr;
        struct kevent event[4];
        int kq;

        sockfd = socket_or_die(AF_INET, SOCK_STREAM, 0);
        setnblock_or_die(sockfd);
        bzero(&servaddr, sizeof(servaddr));
        servaddr.sin_family = AF_INET;
        servaddr.sin_addr.s_addr = htonl(INADDR_ANY);
        servaddr.sin_port = htons(8080);
        if (connect(sockfd, (struct sockaddr *)&servaddr, sizeof(servaddr)) < 0)
                err_sys("connect");
        setnblock_or_die(STDIN_FILENO);
        setnblock_or_die(STDOUT_FILENO);
        EV_SET(event, STDOUT_FILENO, EVFILT_WRITE, EV_ADD | EV_DISABLE, 0, 0,
               (void *)write_msgs);
        EV_SET(event+1, STDIN_FILENO, EVFILT_READ, EV_ADD, 0, 0,
               (void *)read_cmds);
        EV_SET(event+2, sockfd, EVFILT_WRITE, EV_ADD | EV_DISABLE, 0, 0,
               (void *)send_cmds);
        EV_SET(event+3, sockfd, EVFILT_READ, EV_ADD, 0, 0, (void *)read_msgs);
        kq = kqueue_or_die();
        kevent_or_die(kq, event, 4, NULL, 0, NULL);

        cmds = cbuf();
        input = cbuf();
        output = cbuf();
        read_enabled = 1;
        for (;;) {
                int n;

                n = kevent_or_die(kq, NULL, 0, event, sizeof(event), NULL);
                for (int i=0; i<n; i++) {
                        if (event[i].flags & EV_ERROR)
                                err_sys("kevent");
                        ((fnp)event[i].udata)(event+i, kq);
                }
        }
        return (EXIT_SUCCESS);
}
