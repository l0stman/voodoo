#include <netinet/in.h>

#include <strings.h>
#include <stdlib.h>
#include <unistd.h>

#include "cbuf.h"
#include "err.h"
#include "kqueue.h"
#include "utils.h"

#define MIN(a, b)       ((a) < (b) ? (a) : (b))
#define MAX(a, b)       ((a) < (b) ? (b) : (a))

static struct cbuf *cmds;
static struct cbuf *input;
static struct cbuf *output;
static int sockfd;

static void
send_cmds(const struct kevent *ke, int kq)
{
        struct kevent change;

        cwrite(sockfd, cmds, MIN(ke->data, cmds->len));
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
        cread(STDIN_FILENO, input, ke->data);
        if (input->len == ke->data) {
                EV_SET(&change, sockfd, EVFILT_WRITE, EV_ENABLE, 0, 0,
                       (void *)send_cmds);
                kevent_or_die(kq, &change, 1, NULL, 0, NULL);
        }
        while (input->len > 0)
                if (cmovec(input, cmds, '\n', input->len)) {
                        cset('\r', cmds->len, cmds);
                        cset('\n', cmds->len, cmds);
                }
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
