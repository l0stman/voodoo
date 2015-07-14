#include "kqueue.h"
#include "err.h"

int
kqueue_or_die(void)
{
        int kq;

        if ((kq = kqueue()) == -1)
                err_sys("kqueue");
        return kq;
}

int
kevent_or_die(int kq,
              const struct kevent *changelist,
              int nchanges,
              struct kevent *eventlist,
              int nevents,
              const struct timespec *timeout)
{
        int n;

        n = kevent(kq, changelist, nchanges, eventlist, nevents, timeout);
        if (n == -1)
                err_sys("kevent");
        return n;
}
