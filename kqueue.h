#ifndef VOODOO_KQUEUE_H_
#define VOODOO_KQUEUE_H_

#include <sys/types.h>
#include <sys/event.h>
#include <sys/time.h>

extern int kqueue_or_die(void);
extern int kevent_or_die(int, const struct kevent *, int, struct kevent *, int,
                          const struct timespec *);

#endif
