#ifndef VOODOO_ERR_H_
#define VOODOO_ERR_H_

#define ERRMAXLINE	100     /* Maximum length of an error message */

extern void err_quit(const char *, ...);
extern void err_sys(const char *, ...);

#endif
