#ifndef __UTILS_H__
#define __UTILS_H__

extern void set_euid(uid_t);
extern void reset_euid(void);

extern void set_egid(gid_t);
extern void reset_egid(void);

#endif  /* __UTILS_H__ */
