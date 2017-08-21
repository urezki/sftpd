#ifndef __STR_H__
#define __STR_H__

extern void str_contac(char *);
extern size_t str_strlen(const char *);
extern size_t str_findss(const char *, const char *);
extern size_t str_removesfs(char *, const char *);
extern size_t str_strcspn(const char *, const char *);
extern size_t str_remove_from_to_symbols(char *str, char a, char b);

#endif
