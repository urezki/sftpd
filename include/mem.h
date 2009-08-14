#ifndef __MEM_H__
#define __MEM_H__

#ifdef MEMORY_DEBUG

extern void *__calloc(size_t, size_t, const char *, const char *, int);
extern void *__realloc(void *, size_t, const char *, const char *, int);
extern void *__malloc(size_t, const char *, const char *, int);
extern char *__strdup (const char *, const char *, const char *, int);
extern void __free(void *, const char *, const char *, int);
extern u_long __get_mem_status(void);

#define malloc(A) __malloc(A, __FILE__, __FUNCTION__, __LINE__)
#define calloc(A, B) __calloc(A, B, __FILE__, __FUNCTION__, __LINE__)
#define realloc(A, B) __realloc(A, B, __FILE__, __FUNCTION__, __LINE__)
#define strdup(A) __strdup(A, __FILE__, __FUNCTION__, __LINE__)
#define free(A) __free(A, __FILE__, __FUNCTION__, __LINE__)

#endif  /* MEMORY_DEBUG */
#endif  /* __MEM_H__ */
