#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>

/* local headers */
#include <debug.h>
#include <list.h>

/*
 * Head of the memory list, uses for memory debugging.
 */
static TAILQ_HEAD(mem_list, __mnode) mem_head = TAILQ_HEAD_INITIALIZER(mem_head);
							 
static u_long bytes_allocated;
static u_long bytes_freed;

struct __mnode {
	void *addr;
	size_t size;
	const char *file;
	const char *func;
	int line;
	
	/*
	 * This holds the pointers to the next and
	 * previous entries in the tail queue.
	 */
	TAILQ_ENTRY(__mnode) entries;
};

/**
 * __calloc - allocates  memory for an array of
 * nmemb elements of size bytes each and returns
 * a pointer to the allocated memory.
 *
 * @nmemb: number of elements;
 * @size:  size of each element;
 * @file:  name of the file where __calloc is called;
 * @func:  name of the function where __calloc is called;
 * @line:  the line number where __calloc is called.
 */
void *
__calloc(size_t nmemb, size_t size, const char *file, const char *func, int line)
{
	struct __mnode *m = calloc(1, sizeof(*m));
	void *ptr = calloc(nmemb, size);

	m->size = size * nmemb;
	m->addr = ptr;
	m->file = file;
	m->func = func;
	m->line = line;

	bytes_allocated += m->size;
	TAILQ_INSERT_TAIL(&mem_head, m, entries);
	
	return ptr;
}

/**
 * __malloc - allocates size bytes and returns a
 * pointer to the allocated memory, and adds __mnode
 * to the memory list.
 *
 * @size: size of memory;
 * @file: name of the file where __malloc is called;
 * @func: name of the function where __malloc is called;
 * @line: the line number where __malloc is called.
 */
void *
__malloc(size_t size, const char *file, const char *func, int line)
{
	struct __mnode *m = calloc(1, sizeof(*m));
	void *ptr = malloc(size);

	m->size = size;
	m->addr = ptr;
	m->file = file;
	m->func = func;
	m->line = line;
	
	bytes_allocated += size;
	TAILQ_INSERT_TAIL(&mem_head, m, entries);

	return ptr;
}

/**
 * __free - frees the memory space pointed to by ptr,
 * and removes __mndoe from the mem list, if ptr is NULL,
 * no operation is performed.
 *
 * @ptr:  pointer to the allocated memory;
 * @file: name of the file where __free is called;
 * @func: name of the function where __free is called;
 * @line: the line number where __free is called.
 */
void
__free(void *ptr, const char *file, const char *func, int line)
{
	struct __mnode *item;
	int found = 0;

	TAILQ_FOREACH(item, &mem_head, entries) {
		if (item->addr == ptr) {
			bytes_allocated -= item->size;
			bytes_freed += item->size;

			TAILQ_REMOVE(&mem_head, item, entries);

			free(item->addr);
			free(item);
			found++;
			break;
		}
	}
	
	if (!found)
		syslog(LOG_ERR, "unallocated free of %p by %s in %s at line %d\n",
			   ptr, func, file, line);
}

/**
 * __realloc - changes the size of the memory
 * block pointed to by ptr to size bytes.
 *
 * @old_addr: block of memory pointed to by old_addr;
 * @size:     size of memory;
 * @file:     name of the file where __realloc is called;
 * @func:     name of the function where __realloc is called;
 * @line:     the line number where __realloc is called.
 */
void *
__realloc(void *old_addr, size_t size, const char *file, const char *func, int line)
{
	void *new_addr = __malloc(size, file, func, line);

	if (new_addr && old_addr) {
		memcpy(new_addr, old_addr, size);
		__free(old_addr, file, func, line);
	}
	
	return new_addr;
}

/**
 * __strdup - returns a pointer to a new string which
 * is a duplicate of the string s.
 * 
 * @str:  string that will duplicate;
 * @file: name of the file where __strdup is called;
 * @func: name of the function where __strdup is called;
 * @line: the line number where __strdup is called.
 */
char *
__strdup(const char *str, const char *file, const char *func, int line)
{
	size_t len;
	char *new_str;
	
	len = strlen(str) + 1;	  /* +1 for '\0' */
	new_str = __malloc(len, file, func, line);
	
	if (str && new_str)
		strncpy(new_str, str, len);

	return new_str;
}

/**
 * Returns information about how much
 * memory we are using at present.
 */
u_long
__get_mem_status(void)
{
	return bytes_allocated;
}
