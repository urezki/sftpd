#ifndef __DEBUG_H__
#define __DEBUG_H__

#include <errno.h>

/* just causes a Segmentation Fault */
#define BUG() (*(int *)0 = 0)

#define __DEBUG_MSG__
/* #define __DEBUG_FUNC__ */

#ifdef __DEBUG_MSG__		  /* DEBUG MSG */
#define PRINT_DEBUG(fmt,arg...) do {								\
		fprintf(stdout, "%s:%d: " fmt, __FILE__, __LINE__, ##arg);	\
		fflush(stdout); } while (0)
#else
#define PRINT_DEBUG(fmt,arg...)					\
	do { } while(0)
#endif  /* __DEBUG_MSG__ */

#define handle_error_en(en, msg) \
	do { errno = en; perror(msg); exit(EXIT_FAILURE); } while (0)

#define handle_error(msg) \
	do { perror(msg); exit(EXIT_FAILURE); } while (0)

#define FATAL_ERROR(fmt, arg...) do {								\
		fprintf(stdout, "%s:%d: " fmt, __FILE__, __LINE__, ##arg);	\
		fflush(stdout);												\
		exit(-1); } while (0)

#ifdef __DEBUG_FUNC__		  /* DEBUG FUNCTIONS */
#define FUNC_ENTRY() do {								\
		fprintf(stdout, "%s: Enter.\n", __FUNCTION__);	\
		fflush(stdout); } while (0)

#define FUNC_EXIT_VOID() do {							\
		fprintf(stdout, "%s: Exit.\n", __FUNCTION__);	\
		fflush(stdout); } while (0)
		
#define FUNC_EXIT_INT(value) do {							\
		fprintf(stdout, "%s: Exit. Return value is: %d.\n",	\
				__FUNCTION__, value);						\
		fflush(stdout); } while (0)

#define FUNC_EXIT_UINT(value) do {										\
		fprintf(stdout, "%s: Exit. Return value is: %u (0x%08x).\n",	\
				__FUNCTION__, value, value);							\
		fflush(stdout); } while (0)
		
#define FUNC_EXIT_PTR(ptr) do {									\
		fprintf(stdout, "%s: Exit. Returned pointer is: %p.\n",	\
				__FUNCTION__, ptr);								\
		fflush(stdout); } while (0)
#else

#define FUNC_ENTRY() do { } while(0)
#define FUNC_EXIT_VOID() do { } while(0)
#define FUNC_EXIT_INT(value) do { } while(0)
#define FUNC_EXIT_UINT(value) do { } while(0)
#define FUNC_EXIT_PTR(ptr) do { } while(0)

#endif  /* __DEBUG_FUNC__ */
#endif  /* __DEBUG_H__ */
