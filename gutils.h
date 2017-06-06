#ifndef __UCI_CONNMAN_GUTILS_H
#define __UCI_CONNMAN_GUTILS_H

#include <stdlib.h>

#define g_alloc(type, len) (type *)calloc((len), sizeof(type));
#define g_free(ptr) if (ptr) free(ptr)

size_t g_strlen(const char *str);
char * g_strdup(const char *src);
char * g_strdup_printf(const char *fmt, ...);
int    g_strcmp(const char *a, const char *b);
char * g_strv_join(const char **array, const char *sep);

#endif //__UCI_CONNMAN_GUTILS_H

