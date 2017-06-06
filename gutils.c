#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>

#include "gutils.h"

size_t g_strlen(const char *s)
{
    return s ? strlen(s) : 0;
}

char * g_strdup(const char *src)
{
    char *dst = NULL;
    int len = g_strlen(src);

    if (len) {
        dst = g_alloc(char, len + 1);
        strncpy(dst, src, len);
    }

    return dst;
}

char * g_strdup_printf(const char *fmt, ...)
{
    char c;
    size_t len = 0;
    char *dst = NULL;
    va_list args, copy;

    va_start(args, fmt);
    va_copy(copy, args);
    len = vsnprintf(&c, 1, fmt, args) + 1;

    dst = g_alloc(char, len);
    va_start(args, fmt);
    vsnprintf(dst, len, fmt, copy);

    return dst;
}

int g_strcmp(const char *a, const char *b)
{
    if (a == b) return 0;
    if (!a) return (int)-b[0];
    if (!b) return (int)a[0];

    return strcmp(a, b);
}

char * g_strv_join(const char **array, const char *sep)
{
    int i;
    size_t len;
    char *str = NULL;
    size_t sep_len = g_strlen(sep);

    for (i = 0; array[i]; i++)
        len += (g_strlen(array[i]) + sep_len);
    len -= sep_len;
    len += 1;

    str = g_alloc(char, len);

    len = 0;
    for(i = 0; array[i]; i++)
        len += sprintf(str + len, "%s%s", array[i], sep ? sep : "");

    return str;
}
