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
bool   g_str_has_prefix(const char *str, const char *prefix);

typedef struct GKeyFile GKeyFile;
typedef struct GKeyFileGroup GKeyFileGroup;

GKeyFileGroup* g_key_file_group_new(const char *name);
void      g_key_file_group_unref(GKeyFileGroup *group);
void      g_key_file_group_set(GKeyFileGroup *group, const char *key, const char *val);
void      g_key_file_group_append(GKeyFileGroup *group, const char *key, const char *val);
void      g_key_file_group_appendv(GKeyFileGroup *group, ...);
void      g_key_file_group_setv(GKeyFileGroup *group, ...);
void      g_key_file_group_set_boolean(GKeyFileGroup *group, const char *key, bool val);
bool      g_key_file_group_get_boolean(GKeyFileGroup *group, const char *key);

GKeyFile* g_key_file_new();
void      g_key_file_unref(GKeyFile *file);
char*     g_key_file_to_data(GKeyFile *file);
bool      g_key_file_save_to_file(GKeyFile *key_file, const char *file);
bool      g_key_file_load_from_file(GKeyFile *key_file, const char *file);

GKeyFileGroup* g_key_file_get_group(GKeyFile *key_file, const char *name, bool add_if_not_exist);
void      g_key_file_add_group(GKeyFile *file, GKeyFileGroup *group);

void      g_key_file_set_value(GKeyFile *file, const char *group_name, const char *key, const char *val);
void      g_key_file_setv(GKeyFile *file, const char *group_name, ...);
const char * g_key_file_get_string(GKeyFile *key_file, const char *group_name, const char *key);
bool      g_key_file_get_boolean(GKeyFile *key_file, const char *group_name, const char *key);
void      g_key_file_set_boolean(GKeyFile *key_file, const char *group_name, const char *key, bool val);

#endif //__UCI_CONNMAN_GUTILS_H

