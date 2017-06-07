#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <errno.h>

#include <libubox/list.h>

#include "gutils.h"
#include "log.h"

size_t g_strlen(const char *s)
{
    return s ? strlen(s) : 0;
}

char * g_strdup(const char *src)
{
    char *dst = NULL;
    int len = src ? g_strlen(src) + 1 : 0;

    if (len) {
        dst = g_alloc(char, len);
        strncpy(dst, src, len - 1);
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

bool g_str_has_prefix(const char *str, const char *prefix)
{
    if (!str) return false;
    if (!prefix) return true;

    while(*prefix)
        if ( !*str || *str++ != *prefix++) return false;

    return true;
}

/*
 * KeyFile [En/De]coder
 */

typedef struct GKeyVal {
    struct list_head node;
    char *key;
    char *val;
} GKeyVal;

GKeyVal * g_key_val_new(const char *key, const char *val)
{
    GKeyVal *kv = g_alloc(GKeyVal, 1);

    INIT_LIST_HEAD(&kv->node);
    kv->key = g_strdup(key);
    kv->val = g_strdup(val);

    return kv;
}

void g_key_val_unref(GKeyVal *kv)
{
    if (!kv) return;

    list_del(&kv->node);
    g_free(kv->key);
    g_free(kv->val);
    g_free(kv);
}

char * g_key_val_to_data(GKeyVal *opt)
{
    if (!opt) return g_strdup("");

    return g_strdup_printf("%s=%s\n", opt->key, opt->val);
}

typedef struct GKeyFileGroup {
    struct list_head node;
    char *name;
    struct list_head options;
} GKeyFileGroup;

GKeyFileGroup * g_key_file_group_new(const char *name)
{
    GKeyFileGroup *grp = g_alloc(GKeyFileGroup, 1);

    INIT_LIST_HEAD(&grp->node);
    INIT_LIST_HEAD(&grp->options);
    grp->name = g_strdup(name);

    return grp;
}

void g_key_file_group_unref(GKeyFileGroup *group)
{
    GKeyVal *opt, *n;
    if (!group) return ;

    list_del(&group->node);

    g_free(group->name);
    list_for_each_entry_safe(opt, n, &group->options, node) {
        g_key_val_unref(opt);
    }

    g_free(group);
}

void g_key_file_group_append(GKeyFileGroup *group, const char *key, const char *val)
{
    if (!group || !key || !val) return;

    list_add_tail(&g_key_val_new(key, val)->node, &group->options);
}

static
GKeyVal* g_key_file_group_get(GKeyFileGroup *grp, const char *key)
{
    GKeyVal *opt = NULL;

    list_for_each_entry(opt, &grp->options, node) {
        if (opt && !g_strcmp(opt->key, key))
            return opt;
    }

    return NULL;
}

void g_key_file_group_set(GKeyFileGroup *group, const char *key, const char *val)
{
    GKeyVal *opt = NULL;

    if (!group || !key || !val) return;
    
    opt = g_key_file_group_get(group, key);
    if (opt) {
        g_free(opt->val);
        opt->val = g_strdup(val);
    } else {
        g_key_file_group_append(group, key, val);
    }
}

static
void g_key_file_group_set_valist(GKeyFileGroup *group, va_list args)
{
    const char *key, *val;

    while((key = va_arg(args, char *))) {
        val = va_arg(args, char *);
        if (!val) continue;

        g_key_file_group_set(group, key, val);
    }
    va_end(args);
}

void g_key_file_group_setv(GKeyFileGroup *group, ...)
{
    va_list args;

    if (!group) return;

    va_start(args, group);

    g_key_file_group_set_valist(group, args);
}

void g_key_file_group_appendv(GKeyFileGroup *group, ...)
{
    va_list args;
    const char *key = NULL;
    const char *val = NULL;

    if (!group) return;

    va_start(args, group);

    while((key = va_arg(args, char *))) {
        val = va_arg(args, char *);
        if (!val) break;

        g_key_file_group_append(group, key, val);
    }

    va_end(args);
}

void g_key_file_group_set_boolean(GKeyFileGroup *group, const char *key, bool val)
{
    if (!group || !key) return;

    g_key_file_group_set(group, key, val ? "1" : "0");
}

bool g_key_file_group_get_boolean(GKeyFileGroup *group, const char *key)
{
    GKeyVal *opt;

    if (!group || !key) return false;

    opt = g_key_file_group_get(group, key);

    return opt ? opt->val[0] == '1' : false;
}

static
char* g_key_file_group_to_data(GKeyFileGroup *grp)
{
    GKeyVal *opt = NULL;
    char *data = g_strdup("");

    list_for_each_entry(opt, &grp->options, node) {
        char *tmp = g_strdup_printf("%s%s", data, g_key_val_to_data(opt));
        g_free(data);
        data = tmp;
    }

    return data;
}

struct GKeyFile {
    struct list_head groups;

    int ref_count;
};


GKeyFile* g_key_file_new()
{
    GKeyFile *file = g_alloc(GKeyFile, 1);

    INIT_LIST_HEAD(&file->groups);
    file->ref_count = 1;

    return file;
}

void g_key_file_ref(GKeyFile *file)
{
    if (file)
        file->ref_count++;
}

void g_key_file_unref(GKeyFile *file)
{
    struct list_head *p, *n;
    if (!file) return;

    if ( --file->ref_count > 0) return;

    list_for_each_safe(p, n, &file->groups) {
        g_key_file_group_unref(list_entry(p, GKeyFileGroup, node));
    }

    g_free(file);
}

GKeyFileGroup * g_key_file_get_group(GKeyFile *file, const char *name, bool add_if_not_exist)
{
    GKeyFileGroup *group = NULL;

    list_for_each_entry(group, &file->groups, node) {
        if (!g_strcmp(group->name, name)) {
            return group;
        }
    }

    if (add_if_not_exist) {
        group = g_key_file_group_new(name);
        list_add_tail(&group->node, &file->groups);
    } else {
        group = NULL;
    }

    return group;
}

char* g_key_file_to_data(GKeyFile *file)
{
    char *data = g_strdup("");
    char *tmp = NULL;
    GKeyFileGroup *grp;

    if (!file) return data;

    list_for_each_entry(grp, &file->groups, node) {
        char *str_group = g_key_file_group_to_data(grp);
        tmp = g_strdup_printf("%s[%s]\n%s\n", data, grp->name, str_group);
        g_free(data);
        g_free(str_group);
        data = tmp;
   }

    return data;
}

bool g_key_file_save_to_file(GKeyFile *file, const char *file_path)
{
    char *data = NULL;
    size_t len;
    FILE *fp = NULL;

    if (!file || !file_path) {
        errno = EINVAL;
        return false;
    }

    if (!(fp = fopen(file_path, "w"))) {
        return false;
    }
    
    data = g_key_file_to_data(file);
    len = strlen(data);

    if (len != fwrite(data, sizeof(char), len, fp)) {
        g_free(data);
        return false;
    }
    g_free(data);

    return true;
}

bool g_key_file_load_from_file(GKeyFile *key_file, const char *file)
{
    FILE *fp = NULL;
    char line[1024];
    GKeyFileGroup *grp = NULL;

    if (!key_file || !file) {
        errno = EINVAL;
        return false;
    }

    if (!(fp = fopen(file, "r"))) {
        return false;
    }

    while (fgets(line, sizeof(line), fp) != NULL) {
        int i = 0;

        // truncate white spaces
        while ( line[i] && (line[i] == ' ' || line[i] == '\t' || line[i] == '\n'))
            i++;
        // Leave comments and blank lines
        if ( !line[i] || line[i] == '#' )
            continue;

        if ( line[i] == '[') {
            char *grp_name = line + ++i;
            while ( line[i] && line[i] != ']')
                i++;
            line[i] = '\0';

            grp = g_key_file_group_new(grp_name);
            list_add_tail(&grp->node, &key_file->groups);
        } else if (grp) {
            char *key = NULL, *val = NULL;
            GKeyVal *opt = NULL;

            key = line + i;
            while (line[i] && line[i] != '=')
                i++;
            line[i++] = '\0';

            val = line + i;
            while (line[i] && line[i] != '\n')
                i++;
            line[i] = '\0';

            opt = g_key_val_new(key, val);
            list_add_tail(&opt->node, &grp->options);
        }
    }

    return true;
}

void g_key_file_set_value(GKeyFile *file, const char *group, const char *key, const char *val)
{
    GKeyFileGroup *grp = NULL;

    if (!file || !group || !key || !val) return;

    grp = g_key_file_get_group(file, group, true);

    g_key_file_group_set(grp, key, val);
}

void g_key_file_setv(GKeyFile *file, const char *group_name, ...)
{
    va_list args;
    GKeyFileGroup *group = NULL;

    if (!file || !group_name) return;

    group = g_key_file_get_group(file, group_name, true);
    
    va_start(args, group_name);

    g_key_file_group_set_valist(group, args);
}

const char * g_key_file_get_string(GKeyFile *file, const char *group, const char *key)
{
    GKeyFileGroup *grp;

    if ((grp = g_key_file_get_group(file, group, false))) {
        GKeyVal *opt = g_key_file_group_get(grp, key);
        return opt ? opt->val : NULL;
    }
    return NULL;
}

bool g_key_file_get_boolean(GKeyFile *file, const char *group, const char *key)
{
    const char *val = g_key_file_get_string(file, group, key);

    if (!val) return false;

    return val[0] == '1';
}

void g_key_file_set_boolean(GKeyFile *file, const char *group, const char *key, bool val)
{
    g_key_file_set_value(file, group, key, val ? "1" : "0");
}

