#ifndef LIANG_XDP_UTILITY_H
#define LIANG_XDP_UTILITY_H

#include <sys/stat.h>
#include <bpf/libbpf.h>

#ifndef PATH_MAX
#define PATH_MAX 4096
#endif

static inline struct bpf_program *
bpf_program_by_section_name(const struct bpf_object *obj,
                            const char *section_name)
{
    struct bpf_program *pos;
    const char *sname;

    bpf_object__for_each_program(pos, obj)
    {
        sname = bpf_program__section_name(pos);
        if (sname && !strcmp(sname, section_name))
            return pos;
    }
    return NULL;
}

static int make_dir_subdir(const char *parent, const char *dir)
{
    char path[PATH_MAX];
    int err;

    snprintf(path, sizeof(path), "%s/%s", parent, dir);

    err = mkdir(parent, S_IRWXU);
    if (err && errno != EEXIST)
    {
        return err;
    }

    err = mkdir(path, S_IRWXU);
    if (err && errno != EEXIST)
    {
        return err;
    }

    return 0;
}

// static inline

#endif