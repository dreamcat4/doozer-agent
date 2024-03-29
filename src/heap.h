#pragma once

#include <limits.h>

typedef struct heapmgr {

  void (*dtor)(struct heapmgr *hm);

  int (*open_heap)(struct heapmgr *hm, const char *id,
                   char outpath[PATH_MAX],
                   char *errbuf, size_t errlen, int create);

  int (*delete_heap)(struct heapmgr *hm, const char *name);

  int (*clone_heap)(struct heapmgr *hm, const char *src,
                    const char *dst, char outpath[PATH_MAX],
                    char *errbuf, size_t errlen);

  int (*rename_heap)(struct heapmgr *hm, const char *src,
                     const char *dst, char outpath[PATH_MAX],
                     char *errbuf, size_t errlen);

} heapmgr_t;


#ifdef linux
heapmgr_t *heap_btrfs_init(const char *path);
#endif

heapmgr_t *heap_simple_init(const char *path);
