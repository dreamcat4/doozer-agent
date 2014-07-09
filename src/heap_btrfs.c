#include <fcntl.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <unistd.h>
#include <stdio.h>
#include <stdint.h>
#include <errno.h>
#include <string.h>
#include <stdlib.h>

#include "libsvc/trace.h"
#include "libsvc/misc.h"

#include "linux_btrfs.h"
#include "heap.h"
#include "agent.h"


typedef struct heapmgr_btrfs {
  heapmgr_t super;

  char *path;

} heapmgr_btrfs_t;


/**
 *
 */
static void
heap_btrfs_dtor(heapmgr_t *super)
{
  heapmgr_btrfs_t *hm = (heapmgr_btrfs_t *)super;
  free(hm->path);
  free(hm);
}




/**
 *
 */
static int
heap_btrfs_open(struct heapmgr *super, const char *subvolname,
                char outpath[PATH_MAX],
                char *errbuf, size_t errlen, int create)
{
  heapmgr_btrfs_t *hm = (heapmgr_btrfs_t *)super;
  const char *parent = hm->path;

  snprintf(outpath, PATH_MAX, "%s/%s", parent, subvolname);

  struct stat st;
  int r = stat(outpath, &st);
  if(r == 0) {
    if(st.st_ino == 256 && S_ISDIR(st.st_mode))
      return 1;

    snprintf(errbuf, errlen, "%s exists but is not a Btrfs subvolume",
             outpath);
    return -1;
  }

  if(!create) {
    snprintf(errbuf, errlen, "%s does not exist", outpath);
    return -1;
  }

  int fd = open(parent, O_RDONLY);
  if(fd == -1) {
    snprintf(errbuf, errlen, "Unable to open parent dir %s -- %s",
             parent, strerror(errno));
    return -1;
  }

  struct btrfs_ioctl_vol_args args = {};
  snprintf(args.name, BTRFS_SUBVOL_NAME_MAX, "%s", subvolname);
  r = ioctl(fd, BTRFS_IOC_SUBVOL_CREATE, &args);
  int err = errno;
  close(fd);

  if(r == 0)
    return 0;

  snprintf(errbuf, errlen,
           "Unable to create Btrfs subvolume %s at %s -- %s",
           subvolname, parent, strerror(err));
  return -1;
}


/**
 *
 */
static int
heap_btrfs_delete(struct heapmgr *super, const char *subvolname)
{
  heapmgr_btrfs_t *hm = (heapmgr_btrfs_t *)super;
  const char *parent = hm->path;


  int fd = open(parent, O_RDONLY);
  if(fd == -1) {
    trace(LOG_ERR, "heap_btrfs: Unable to open parent dir %s -- %s",
          parent, strerror(errno));
    return -1;
  }

  struct btrfs_ioctl_vol_args args = {};
  snprintf(args.name, BTRFS_SUBVOL_NAME_MAX, "%s", subvolname);

  linux_cap_change(1, CAP_SYS_ADMIN, -1);

  int r = ioctl(fd, BTRFS_IOC_SNAP_DESTROY, &args);
  int err = errno;

  linux_cap_change(0, CAP_SYS_ADMIN, -1);

  close(fd);

  if(r == 0 || err == ENOENT)
    return 0;

  trace(LOG_ERR,
        "heap_btrfs: Unable to destroy Btrfs subvolume %s at %s -- %s",
        subvolname, parent, strerror(err));
  return -1;
}



/**
 *
 */
static int
heap_btrfs_clone(struct heapmgr *super, const char *src, const char *dst,
                 char outpath[PATH_MAX], char *errbuf, size_t errlen)
{
  heapmgr_btrfs_t *hm = (heapmgr_btrfs_t *)super;
  const char *parent = hm->path;

  int fd = open(parent, O_RDONLY);
  if(fd == -1) {
    snprintf(errbuf, errlen, "heap_btrfs: Unable to open parent dir %s -- %s",
             parent, strerror(errno));
    return -1;
  }

  // Delete target if it existed previously

  struct btrfs_ioctl_vol_args args = {};
  snprintf(args.name, BTRFS_SUBVOL_NAME_MAX, "%s", dst);

  linux_cap_change(1, CAP_SYS_ADMIN, -1);
  ioctl(fd, BTRFS_IOC_SNAP_DESTROY, &args);
  linux_cap_change(0, CAP_SYS_ADMIN, -1);


  char srcpath[PATH_MAX];
  snprintf(srcpath, sizeof(srcpath), "%s/%s", parent, src);

  int fd_src = open(srcpath, O_RDONLY);
  if(fd_src == -1) {
    snprintf(errbuf, errlen, "heap_btrfs: Unable to open source dir %s -- %s",
             srcpath, strerror(errno));
    close(fd);
    return -1;
  }

  struct btrfs_ioctl_vol_args_v2 argsv2 = {};
  argsv2.fd = fd_src;
  snprintf(argsv2.name, BTRFS_SUBVOL_NAME_MAX, "%s", dst);
  int r = ioctl(fd, BTRFS_IOC_SNAP_CREATE_V2, &argsv2);
  int err = errno;

  close(fd);
  close(fd_src);


  if(r < 0) {
    snprintf(errbuf, errlen,
             "heap_btrfs: Unable to create snapshot %s from %s -- %s",
             dst, src, strerror(err));
    return -1;
  }

  snprintf(outpath, PATH_MAX, "%s/%s", parent, dst);

  return 0;
}


/**
 *
 */
static int
heap_btrfs_rename(struct heapmgr *super, const char *src, const char *dst,
                  char outpath[PATH_MAX], char *errbuf, size_t errlen)
{
  heapmgr_btrfs_t *hm = (heapmgr_btrfs_t *)super;

  char srcpath[PATH_MAX];
  char dstpath[PATH_MAX];

  if(outpath == NULL)
    outpath = dstpath;

  snprintf(srcpath, sizeof(srcpath), "%s/%s", hm->path, src);
  snprintf(outpath, PATH_MAX, "%s/%s", hm->path, dst);

  if(!rename(srcpath, outpath))
    return 0;

  snprintf(errbuf, errlen, "Unable to rename %s to %s -- %s",
           srcpath, outpath, strerror(errno));
  return -1;
}


/**
 *
 */
heapmgr_t *
heap_btrfs_init(const char *path)
{
  int fd = open(path, O_RDONLY);
  if(fd == -1) {
    trace(LOG_WARNING, "heap_btrfs: %s is not accessible", path);
    return NULL;
  }

  struct btrfs_ioctl_ino_lookup_args args = {};

  args.objectid = 256ULL;
  int r = ioctl(fd, BTRFS_IOC_INO_LOOKUP, &args);
  close(fd);
  if(r < 0) {
    trace(LOG_WARNING,
          "heap_btrfs: %s is not on a Btrfs filesystem -- %s",
          path, strerror(errno));
    return NULL;
  }

  heapmgr_btrfs_t *hm = calloc(1, sizeof(heapmgr_btrfs_t));
  hm->path = strdup(path);
  hm->super.dtor = heap_btrfs_dtor;
  hm->super.open_heap = heap_btrfs_open;
  hm->super.delete_heap = heap_btrfs_delete;
  hm->super.clone_heap = heap_btrfs_clone;
  hm->super.rename_heap = heap_btrfs_rename;

  return &hm->super;
}

