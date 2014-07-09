#include <stdlib.h>
#include <fcntl.h>
#include <string.h>
#include <limits.h>
#include <errno.h>
#include <stdio.h>
#include <archive.h>
#include <archive_entry.h>

#include "agent.h"
#include "buildenv.h"
#include "heap.h"
#include "autobuild.h"

#include "libsvc/curlhelpers.h"
#include "libsvc/cfg.h"

/**
 *
 */
static int
makenode(const char *root, const char *d, mode_t mode, dev_t dev,
         char *errbuf, size_t errlen)
{
  char path[PATH_MAX];
  snprintf(path, sizeof(path), "%s/dev/%s", root, d);
  if(mknod(path, mode, dev)) {
    if(errno == EEXIST)
      return 0;

    snprintf(errbuf, errlen, "Unable to mknod(%s, 0%o, %d:%d) -- %s",
             path, mode, major(dev), minor(dev), strerror(errno));
    return -1;
  }

  if(chmod(path, mode)) {
    snprintf(errbuf, errlen, "Unable to chmod(%s,0%o) -- %s",
             path, mode, strerror(errno));
    unlink(path);
    return -1;
  }

  int uid = 10000;
  int gid = 10000;

  if(lchown(path, uid, gid)) {
    snprintf(errbuf, errlen, "Unable to chown(%s, %d, %d) -- %s",
             path, uid, gid, strerror(errno));
    unlink(path);
    return -1;
  }
  return 0;
}


/**
 *
 */
static int
makenodes(const char *root, char *errbuf, size_t errlen)
{

  if(makenode(root, "null", S_IFCHR | 0666, makedev(1, 3), errbuf, errlen))
    return -1;

  if(makenode(root, "zero", S_IFCHR | 0666, makedev(1, 5), errbuf, errlen))
    return -1;

  if(makenode(root, "random", S_IFCHR | 0444, makedev(1, 8), errbuf, errlen))
    return -1;

  if(makenode(root, "urandom", S_IFCHR | 0444, makedev(1, 9), errbuf, errlen))
    return -1;
  return 0;
}


/**
 *
 */
static int
buildenv_extract(const char *source, const char *target,
                 char *errbuf, size_t errlen,
                 int uidgidoffset, job_t *j)
{
  int rval = -1;
  char *data = NULL;
  size_t datalen = 0;
  int r;
  struct archive *a = archive_read_new();
  archive_read_support_compression_all(a);
  archive_read_support_format_all(a);
  archive_read_support_filter_all(a);

  if(!strncmp(source, "http://", 7) || !strncmp(source, "https://", 8)) {

    job_report_status(j, "building", "Downloading %s", source);

    CURL *curl = curl_easy_init();

    FILE *f = open_memstream(&data, &datalen);
    curl_easy_setopt(curl, CURLOPT_URL, source);
    curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, f);
    curl_easy_setopt(curl, CURLOPT_FAILONERROR, 1L);
    curl_easy_setopt(curl, CURLOPT_OPENSOCKETFUNCTION, &libsvc_curl_sock_fn);
    curl_easy_setopt(curl, CURLOPT_OPENSOCKETDATA, NULL);
    CURLcode cerr = curl_easy_perform(curl);
    fclose(f);
    curl_easy_cleanup(curl);

    if(cerr) {
      snprintf(errbuf, errlen, "Unable to download %s -- %s",
               source, curl_easy_strerror(cerr));
      return 1;
    }

    r = archive_read_open_memory(a, (void *)data, datalen);
  } else {
    r = archive_read_open_filename(a, source, 65536);
  }

  if(r) {
    snprintf(errbuf, errlen, "%s", archive_error_string(a));
  } else {

    struct archive_entry *entry;
    const char *oldpath;
    char path[PATH_MAX];
    char path2[PATH_MAX];

    while(archive_read_next_header(a, &entry) == ARCHIVE_OK) {

      int fd;
      int64_t size;

      snprintf(path, sizeof(path), "%s/%s",
               target, archive_entry_pathname(entry));

      int do_chmod = 0;
      int do_chown = 0;

      switch(archive_entry_filetype(entry)) {

      case AE_IFCHR:
      case AE_IFBLK:
        continue;

      case 0:
        snprintf(path2, sizeof(path2), "%s/%s",
                 target, archive_entry_hardlink(entry));
        if(link(path2, path)) {
          snprintf(errbuf, errlen, "Unable to link(%s, %s) -- %s",
                  path2, path, strerror(errno));
          goto bad;
        }
        break;

      case AE_IFDIR:
        if(mkdir(path, 0) && errno != EEXIST) {
          snprintf(errbuf, errlen, "Unable to mkdir(%s) -- %s",
                  path, strerror(errno));
          goto bad;
        }
        do_chmod = 1;
        do_chown = 1;
        break;

      case AE_IFLNK:
        oldpath = archive_entry_symlink(entry);
        if(symlink(oldpath, path)) {
          snprintf(errbuf, errlen, "Unable to symlink(%s, %s) -- %s",
                  oldpath, path, strerror(errno));
          goto bad;
        }
        do_chown = 1;
        break;

      case AE_IFREG:
        size = archive_entry_size(entry);
        void *mem = malloc(size);
        if(mem == NULL) {
          snprintf(errbuf, errlen, "out of memory");
          goto bad;
        }

        if(archive_read_data(a, mem, size) != size) {
          snprintf(errbuf, errlen, "Unable to read data");
          free(mem);
          goto bad;
        }

        fd = open(path, O_CLOEXEC | O_CREAT | O_TRUNC | O_NOFOLLOW | O_WRONLY,
                  0600);
        if(fd == -1) {
          snprintf(errbuf, errlen, "Unable to open(%s) -- %s",
                  path, strerror(errno));
          free(mem);
          goto bad;
        }

        if(write(fd, mem, size) != size) {
          snprintf(errbuf, errlen, "Unable to write(%s)",
                  path);
          close(fd);
          free(mem);
          goto bad;
        }
        close(fd);
        free(mem);
        do_chmod = 1;
        do_chown = 1;
        break;

      default:
        snprintf(errbuf, errlen, "Unable to handle filetype 0%o",
                archive_entry_filetype(entry));
        goto bad;

      }

      if(do_chmod) {
        mode_t mode = archive_entry_perm(entry);

        if(chmod(path, mode)) {
          snprintf(errbuf, errlen, "Unable to chmod(%s,0%o) -- %s",
                  path, mode, strerror(errno));
          goto bad;
        }
      }


      if(do_chown) {
        uid_t owner = archive_entry_uid(entry) + uidgidoffset;
        gid_t group = archive_entry_gid(entry) + uidgidoffset;
        if(lchown(path, owner, group)) {
          snprintf(errbuf, errlen, "Unable to chown(%s,%d,%d) -- %s",
                  path, owner, group, strerror(errno));
          goto bad;
        }
      }
    }
  }

  rval = 0;

 bad:
  archive_read_free(a);
  free(data);
  return rval;
}


/**
 *
 */
int
buildenv_install(job_t *j)
{
  char heapdir[PATH_MAX];
  int r;
  const char *id = j->buildenv_source_id;
  const char *source = j->buildenv_source;

  r = buildenv_heap_mgr->open_heap(buildenv_heap_mgr, id,
                                   heapdir, j->errmsg, sizeof(j->errmsg), 0);

  if(r == 0) {
    // Exist
    job_report_status(j, "building", "Build environment %s exist", id);
    return 0;
  }

  buildenv_heap_mgr->delete_heap(buildenv_heap_mgr, "tmp");

  r = buildenv_heap_mgr->open_heap(buildenv_heap_mgr, "tmp",
                                   heapdir, j->errmsg, sizeof(j->errmsg), 1);

  if(r)
      return r;

  job_report_status(j, "building", "Extracting build environment %s from %s",
                    id, source);

  linux_cap_change(1,
                   CAP_CHOWN,
                   CAP_DAC_OVERRIDE,
                   CAP_FOWNER,
                   CAP_FSETID,
                   CAP_MKNOD,
                   -1);

  r = buildenv_extract(source, heapdir, j->errmsg, sizeof(j->errmsg), 10000, j);

  if(!r)
    r = makenodes(heapdir, j->errmsg, sizeof(j->errmsg));

  if(!r) {
    // Create mount point for project bindmount
    char path[PATH_MAX];
    snprintf(path, sizeof(path), "%s/project", heapdir);

    if((r = mkdir(path, 0755)) != 0)
      snprintf(j->errmsg, sizeof(j->errmsg), "Unable to mkdir %s -- %s",
               path, strerror(errno));
  }


  linux_cap_change(0,
                   CAP_CHOWN,
                   CAP_DAC_OVERRIDE,
                   CAP_FOWNER,
                   CAP_FSETID,
                   CAP_MKNOD,
                   -1);

  if(!r)
      r = buildenv_heap_mgr->rename_heap(buildenv_heap_mgr, "tmp", id, NULL,
                                         j->errmsg, sizeof(j->errmsg));

  if(r)
    return DOOZER_PERMANENT_FAIL;

  return 0;
}
