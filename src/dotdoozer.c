#include <sys/param.h>
#include <assert.h>
#include <sys/stat.h>
#include <sys/types.h>

#include <string.h>
#include <errno.h>
#include <stdlib.h>
#include <limits.h>
#include <unistd.h>
#include <stdio.h>
#include <stdarg.h>
#include <fcntl.h>
#include <openssl/sha.h>

#include "libsvc/htsmsg.h"
#include "libsvc/misc.h"
#include "libsvc/trace.h"
#include "libsvc/htsbuf.h"
#include "libsvc/talloc.h"
#include "libsvc/htsmsg_json.h"

#include "job.h"
#include "git.h"
#include "dotdoozer.h"
#include "artifact.h"
#include "heap.h"
#include "buildenv.h"


static int
dotdoozer_parse(job_t *j, htsmsg_t *target)
{
  const char *buildenv = htsmsg_get_str(target, "buildenv");
  if(buildenv == NULL)
    return 0;

  // We are going to build in a chroot
  j->projectdir_internal = "/project";

  j->base_buildenv = tstrdup(buildenv);

  SHA_CTX ctx;
  SHA1_Init(&ctx);

  SHA1_Update(&ctx, j->base_buildenv, strlen(j->base_buildenv));

  htsmsg_t *builddeps = htsmsg_get_list(target, "builddeps");
  if(builddeps != NULL) {

    htsmsg_field_t *f;

    int count = 0;
    HTSMSG_FOREACH(f, builddeps) {
      if(f->hmf_type != HMF_STR) {
        snprintf(j->errmsg, sizeof(j->errmsg),
                 "Not all builddeps are strings");
        return DOOZER_PERMANENT_FAIL;
      }
      count++;
    }

    j->num_builddeps = count;

    const char **bds = talloc_zalloc(count * sizeof(char *));
    count = 0;
    HTSMSG_FOREACH(f, builddeps) {
      bds[count++] = tstrdup(f->hmf_str);
      SHA1_Update(&ctx, f->hmf_str, strlen(f->hmf_str));
    }
    j->builddeps = bds;
  }

  SHA1_Final(j->modified_buildenv_digest, &ctx);
  return 0;
}


/**
 *
 */
static int
dotdoozer_prep_buildenv(job_t *j)
{
  int r;
  char modified_heap[41];
  char path[PATH_MAX];

  // Delete any current heap

  buildenv_heap_mgr->delete_heap(buildenv_heap_mgr, "current");

  // Name of the modified builvenv is just the sha1 hash

  bin2hex(modified_heap, sizeof(modified_heap),
          j->modified_buildenv_digest, sizeof(j->modified_buildenv_digest));

  r = buildenv_heap_mgr->clone_heap(buildenv_heap_mgr,
                                    modified_heap,
                                    "current", path,
                                    j->errmsg, sizeof(j->errmsg));
  if(!r) {
    // Ok, got it cloned into 'current'
    j->buildenvdir = tstrdup(path);
    return 0;
  }

  // Make sure base buildenv is installed

  r = buildenv_install(j);
  if(r)
    return r;

  r = buildenv_heap_mgr->clone_heap(buildenv_heap_mgr,
                                    j->base_buildenv,
                                    modified_heap,
                                    path,
                                    j->errmsg, sizeof(j->errmsg));
  if(r)
    return r;

  j->buildenvdir = tstrdup(path);

  int argc = 4 + j->num_builddeps + 1;
  const char **argv = talloc_malloc(argc * sizeof(char *));

  argv[0] = "/usr/bin/apt-get";
  argv[1] = "--yes";
  argv[2] = "--force-yes";
  argv[3] = "install";

  for(int i = 0; i < j->num_builddeps; i++)
    argv[4 + i] = j->builddeps[i];

  argv[4 + j->num_builddeps] = NULL;

  r = job_run_command(j, argv, JOB_RUN_AS_ROOT);

  if(r)
    buildenv_heap_mgr->delete_heap(buildenv_heap_mgr, modified_heap);

  return r;
}


/**
 *
 */
static int
dotdoozer_do_build(job_t *j, htsmsg_t *target)
{
  const char *buildcmd = htsmsg_get_str(target, "buildcmd");

  if(buildcmd == NULL) {
    snprintf(j->errmsg, sizeof(j->errmsg),
             "No build command");
    return DOOZER_PERMANENT_FAIL;
  }

  printf("buildcmd: %s\n", buildcmd);

  char *arg = mystrdupa(buildcmd);
  const char *argv[257];
  int argc = str_tokenize(arg, (char **)argv, 256, ' ');
  argv[argc] = NULL;
  char workdir[PATH_MAX];
  snprintf(workdir, sizeof(workdir), "%s/workdir",
           j->projectdir_internal);


  // Very lazy and lame variable substitution

  for(int i = 0; i < argc; i++) {
    if(!strcmp(argv[i], "${TARGET}"))
      argv[i] = j->target;
    else if(!strcmp(argv[i], "${WORKDIR}"))
      argv[i] = workdir;
    else if(!strcmp(argv[i], "${PARALLEL}"))
      argv[i] = "2";
  }

  return job_run_command(j, argv, 0);
}


/**
 *
 */
int
dotdoozer_build(job_t *j)
{
  char path[PATH_MAX];
  snprintf(path, sizeof(path),
           "%s/repo/checkout/.doozer.json", j->projectdir_external);

  int fd = open(path, O_RDONLY);
  if(fd == -1)
    return DOOZER_SKIP;

  struct stat st;
  if(fstat(fd, &st)) {
    snprintf(j->errmsg, sizeof(j->errmsg),
             "Unable to stat() %s -- %s", path, strerror(errno));
    close(fd);
    return DOOZER_TEMPORARY_FAIL;
  }

  char *mem = talloc_malloc(st.st_size + 1);
  if(mem == NULL) {
    snprintf(j->errmsg, sizeof(j->errmsg), "Unable to malloc(%zd)",
             st.st_size + 1);
    close(fd);
    return DOOZER_TEMPORARY_FAIL;
  }

  if(read(fd, mem, st.st_size) != st.st_size) {
    snprintf(j->errmsg, sizeof(j->errmsg), "read error -- %s",
             strerror(errno));
    close(fd);
    return DOOZER_TEMPORARY_FAIL;
  }

  close(fd);

  mem[st.st_size] = 0;

  htsmsg_t *doc = htsmsg_json_deserialize(mem, j->errmsg, sizeof(j->errmsg));
  if(doc == NULL)
    return DOOZER_PERMANENT_FAIL;

  htsmsg_t *targets = htsmsg_get_map(doc, "targets");
  if(targets == NULL) {
    snprintf(j->errmsg, sizeof(j->errmsg),
             "'targets' missing in .doozer.json");
    htsmsg_destroy(doc);
    return DOOZER_PERMANENT_FAIL;
  }

  htsmsg_t *target = htsmsg_get_map(targets, j->target);
  if(target == NULL) {
    snprintf(j->errmsg, sizeof(j->errmsg),
             "'targets' does not contain '%s' in .doozer.json", j->target);
    htsmsg_destroy(doc);
    return DOOZER_PERMANENT_FAIL;
  }

  int rval = dotdoozer_parse(j, target);
  if(!rval)
    rval = dotdoozer_prep_buildenv(j);

  if(!rval)
    rval = dotdoozer_do_build(j, target);

  htsmsg_destroy(doc);
  return rval;
}
