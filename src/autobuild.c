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

#include <openssl/sha.h>

#include "libsvc/htsmsg.h"
#include "libsvc/misc.h"
#include "libsvc/trace.h"
#include "libsvc/htsbuf.h"

#include "job.h"
#include "git.h"
#include "autobuild.h"
#include "artifact.h"


/**
 *
 */
static int
autobuild_query_env(job_t *j)
{
  int r;
  char line[1024] = {};

  r = job_run_command(j, (const char *[]){"./Autobuild.sh", "-v", NULL}, 0);
  if(r)
    return r;


  htsbuf_read(&j->buildlog, line, sizeof(line) - 1);
  htsbuf_queue_flush(&j->buildlog);
  j->autobuild_version = atoi(line);

  if(j->autobuild_version != 3) {
    // This is the only version we support right now
    snprintf(j->errmsg, sizeof(j->errmsg),
             "Unsupported autobuild version %d",
             j->autobuild_version);
    return DOOZER_PERMANENT_FAIL;
  }

  j->modified_buildenv[0] = 0;

  r = job_run_command(j,
                      (const char *[]){"./Autobuild.sh",
                          "-t", j->target,
                          "-o", "buildenv",
                          NULL},
                      0);
  if(r)
    return 0;

  htsbuf_read(&j->buildlog, line, sizeof(line) - 1);
  htsbuf_queue_flush(&j->buildlog);

  uint8_t sha1_digest[20];

  SHA1((void *)line, strlen(line), sha1_digest);
  bin2hex(j->modified_buildenv, sizeof(j->modified_buildenv),
          sha1_digest, sizeof(sha1_digest));
  return 0;
}


/**
 *
 */
static int
autobuild_prep_env(job_t *j)
{
  int r;

  r = job_run_command(j,
                      (const char *[]){"./Autobuild.sh",
                          "-t", j->target, "-o", "deps", NULL},
                      JOB_RUN_AS_ROOT);
  return r;
}


/**
 *
 */
static int
autobuild_build(job_t *j)
{
  int r;

  char workdir[PATH_MAX];
  snprintf(workdir, sizeof(workdir), "%s/workdir",
           j->projectdir_internal);

  r = job_run_command(j,
                      (const char *[]){"./Autobuild.sh",
                          "-t", j->target,
                          "-o", "build",
                          "-w", workdir,
                          NULL},
                      0);
  return r;
}



int
autobuild_probe(job_t *j)
{
  char autobuild[PATH_MAX];
  snprintf(autobuild, sizeof(autobuild),
           "%s/repo/checkout/Autobuild.sh", j->projectdir_external);

  if(!access(autobuild, X_OK)) {

    j->query_env = autobuild_query_env;
    j->prep_env  = autobuild_prep_env;
    j->build     = autobuild_build;
    return 0;
  }
  return 1;
}
