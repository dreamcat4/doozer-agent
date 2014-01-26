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
int
autobuild_process(job_t *j)
{
  int r;
  r = job_run_command(j, (const char *[]){j->autobuild, "-v", NULL}, 0);
  if(r)
    return r;

  char line[64] = {};

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


  r = job_run_command(j,
                      (const char *[]){j->autobuild,
                          "-t", j->target, "-o", "deps", NULL},
                      0);
  if(r)
    return r;

  r = job_run_command(j,
                      (const char *[]){j->autobuild,
                          "-t", j->target, "-o", "build", NULL},
                      0);

  return r;
}
