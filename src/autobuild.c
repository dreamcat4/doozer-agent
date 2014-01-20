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
void
autobuild_process(job_t *j)
{
  htsbuf_queue_t output;
  int r;
  char errbuf[1024];

  htsbuf_queue_init2(&output, 100000);

  r = job_run_command(j,
                      (const char *[]){j->autobuild,
                          "-v", NULL},
                      &output, 0, errbuf, sizeof(errbuf));
  if(r)
    goto done;

  char line[64] = {};

  htsbuf_read(&output, line, sizeof(line) - 1);
  htsbuf_queue_flush(&output);
  j->autobuild_version = atoi(line);

  if(j->autobuild_version != 3) {
    // This is the only version we support right now
    job_report_fail(j, "Unsupported autobuild version %d",
                    j->autobuild_version);
    return;
  }


  r = job_run_command(j,
                      (const char *[]){j->autobuild,
                          "-t", j->target, "-o", "deps", NULL},
                      &output, 0, errbuf, sizeof(errbuf));
  if(r)
    goto done;

  r = job_run_command(j,
                      (const char *[]){j->autobuild,
                          "-t", j->target, "-o", "build", NULL},
                      &output, 0, errbuf, sizeof(errbuf));
  job_run_command(j,
                  (const char *[]){j->autobuild,
                      "-t", j->target, "-o", "clean", NULL},
                  &output, 0, NULL, 0);

 done:
  if(output.hq_size) {
    if(artifact_add_htsbuf(j, "buildlog", "buildlog", NULL, &output, 1)) {
      return;
    }
  }

  if(aritfacts_wait(j))
    return;

  switch(r) {
  case SPAWN_TEMPORARY_FAIL:
    job_report_temp_fail(j, "%s", errbuf);
    break;
  case SPAWN_PERMANENT_FAIL:
    job_report_fail(j, "%s", errbuf);
    break;
  case 0:
    job_report_status(j, "done", "Build done");
    break;
  default:
    job_report_fail(j, "Exited with status %d", r);
    break;
  }
}
