#pragma once

#include <pthread.h>
#include <sys/queue.h>

#include "agent.h"
#include "spawn.h"
#include "libsvc/htsbuf.h"

struct htsmsg;

LIST_HEAD(artifact_list, artifact);


/**
 *
 */
typedef struct job {
  struct buildmaster *bm;
  struct artifact_list artifacts;

  pthread_cond_t artifact_cond;

  int jobid;
  int can_temp_fail;

  htsbuf_queue_t buildlog;
  char errmsg[1024];

  const char *jobsecret;
  const char *repourl;
  const char *project;
  const char *version;
  const char *revision;
  const char *target;

  // Various filesystem paths

  const char *projectdir_internal;
  const char *projectdir_external;

  //  const char *repodir;
  //  const char *workdir;
  //  const char *homedir;

  // For autobuild mode
  int autobuild_version;

  // Build environment
  const char *buildenvdir;

  // ID of buildenv as given by the project
  char modified_buildenv[512];

  int (*query_env)(struct job *j);

  int (*prep_env)(struct job *j);

  int (*build)(struct job *j);

} job_t;


void job_report_status(job_t *j, const char *status, const char *fmt, ...)
  __attribute__ ((format (printf, 3, 4)));

void job_process(buildmaster_t *bm, struct htsmsg *msg);

int job_run_command(job_t *j, const char *argv[], int flags);

#define JOB_RUN_AS_ROOT 0x1
