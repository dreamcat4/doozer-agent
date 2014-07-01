#include <sys/mman.h>
#include <sys/param.h>
#include <sys/wait.h>
#include <assert.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <poll.h>
#include <signal.h>

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
#include "libsvc/misc.h"

#include "job.h"
#include "heap.h"
#include "git.h"
#include "artifact.h"
#include "autobuild.h"
#include "doozerctrl.h"
#include "makefile.h"
#include "buildenv.h"

#include <sys/mount.h>


/**
 *
 */
static void
job_report_status_va(job_t *j, const char *status0, const char *fmt, va_list ap)
{
  char msg0[512];
  vsnprintf(msg0, sizeof(msg0), fmt, ap);

  char status[64];
  char msg[512];

  url_escape(status, sizeof(status), status0, URL_ESCAPE_PARAM);
  url_escape(msg,    sizeof(msg),    msg0,    URL_ESCAPE_PARAM);

  trace(LOG_INFO, "Project: %s (%s): %s: %s",
        j->project ?: "<Unknown project>",
        j->version ?: "<Unknown version>",
        status0, msg0);

  for(int i = 0; i < 10; i++) {

    char *r = call_buildmaster(j->bm, "report?jobid=%d&jobsecret=%s&status=%s&msg=%s",
                               j->jobid, j->jobsecret, status, msg);

    if(r == NULL) {
      trace(LOG_WARNING, "Unable to report status '%s' -- %s. Retrying", status,
            j->bm->last_rpc_error);
      sleep(3);
      continue;
    }

    free(r);
    return;
  }
}


/**
 *
 */
void
job_report_status(job_t *j, const char *status0, const char *fmt, ...)
{
  va_list ap;
  va_start(ap, fmt);
  job_report_status_va(j, status0, fmt, ap);
  va_end(ap);
}


/**
 *
 */
static void
job_report_fail(job_t *j, const char *fmt, ...)
{
  va_list ap;
  va_start(ap, fmt);
  job_report_status_va(j, "failed", fmt, ap);
  va_end(ap);
}


/**
 *
 */
static void
job_report_temp_fail(job_t *j, const char *fmt, ...)
{
  va_list ap;
  va_start(ap, fmt);
  job_report_status_va(j, j->can_temp_fail ? "tempfailed" : "failed", fmt, ap);
  va_end(ap);
}



/**
 *
 */
typedef struct job_run_command_aux {
  job_t *job;
  const char **argv;
  int flags;
} job_run_command_aux_t;


/**
 *
 */
static int
intercept_doozer_artifact(job_t *j, const char *a, int gzipped,
                          char *errbuf, size_t errlen)
{
  char *line = mystrdupa(a);
  char *argv[4];
  if(str_tokenize(line, argv, 4, ':') != 4) {
    snprintf(errbuf, errlen, "Invalid doozer-artifact line");
    return DOOZER_PERMANENT_FAIL;
  }

  const char *localpath   = argv[0];
  const char *filetype    = argv[1];
  const char *contenttype = argv[2];
  const char *filename    = argv[3];

  char newpath[PATH_MAX];

  if(localpath[0] == '/') {

    if(!strncmp(localpath, j->projectdir_internal,
                strlen(j->projectdir_internal))) {

      const char *x = localpath + strlen(j->projectdir_internal);
      snprintf(newpath, sizeof(newpath), "%s%s",
               j->projectdir_external, x);
      localpath = newpath;
    }

  } else {
    snprintf(newpath, sizeof(newpath), "%s/checkout/repo/%s",
             j->projectdir_external, localpath);
    localpath = newpath;
  }

  char newfilename[PATH_MAX];

  char *file_ending = strrchr(filename, '.');
  if(file_ending != NULL)
    *file_ending++ = 0;

  snprintf(newfilename, sizeof(newfilename),
           "%s-%s%s%s",
           filename, j->version,
           file_ending ? "." : "",
           file_ending ?: "");

  if(artifact_add_file(j, filetype, newfilename, contenttype,
                       localpath, gzipped, errbuf, errlen))
    return DOOZER_PERMANENT_FAIL;
  return 0;
}


/**
 *
 */
static int
job_run_command_line_intercept(void *opaque,
                               const char *line,
                               char *errbuf,
                               size_t errlen)
{
  job_run_command_aux_t *aux = opaque;
  job_t *j = aux->job;
  const char *a;
  int err = 0;

  if((a = mystrbegins(line, "doozer-artifact:")) != NULL)
    err = intercept_doozer_artifact(j, a, 0, errbuf, errlen);
  else if((a = mystrbegins(line, "doozer-artifact-gzip:")) != NULL)
    err = intercept_doozer_artifact(j, a, 1, errbuf, errlen);
  return err;
}

/**
 *
 */
static int
job_run_command_spawn(void *opaque)
{
  job_run_command_aux_t *aux = opaque;
  job_t *j = aux->job;
  char path[PATH_MAX];

  if(j->buildenvdir != NULL) {


    linux_cap_change(1, CAP_SYS_ADMIN, -1);

    snprintf(path, sizeof(path), "%s/project", j->buildenvdir);
    if(mount(j->projectdir_external, path, "bind", MS_BIND, "")) {
      fprintf(stderr, "Unable to bind mount %s on %s -- %s\n",
              j->projectdir_external, path, strerror(errno));
      return 1;
    }

    snprintf(path, sizeof(path), "%s/tmp", j->buildenvdir);
    if(mount("tmpfs", path, "tmpfs", 0, "")) {
      fprintf(stderr, "Unable to mount tmpfs on %s -- %s\n",
              path, strerror(errno));
      return 1;
    }

    snprintf(path, sizeof(path), "%s/var/tmp", j->buildenvdir);
    if(mount("tmpfs", path, "tmpfs", 0, "")) {
      fprintf(stderr, "Unable to mount tmpfs on %s -- %s\n",
              path, strerror(errno));
      return 1;
    }

    linux_cap_change(0, CAP_SYS_ADMIN, -1);


    linux_cap_change(1, CAP_SYS_CHROOT, -1);
    if(chroot(j->buildenvdir)) {
      fprintf(stderr, "Unable to chroot to %s -- %s\n",
              j->buildenvdir, strerror(errno));
      return 1;
    }
    linux_cap_change(0, CAP_SYS_CHROOT, -1);
    j->buildenvdir = NULL;
  }

  snprintf(path, sizeof(path), "%s/repo/checkout", j->projectdir_internal);
  if(chdir(path)) {
    fprintf(stderr, "Unable to chdir to %s -- %s\n",
            path, strerror(errno));
    return 1;
  }

  const int as_root = aux->flags & JOB_RUN_AS_ROOT;

  if(build_uid != -1 || as_root) {

    // Become root

    if(setuid(0)) {
      fprintf(stderr, "Unable to setuid(0) -- %s\n",
              strerror(errno));
      return 1;
    }


    if(!as_root) {
      // Then setuid to build_uid

      if(setuid(build_uid)) {
        fprintf(stderr, "Unable to setuid(%d) -- %s\n",
                build_uid, strerror(errno));
        return 1;
      }
    }
  }

  char homevar[PATH_MAX];
  snprintf(homevar, sizeof(homevar), "HOME=%s/home", j->projectdir_internal);

  const char *envp[] = {
    homevar,
    "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
    "TZ=UTC0",
    "USER=nobody",
    "LOGNAME=nobody",
    "LANG=C",
    NULL
  };

  execve(aux->argv[0], (void *)aux->argv, (void *)envp);
  fprintf(stderr, "Unable to execute %s -- %s\n",
          aux->argv[0], strerror(errno));
  return 127;
}


/**
 *
 */
int
job_run_command(job_t *j, const char **argv, int flags)
{
  job_run_command_aux_t aux;
  aux.job = j;
  aux.argv = argv;
  aux.flags = flags;

  char cmdline[1024];
  int l = 0;
  cmdline[0] = 0;
  for(;*argv; argv++)
    l += snprintf(cmdline + l, sizeof(cmdline) - l, "%s%s",
                  *argv, argv[1] ? " " : "");

  job_report_status(j, "building", "Running: %s", cmdline);

  int spawn_flags = 0;


  return spawn(job_run_command_spawn,
               job_run_command_line_intercept,
               &aux, &j->buildlog, 600, spawn_flags,
               j->errmsg, sizeof(j->errmsg));
}


/**
 *
 */
static int
job_mkdir(job_t *j,  const char *fmt, ...)
{
  va_list ap;
  char path[PATH_MAX];
  int l = snprintf(path, PATH_MAX, "%s/", j->projectdir_external);

  va_start(ap, fmt);
  vsnprintf(path + l, PATH_MAX - l, fmt, ap);
  va_end(ap);
  int r = makedirs(path);
  if(r) {
    job_report_temp_fail(j, "Unable to create dir %s -- %s",
                         path, strerror(r));
    return -1;
  }
  return 0;
}


/**
 *
 */
static int
job_probe_build(job_t *j)
{
  if(!autobuild_probe(j))
    return 0;

  snprintf(j->errmsg, sizeof(j->errmsg),
           "No clue how to build from this repo");
  return DOOZER_PERMANENT_FAIL;
}



/**
 *
 */
static int
job_run(job_t *j)
{
  int r;
  char buildenv_root[PATH_MAX];

  // Checkout from GIT
  if((r = git_checkout_repo(j)) != 0)
    return r;

  j->projectdir_internal = "/project";

  // Figure out which build strategy to use

  if((r = job_probe_build(j)) != 0)
    return r;

  const char *buildenv_base_id = "base1-precise-amd64";

  if(buildenv_install(j, buildenv_base_id,
                      "/home/andoma/doozerlab/precise-amd64.tar.xz"))
    return DOOZER_PERMANENT_FAIL;


  if(j->query_env != NULL) {

    // Need to run stuff to figure out what build environment to use
    // We do this in a snapshot of the base buildenv

    // First we need to have a base buildenv

    r = buildenv_heap_mgr->clone_heap(buildenv_heap_mgr,
                                      buildenv_base_id,
                                      "current", buildenv_root,
                                      j->errmsg, sizeof(j->errmsg));
    if(r)
      return DOOZER_PERMANENT_FAIL;

    j->buildenvdir = buildenv_root;
    r = j->query_env(j);

    if(r) {
      buildenv_heap_mgr->delete_heap(buildenv_heap_mgr, "current");
      return r;
    }

    if(j->modified_buildenv[0]) {

      buildenv_heap_mgr->delete_heap(buildenv_heap_mgr, "current");

      char buildenv_modified_id[512];

      snprintf(buildenv_modified_id, sizeof(buildenv_modified_id),
               "project1-%s-%s-%s-%s",
               j->project, j->target, j->modified_buildenv,
               buildenv_base_id);

      r = buildenv_heap_mgr->open_heap(buildenv_heap_mgr,
                                       buildenv_modified_id,
                                       buildenv_root,
                                       j->errmsg, sizeof(j->errmsg), 0);
      if(r < 0) {
        r = buildenv_heap_mgr->clone_heap(buildenv_heap_mgr,
                                          buildenv_base_id,
                                          buildenv_modified_id, buildenv_root,
                                          j->errmsg, sizeof(j->errmsg));


        j->buildenvdir = buildenv_root;
        r = j->prep_env(j);

        if(r) {
          buildenv_heap_mgr->delete_heap(buildenv_heap_mgr,
                                         buildenv_modified_id);
          return r;
        }
      }


      r = buildenv_heap_mgr->clone_heap(buildenv_heap_mgr,
                                        buildenv_modified_id,
                                        "current",
                                        buildenv_root,
                                        j->errmsg, sizeof(j->errmsg));

      j->buildenvdir = buildenv_root;

    } else {

      j->buildenvdir = buildenv_root;

      // No way to get buildenv id, just build in current
      r = j->prep_env(j);

    }
  }

  r = j->build(j);
  return r;
}


/**
 *
 */
void
job_process(buildmaster_t *bm, htsmsg_t *msg)
{
  job_t j = {};
  j.bm = bm;


  const char *type = htsmsg_get_str(msg, "type");
  if(type == NULL)
    return;

  if(strcmp(type, "build"))
    return;

  j.jobid = htsmsg_get_u32_or_default(msg, "id", 0);
  if(j.jobid == 0) {
    trace(LOG_ERR, "Job has no jobid");
    return;
  }

  j.jobsecret = htsmsg_get_str(msg, "jobsecret");
  if(j.jobsecret == NULL) {
    trace(LOG_ERR, "Job has no jobsecret");
    return;
  }

  /*
   * From here on we should always report a job status if something fails
   */
  j.can_temp_fail = htsmsg_get_u32_or_default(msg, "can_temp_fail", 0);

  if((j.project = htsmsg_get_str(msg, "project")) == NULL) {
    job_report_temp_fail(&j, "No 'project' field in work");
    return;
  }

  if((j.version = htsmsg_get_str(msg, "version")) == NULL) {
    job_report_temp_fail(&j, "No 'version' field in work");
    return;
  }

  if((j.revision = htsmsg_get_str(msg, "revision")) == NULL) {
    job_report_temp_fail(&j, "No 'revision' field in work");
    return;
  }

  if((j.target = htsmsg_get_str(msg, "target")) == NULL) {
    job_report_temp_fail(&j, "No 'target' field in work");
    return;
  }

  if((j.repourl = htsmsg_get_str(msg, "repo")) == NULL) {
    job_report_temp_fail(&j, "No 'repo' field in work");
    return;
  }

  // Create project heap

  char heapdir[PATH_MAX];
  int r = project_heap_mgr->open_heap(project_heap_mgr,
                                      j.project,
                                      heapdir,
                                      j.errmsg, sizeof(j.errmsg), 1);

  if(r < 0) {
    job_report_fail(&j, "%s", j.errmsg);
    return;
  }
  j.projectdir_internal = heapdir;
  j.projectdir_external = heapdir;

  if(job_mkdir(&j, "checkout/repo"))
    return;

  if(job_mkdir(&j, "workdir"))
    return;

  if(job_mkdir(&j, "home"))
    return;

  LIST_INIT(&j.artifacts);
  pthread_cond_init(&j.artifact_cond, NULL);
  htsbuf_queue_init2(&j.buildlog, 100000);

  int err = job_run(&j);

  if(j.buildlog.hq_size) {
    if(artifact_add_htsbuf(&j, "buildlog", "buildlog",
                           NULL, &j.buildlog, 1)) {
      job_report_temp_fail(&j, "Unable to send buildlog");
      goto cleanup;
    }
  }

  if(artifacts_wait(&j))
    err = DOOZER_PERMANENT_FAIL;

  switch(err) {
  case DOOZER_TEMPORARY_FAIL:
    job_report_temp_fail(&j, "%s",
                         *j.errmsg ? j.errmsg : "No specific message");
    break;
  case DOOZER_PERMANENT_FAIL:
    job_report_fail(&j, "%s",
                    *j.errmsg ? j.errmsg : "No specific message");
    break;
  case 0:
    job_report_status(&j, "done", "Build done");
    break;
  default:
    job_report_fail(&j, "Exited with status %d", err);
    break;
  }
 cleanup:
  htsbuf_queue_flush(&j.buildlog);
  pthread_cond_destroy(&j.artifact_cond);
  assert(LIST_FIRST(&j.artifacts) == NULL);
}
