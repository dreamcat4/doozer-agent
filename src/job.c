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
#include <dirent.h>

#include "libsvc/htsmsg.h"
#include "libsvc/htsmsg_json.h"
#include "libsvc/misc.h"
#include "libsvc/trace.h"
#include "libsvc/htsbuf.h"
#include "libsvc/misc.h"
#include "libsvc/talloc.h"

#include "job.h"
#include "heap.h"
#include "git.h"
#include "artifact.h"
#include "dotdoozer.h"
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

  trace(LOG_INFO, "Project: %s (%s): %s: %s",
        j->project ?: "<Unknown project>",
        j->version ?: "<Unknown version>",
        status0, msg0);

  if(j->bm == NULL)
    return;

  char status[64];
  char msg[512];

  url_escape(status, sizeof(status), status0, URL_ESCAPE_PARAM);
  url_escape(msg,    sizeof(msg),    msg0,    URL_ESCAPE_PARAM);


  for(int i = 0; i < 10; i++) {

    char *r = call_buildmaster(j->bm, 0,
                               "report?jobid=%d&jobsecret=%s&status=%s&msg=%s",
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



#define ARTIFACT_GZIP              0x1
#define ARTIFACT_ALREADY_VERSIONED 0x2

/**
 *
 */
static int
intercept_doozer_artifact(job_t *j, const char *a, int flags,
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
  const char *origpath    = localpath;
  char newpath[PATH_MAX];

  if(localpath[0] == '/') {

    /**
     * Convert from internal path (inside chroot which the build sees)
     * to external path (that which we see)
     */

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

  /**
   * Ok, verify that the path is actually inside the build area.
   *
   * We use realpath(3), thus user is allowed to use a few ../ in the path, etc
   * as long as it does not escape the rootenv
   */

  int follow_cnt = 0;

  while(1) {

    if(follow_cnt == 10) {
      snprintf(errbuf, errlen, "Too many symbolic links at %s",
               origpath);
      return DOOZER_PERMANENT_FAIL;
    }

    char localrealpath[PATH_MAX];
    if(realpath(localpath, localrealpath) == NULL) {
      snprintf(errbuf, errlen, "Invalid artifact path %s -- %s",
               localpath, strerror(errno));
      return DOOZER_PERMANENT_FAIL;
    }

    if(mystrbegins(localrealpath, j->projectdir_external) == NULL) {
      snprintf(errbuf, errlen, "Invalid artifact path %s -- Not within build area",
               localpath);
      return DOOZER_PERMANENT_FAIL;
    }

    localpath = localrealpath;

    struct stat st;
    if(lstat(localpath, &st)) {
      snprintf(errbuf, errlen, "Invalid artifact path %s -- %s",
               localpath, strerror(errno));
      return DOOZER_PERMANENT_FAIL;
    }

    if(S_ISREG(st.st_mode)) {
      break;
    } else if(S_ISLNK(st.st_mode)) {
      if(readlink(localpath, newpath, sizeof(newpath)) == -1) {
        snprintf(errbuf, errlen, "Unable to follow symbolc link %s -- %s",
                 localpath, strerror(errno));
        return DOOZER_PERMANENT_FAIL;
      }

      localpath = newpath;
      follow_cnt++;
      continue;

    } else {
      snprintf(errbuf, errlen, "Unable to send %s -- Not a regular file",
               localpath);
      return DOOZER_PERMANENT_FAIL;
    }
  }


  if(!(flags & ARTIFACT_ALREADY_VERSIONED)) {

    char newfilename[PATH_MAX];

    char *file_ending = strrchr(filename, '.');
    if(file_ending != NULL)
      *file_ending++ = 0;

    snprintf(newfilename, sizeof(newfilename),
             "%s-%s%s%s",
             filename, j->version,
             file_ending ? "." : "",
             file_ending ?: "");
    filename = newfilename;
  }

  if(artifact_add_file(j, filetype, filename, contenttype,
                       localpath, !!(flags & ARTIFACT_GZIP), errbuf, errlen))
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
    err = intercept_doozer_artifact(j, a, ARTIFACT_GZIP, errbuf, errlen);
  else if((a = mystrbegins(line, "doozer-versioned-artifact:")) != NULL)
    err = intercept_doozer_artifact(j, a, ARTIFACT_ALREADY_VERSIONED,
                                    errbuf, errlen);
  return err;
}

static int job_terminated = 0;

/**
 *
 */
static void
jobterm(int x)
{
  job_terminated = 1;
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
#if 0
    snprintf(path, sizeof(path), "%s/proc", j->buildenvdir);
    if(mount("proc", path, "proc", 0, "")) {
      fprintf(stderr, "Unable to mount proc on %s -- %s\n",
              path, strerror(errno));
      return 1;
    }
#endif

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


  if(getpid() == 1) {
    // We run in an isolated pid space

    pid_t newpid = fork();
    if(newpid == -1) {
      fprintf(stderr, "Unable to fork -- %s\n", strerror(errno));
      return 1;
    }

    if(newpid != 0) {
      int status;
      sigset_t set;

      sigemptyset(&set);
      sigaddset(&set, SIGTERM);

      struct sigaction sa = {};
      sa.sa_handler = jobterm;
      sigaction(SIGTERM, &sa, NULL);

      pthread_sigmask(SIG_UNBLOCK, &set, NULL);

      while(1) {
        pid_t p = waitpid(newpid, &status, 0);

        if(p == -1) {

          if(errno == EINTR) {
            if(job_terminated) {
              break;
            } else {
              continue;
            }
          }
          fprintf(stderr, "wait() error -- %s\n", strerror(errno));
        }
        break;
      }

      // Kill off any remaining processes in this PID space
      kill(-1, SIGKILL);

      while(1) {
        int status;
        pid_t p = waitpid(-1, &status, WNOHANG);
        if(p <= 0)
          break;
        fprintf(stderr, "Collected pid %d\n", p);
      }

      if(job_terminated) {
        fprintf(stderr, "Job aborted\n");
        return 1;
      }

      if(WIFEXITED(status)) {
        return WEXITSTATUS(status);
      } else if(WIFSIGNALED(status)) {
#ifdef WCOREDUMP
        if(WCOREDUMP(status)) {
          fprintf(stderr, "Core dumped\n");
        }
#endif
        fprintf(stderr, "Terminated with signal %d\n", WTERMSIG(status));
      } else {
        fprintf(stderr, "Exited with statucode %d\n", status);
      }
      return 1;
    }
    setsid();
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

  extern char **environ;

  environ = (void *)envp;
  execvp(aux->argv[0], (void *)aux->argv);
  fprintf(stderr, "Unable to execute %s -- %s\n",
          aux->argv[0], strerror(errno));
  return 127;
}


/**
 *
 */
static const char *
joinarray(const char **argv, int argc)
{
  int len = 0;

  if(argc == -1) {
    argc = 0;
    for(int i = 0; argv[i] != NULL; i++) {
      len += strlen(argv[i]) + 1;
      argc++;
    }

  } else {

  for(int i = 0; i < argc; i++)
    len += strlen(argv[i]) + 1;

  }

  if(len == 0)
    return "";

  char *r = talloc_malloc(len);
  char *x = r;
  for(int i = 0; i < argc; i++) {
    int a = strlen(argv[i]);
    memcpy(x, argv[i], a);
    x[a] = ' ';
    x += a + 1;
  }
  x[-1] = 0;
  return r;
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

  job_report_status(j, "building", "Running: %s", joinarray(argv, -1));

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
job_run(job_t *j)
{
  int r;
  // Checkout from GIT
  if((r = git_checkout_repo(j)) != 0)
    return r;

  // A return value of '1' mean that this method does not apply on this repo
  if((r = dotdoozer_build(j)) != DOOZER_SKIP)
    return r;

  snprintf(j->errmsg, sizeof(j->errmsg),
           "No clue how to build from this repo");
  return DOOZER_PERMANENT_FAIL;
}


/**
 *
 */
static void
remove_files_in_dir(const char *path)
{

  struct dirent **namelist;
  int n;

  n = scandir(path, &namelist, NULL, alphasort);
  if(n < 0)
    return;

  while(n--) {
    char path2[PATH_MAX];
    snprintf(path2, sizeof(path2), "%s/%s", path, namelist[n]->d_name);
    unlink(path2);
    free(namelist[n]);
  }
  free(namelist);

}

/**
 *
 */
static void
cleanup_files(job_t *j)
{
  char path[PATH_MAX];
  snprintf(path, sizeof(path), "%s/repo", j->projectdir_external);
  remove_files_in_dir(path);
  snprintf(path, sizeof(path), "%s", j->projectdir_external);
  remove_files_in_dir(path);
}

/**
 *
 */
void
job_process(buildmaster_t *bm, htsmsg_t *msg)
{
  job_t j = {};
  j.bm = bm;
  j.jobmsg = msg;

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

  if(bm != NULL) {
    j.jobsecret = htsmsg_get_str(msg, "jobsecret");
    if(j.jobsecret == NULL) {
      trace(LOG_ERR, "Job has no jobsecret");
      return;
    }
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

  cleanup_files(&j);

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

  cleanup_files(&j);

  htsbuf_queue_flush(&j.buildlog);
  pthread_cond_destroy(&j.artifact_cond);
  assert(LIST_FIRST(&j.artifacts) == NULL);
}
