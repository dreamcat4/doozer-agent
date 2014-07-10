#include <sys/param.h>
#include <sys/stat.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>
#include <getopt.h>
#include <fcntl.h>
#include <errno.h>
#include <git2.h>

#include "libsvc/htsmsg_json.h"

#include "libsvc/tcp.h"
#include "libsvc/http.h"
#include "libsvc/trace.h"
#include "libsvc/irc.h"
#include "libsvc/cfg.h"
#include "libsvc/ctrlsock.h"
#include "libsvc/cmd.h"

#include "agent.h"
#include "artifact.h"
#include "spawn.h"

#include <sys/types.h>
#include <regex.h>

#include "heap.h"


struct heapmgr *project_heap_mgr;
struct heapmgr *buildenv_heap_mgr;
int build_uid = -1;
int build_gid = -1;

int running = 1;
static int reload = 0;

/**
 *
 */
static void
handle_sigpipe(int x)
{
  return;
}


/**
 *
 */
static void
doexit(int x)
{
  running = 0;
}


/**
 *
 */
static void
doreload(int x)
{
  reload = 1;
}


/**
 *
 */
static void
get_uid_gid(void)
{
  cfg_root(root);

  const char *user  = cfg_get_str(root, CFG("user"),  "nobody");
  const char *group = cfg_get_str(root, CFG("group"), "nogroup");

  const struct passwd *p = getpwnam(user);
  if(p == NULL) {
    trace(LOG_ERR, "Unable to find UID for user %s. Exiting", user);
    exit(1);
  }
  build_uid = p->pw_uid;

  const struct group *g = getgrnam(group);
  if(g == NULL) {
    trace(LOG_ERR, "Unable to find GID for group %s. Exiting", group);
    exit(1);
  }
  build_gid = g->gr_gid;
}


/**
 *
 */
static heapmgr_t *
create_heap(const char *path)
{
  heapmgr_t *h;
#ifdef linux
  h = heap_btrfs_init(path);
  if(h == NULL)
#endif
    h = heap_simple_init(path);

  if(h == NULL) {
    trace(LOG_ERR, "Unable to crate heap at %s. Giving up", path);
    exit(1);
  }
  return h;
}



/**
 *
 */
static void
create_heaps(void)
{
  cfg_root(root);
  const char *d;

  d = cfg_get_str(root, CFG("projectdir"), NULL);
  if(d == NULL) {
    trace(LOG_ERR, "No 'projectdir' configured, giving up");
    exit(1);
  }
  project_heap_mgr = create_heap(d);

  d = cfg_get_str(root, CFG("buildenvdir"), NULL);
  if(d == NULL) {
    trace(LOG_ERR, "No 'buildenvdir' configured, giving up");
    exit(1);
  }
  buildenv_heap_mgr = create_heap(d);
}


#ifdef linux

#include <sys/syscall.h>

/**
 *
 */
void
linux_cap_print(void)
{
  struct __user_cap_header_struct x;
  struct __user_cap_data_struct s[3] = {};

  x.version = _LINUX_CAPABILITY_VERSION_3;
  x.pid = syscall(SYS_gettid);

  if(syscall(SYS_capget, &x, s)) {
    perror("linux_check_capabilities");
    return;
  }

  printf("  effective: %08x %08x %08x\n",
         s[0].effective, s[1].effective, s[2].effective);

  printf("  permitted: %08x %08x %08x\n",
         s[0].permitted, s[1].permitted, s[2].permitted);

  printf("inheritable: %08x %08x %08x\n",
         s[0].inheritable, s[1].inheritable, s[2].inheritable);

}



/**
 *
 */
void
linux_cap_change(int on, ...)
{
  struct __user_cap_header_struct x;
  struct __user_cap_data_struct s[3] = {};

  x.version = _LINUX_CAPABILITY_VERSION_3;
  x.pid = syscall(SYS_gettid);

  if(syscall(SYS_capget, &x, s)) {
    perror("capget");
    exit(1);
  }

  va_list ap;
  va_start(ap, on);

  int cap;
  while((cap = va_arg(ap, int)) != -1) {

    if(!cap_valid(cap)) {
      fprintf(stderr, "cap %d is not valid\n", cap);
      exit(1);
    }

    if(on) {
      s[CAP_TO_INDEX(cap)].effective |= CAP_TO_MASK(cap);
    } else {
      s[CAP_TO_INDEX(cap)].effective &= ~CAP_TO_MASK(cap);
    }
  }

  if(syscall(SYS_capset, &x, s)) {
    perror("capset");
    exit(1);
  }
}
#endif

#if 0

/**
 *
 */
static void
linux_cap_drop(void)
{
  struct __user_cap_header_struct x;
  struct __user_cap_data_struct s[3] = {};

  x.version = _LINUX_CAPABILITY_VERSION_3;
  x.pid = syscall(SYS_gettid);

  if(syscall(SYS_capget, &x, s)) {
    perror("capget");
    exit(1);
  }

  s[0].effective = 0;
  s[1].effective = 0;
  s[2].effective = 0;


  if(syscall(SYS_capset, &x, s)) {
    perror("capset");
    exit(1);
  }
}

#endif

/**
 *
 */
int
main(int argc, char **argv)
{
  int c;
  sigset_t set;
  const char *cfgfile = NULL;
  const char *jobfile = NULL;
  const char *defconf = "doozer-agent.json";

  signal(SIGPIPE, handle_sigpipe);

  while((c = getopt(argc, argv, "c:s:j:")) != -1) {
    switch(c) {
    case 'c':
      cfgfile = optarg;
      break;
    case 's':
      enable_syslog("doozer-agent", optarg);
      break;
    case 'j':
      jobfile = optarg;
      break;
    }
  }

  sigfillset(&set);
  sigprocmask(SIG_BLOCK, &set, NULL);

  srand48(getpid() ^ time(NULL));

  if(cfg_load(cfgfile, defconf)) {
    fprintf(stderr, "Unable to load config (check -c option). Giving up\n");
    exit(1);
  }

  create_heaps();

  if(geteuid() == 0) {

    get_uid_gid();

    if(setgid(build_gid)) {
      trace(LOG_ERR, "Unable to setgid(%d) -- %s", build_gid,
            strerror(errno));
      exit(1);
    }

    if(seteuid(build_uid)) {
      trace(LOG_ERR, "Unable to seteuid(%d) -- %s", build_uid,
            strerror(errno));
    }
  }

  git_threads_init();

  artifact_init();

  agent_init(jobfile);

  running = 1;
  sigemptyset(&set);
  sigaddset(&set, SIGTERM);
  sigaddset(&set, SIGINT);
  sigaddset(&set, SIGHUP);

  signal(SIGTERM, doexit);
  signal(SIGINT, doexit);
  signal(SIGHUP, doreload);

  pthread_sigmask(SIG_UNBLOCK, &set, NULL);

  while(running) {
    if(reload) {
      reload = 0;
      if(!cfg_load(NULL, defconf)) {
      }
    }
    pause();
  }

  spawn_stop_all();
  trace(LOG_NOTICE, "Waiting for jobs to stop");
  agent_join();
  return 0;
}
