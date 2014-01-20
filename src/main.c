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

#include <sys/types.h>
#include <regex.h>

#include "heap.h"


struct heapmgr *projects_heap_mgr;
struct heapmgr *buildenv_heap_mgr;
int build_uid = -1;
int build_gid = -1;

static int running = 1;
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

  const char *user  = cfg_get_str(root, CFG("user"),  NULL);
  const char *group = cfg_get_str(root, CFG("group"), NULL);

  if(user != NULL) {
    const struct passwd *p = getpwnam(user);
    if(p == NULL) {
      trace(LOG_ERR, "Unable to find UID for user %s. Exiting", user);
      exit(1);
    }
    build_uid = p->pw_uid;
  }

  if(group != NULL) {
    const struct group *g = getgrnam(group);

    if(g == NULL) {
      trace(LOG_ERR, "Unable to find GID for group %s. Exiting", group);
      exit(1);
    }
    build_gid = g->gr_gid;
  }
}


/**
 *
 */
static void
create_heaps(void)
{
  cfg_root(root);

  const char *projects_dir = cfg_get_str(root, CFG("projectsdir"), NULL);
  if(projects_dir == NULL) {
    trace(LOG_ERR, "No projectsdir configured, giving up");
    exit(1);
  }


#ifdef linux
  projects_heap_mgr = heap_btrfs_init(projects_dir);
#endif

  if(projects_heap_mgr == NULL)
    projects_heap_mgr = heap_simple_init(projects_dir);

  if(projects_heap_mgr == NULL) {

    trace(LOG_ERR, "No heap manager for projects in %s, giving up",
          projects_dir);
    exit(1);
  }
}


/**
 *
 */
int
main(int argc, char **argv)
{
  int c;
  sigset_t set;
  const char *cfgfile = NULL;

  const char *defconf = "agent.json";

  signal(SIGPIPE, handle_sigpipe);

  while((c = getopt(argc, argv, "c:s:")) != -1) {
    switch(c) {
    case 'c':
      cfgfile = optarg;
      break;
    case 's':
      enable_syslog("doozer", optarg);
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

  get_uid_gid();

  create_heaps();

  if(build_gid != -1) {
    if(setgid(build_gid)) {
      trace(LOG_ERR, "Unable to setgid(%d) -- %s", build_gid,
            strerror(errno));
      exit(1);
    }
  }

  if(build_uid != -1) {
    if(seteuid(build_uid)) {
      trace(LOG_ERR, "Unable to seteuid(%d) -- %s", build_uid,
            strerror(errno));
    }
  }

  git_threads_init();

  artifact_init();

  agent_init();

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

  return 0;
}
