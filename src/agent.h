#pragma once

#include <pwd.h>
#include <grp.h>

extern struct heapmgr *project_heap_mgr;
extern struct heapmgr *buildenv_heap_mgr;
extern int build_uid;
extern int build_gid;
extern int running;

#define DOOZER_PERMANENT_FAIL -1
#define DOOZER_TEMPORARY_FAIL -2
#define DOOZER_SKIP           -3

/**
 *
 */
typedef struct buildmaster {
  const char *url;
  const char *agentid;
  const char *secret;
  const char *last_rpc_error;

  char rpc_errbuf[128];
} buildmaster_t;


void agent_init(void);

void agent_join(void);

char *call_buildmaster(buildmaster_t *bm, int flags, const char *path, ...);


#ifdef linux

#include <linux/capability.h>

void linux_cap_print(void);

void linux_cap_change(int on, ...);

#define UIDGID_OFFSET 10000

#endif
