#pragma once

#include <git2.h>
#include "cfg.h"
#include "doozer.h"

#define PROJECT_JOB_UPDATE_REPO       0x1
#define PROJECT_JOB_CHECK_FOR_BUILDS  0x2
#define PROJECT_JOB_GENERATE_RELEASES 0x4
/**
 *
 */
typedef struct project {

  // --------------------------------------------------
  // These fields are projected with the global project_mutex

  LIST_ENTRY(project) p_link;
  char *p_id;

  pthread_t p_thread;

  int p_pending_jobs;
  int p_active_jobs;
  int p_failed_jobs;

  // --------------------------------------------------
  // --------------------------------------------------

  pthread_mutex_t p_repo_mutex;
  git_repository *p_repo;

} project_t;

project_t *project_get(const char *id);

void projects_reload(void);

void projects_init(void);

void project_schedule_job(project_t *p, int mask);


/**
 * Project specific log
 *
 *  List of "known" contexts
 *
 *   system                          - Various tech and internal
 *
 *   build/check                     - Buildmaster checking
 *   build/queue                     - Modifications to build queue
 *   build/artifact                  - Reception of artifacts
 *   build/status                    - Modification of build status
 *
 *   release/check                   - Releasemaker check
 *   release/manifest/info/<arch>    - JSON manifest updates
 *   release/manifest/publish/<arch> - New relases published in JSON manifest
 *
 *   git/repo                        - Updates to repo
 */
void plog(project_t *p, const char *context, const char *fmt, ...)
 __attribute__ ((format (printf, 3, 4)));
