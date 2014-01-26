#include "job.h"
#include "makefile.h"
#include "artifact.h"

/**
 *
 */
int
makefile_process(job_t *j)
{
  return job_run_command(j, (const char *[]){"/usr/bin/env", "make", NULL}, 0);
}
