#include "agent.h"

#include <sys/stat.h>
#include <sys/param.h>
#include <pthread.h>
#include <stdlib.h>
#include <unistd.h>
#include <curl/curl.h>
#include <stdio.h>
#include <stdarg.h>
#include <errno.h>
#include <string.h>
#include <grp.h>

#include "libsvc/cfg.h"
#include "libsvc/trace.h"
#include "libsvc/htsmsg_json.h"
#include "libsvc/misc.h"
#include "libsvc/memstream.h"
#include "libsvc/talloc.h"
#include "libsvc/curlhelpers.h"

#include "agent.h"
#include "job.h"

static int
xferfunc(void *clientp, curl_off_t dltotal, curl_off_t dlnow,
         curl_off_t ultotal, curl_off_t ulnow)
{
  return !running;
}


#define BM_FLAG_STOPPABLE 0x1

/**
 *
 */
static char *
call_buildmaster0(buildmaster_t *bm, int flags, const char *accepthdr,
                  const char *path, va_list ap)
{
  char *out = NULL;
  size_t outlen;
  char url[2048];
  int l = snprintf(url, sizeof(url), "%s/buildmaster/", bm->url);

  vsnprintf(url + l, sizeof(url) - l, path, ap);

  CURL *curl = curl_easy_init();

  FILE *f = open_buffer(&out, &outlen);
  curl_easy_setopt(curl, CURLOPT_URL, url);
  curl_easy_setopt(curl, CURLOPT_USERNAME, bm->agentid);
  curl_easy_setopt(curl, CURLOPT_PASSWORD, bm->secret);
  curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);
  curl_easy_setopt(curl, CURLOPT_WRITEDATA, f);
  curl_easy_setopt(curl, CURLOPT_FAILONERROR, 1L);

  curl_easy_setopt(curl, CURLOPT_OPENSOCKETFUNCTION, &libsvc_curl_sock_fn);
  curl_easy_setopt(curl, CURLOPT_OPENSOCKETDATA, NULL);

  if(flags & BM_FLAG_STOPPABLE) {
    curl_easy_setopt(curl, CURLOPT_XFERINFODATA, &flags);
    curl_easy_setopt(curl, CURLOPT_XFERINFOFUNCTION, &xferfunc);
    curl_easy_setopt(curl, CURLOPT_NOPROGRESS, 0L);
  }

  struct curl_slist *slist = NULL;
  if(accepthdr) {
    char b[128];
    snprintf(b, sizeof(b), "Accept: %s", accepthdr);
    slist = curl_slist_append(slist, b);
  }
  curl_easy_setopt(curl, CURLOPT_HTTPHEADER, slist);

  CURLcode result = curl_easy_perform(curl);

  curl_slist_free_all(slist);

  if(result == CURLE_HTTP_RETURNED_ERROR) {
    long http_code = 0;
    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &http_code);
    snprintf(bm->rpc_errbuf, sizeof(bm->rpc_errbuf), "HTTP Error %lu", http_code);
    bm->last_rpc_error = bm->rpc_errbuf;
  } else {
    bm->last_rpc_error = curl_easy_strerror(result);
  }

  fwrite("", 1, 1, f);
  fclose(f);
  curl_easy_cleanup(curl);
  if(result) {
    free(out);
    return NULL;
  }
  return out;
}

/**
 *
 */
char *
call_buildmaster(buildmaster_t *bm, int flags, const char *path, ...)
{
  va_list ap;
  va_start(ap, path);
  char *r = call_buildmaster0(bm, flags, NULL, path, ap);
  va_end(ap);
  return r;
}


/**
 *
 */
static htsmsg_t *
call_buildmaster_json(buildmaster_t *bm, int flags, const char *path, ...)
{
  va_list ap;
  va_start(ap, path);
  char *r = call_buildmaster0(bm, flags, "application/json", path, ap);
  va_end(ap);

  if(r == NULL)
    return NULL;
  htsmsg_t *m = htsmsg_json_deserialize(r, bm->rpc_errbuf, sizeof(bm->rpc_errbuf));
  free(r);
  if(m == NULL)
    bm->last_rpc_error = bm->rpc_errbuf;
  return m;
}




/**
 *
 */
static int
getjob(buildmaster_t *bm)
{
  char buf[4096];
  int off = 0;
  const char *query = NULL;
  cfg_root(root);


  cfg_t *cmsg = cfg_get_map(root, "buildenvs");

  if(cmsg == NULL) {
    cmsg = cfg_get_map(root, "targets");
    if(cmsg == NULL) {
      trace(LOG_ERR, "No targets nor buildenvs configured");
      return -1;
    }
    query = "targets";
  } else {
    query = "buildenvs";
  }

  htsmsg_field_t *f;
  HTSMSG_FOREACH(f, cmsg) {
    htsmsg_t *sub = htsmsg_get_map_by_field(f);
    if(sub == NULL)
      continue;

    off += snprintf(buf + off, sizeof(buf) - off, "%s%s",
                    off ? "," : "", f->hmf_name);
  }


  if(off == 0) {
    trace(LOG_ERR, "No %s configured", query);
    return -1;
  }

  htsmsg_t *msg;
  msg = call_buildmaster_json(bm, BM_FLAG_STOPPABLE, "getjob?%s=%s",
                              query, buf);
  if(msg == NULL) {
    if(running)
      trace(LOG_ERR, "Unable to getjob -- %s", bm->last_rpc_error);
    return -1;
  }
  job_process(bm, msg);
  htsmsg_destroy(msg);
  return 0;
}


/**
 *
 */
static int
agent_run(void)
{
  buildmaster_t bm = {};

  cfg_root(root);

  bm.url     = cfg_get_str(root, CFG("buildmaster", "url"), NULL);
  bm.agentid = cfg_get_str(root, CFG("buildmaster", "agentid"), NULL);
  bm.secret  = cfg_get_str(root, CFG("buildmaster", "secret"), NULL);

  if(bm.url == NULL) {
    trace(LOG_ERR, "Missing configuration buildmaster.url");
    return -1;
  }

  if(bm.agentid == NULL) {
    trace(LOG_ERR, "Missing configuration buildmaster.agentid");
    return -1;
  }

  if(bm.secret == NULL) {
    trace(LOG_ERR, "Missing configuration buildmaster.secret");
    return -1;
  }

  char *msg = call_buildmaster(&bm, 0, "hello");
  if(msg == NULL) {
    trace(LOG_ERR, "Not welcomed by buildmaster -- %s",
          bm.last_rpc_error);
    return -1;
  }
  free(msg);
  trace(LOG_DEBUG, "Welcomed by buildmaster");

  while(running) {

    if(getjob(&bm))
      return -1;

    talloc_cleanup();
  }
  talloc_cleanup();

  return 0;
}


/**
 *
 */
static void *
agent_main(void *aux)
{
  int sleeper = 1;
  while(running) {

    talloc_cleanup();

    if(agent_run()) {
      if(!running)
        return NULL;

      sleeper = MIN(120, sleeper * 2);
      trace(LOG_ERR, "An error occured, sleeping for %d seconds", sleeper);

      talloc_cleanup();

      for(int i = 0; i < sleeper * 10; i++) {
        if(!running)
          return NULL;
        usleep(100000);
      }
    } else {
      sleeper = 1;
    }
  }
  return NULL;
}

pthread_t agent_tid;


/**
 *
 */
void
agent_init(void)
{
  pthread_create(&agent_tid, NULL, agent_main, NULL);
}

/**
 *
 */
void
agent_join(void)
{
  pthread_join(agent_tid, NULL);
}
