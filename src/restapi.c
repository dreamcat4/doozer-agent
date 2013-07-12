#include <string.h>
#include <stdio.h>

#include "net/http.h"
#include "misc/htsmsg_json.h"

#include "github.h"
#include "cfg.h"
#include "project.h"
#include "db.h"
#include "restapi.h"


#define API_NO_DATA ((htsmsg_t *)-1)
#define API_ERROR   NULL

#define BUILD_MSG_FIELDS "id,revision,target,version, " \
  "branch,type,status,created, buildstart, buildend, status_change," \
  "agent,progress_text"

/**
 *
 */
static htsmsg_t *
build_to_htsmsg(MYSQL_STMT *q)
{
  int id;
  char revision[64];
  char target[64];
  char version[64];
  char branch[128];
  char type[128];
  char status[128];
  time_t created;
  time_t build_start;
  time_t build_end;
  time_t status_change;
  char agent[64];
  char progress[1024];
  int r = db_stream_row(0, q,
                        DB_RESULT_INT(id),
                        DB_RESULT_STRING(revision),
                        DB_RESULT_STRING(target),
                        DB_RESULT_STRING(version),
                        DB_RESULT_STRING(branch),
                        DB_RESULT_STRING(type),
                        DB_RESULT_STRING(status),
                        DB_RESULT_TIME(created),
                        DB_RESULT_TIME(build_start),
                        DB_RESULT_TIME(build_end),
                        DB_RESULT_TIME(status_change),
                        DB_RESULT_STRING(agent),
                        DB_RESULT_STRING(progress));

  if(r < 0)
    return NULL;

  if(r)
    return API_NO_DATA;

  htsmsg_t *m = htsmsg_create_map();
  htsmsg_add_u32(m, "id",           id);
  htsmsg_add_str(m, "revision",      revision);
  htsmsg_add_str(m, "target",        target);
  htsmsg_add_str(m, "version",       version);
  htsmsg_add_str(m, "branch",        branch);
  htsmsg_add_str(m, "type",          type);
  htsmsg_add_str(m, "status",        status);
  if(created)
    htsmsg_add_u32(m, "created",       created);
  if(build_start)
    htsmsg_add_u32(m, "build_start",   build_start);
  if(build_end)
    htsmsg_add_u32(m, "build_end",     build_end);
  if(status_change)
    htsmsg_add_u32(m, "status_change", status_change);
  htsmsg_add_str(m, "agent",         agent);
  if(*progress)
    htsmsg_add_str(m, "progress_text", progress);
  return m;
}



#define ARTIFACT_MSG_FIELDS "id,created,name,type,size,md5,sha1," \
  "dlcount,contenttype,encoding"
/**
 *
 */
static htsmsg_t *
artifact_to_htsmsg(MYSQL_STMT *q, const char *artifact_prefix)
{
  int id;
  time_t created;
  char name[256];
  char type[64];
  int size;
  char md5[33];
  char sha1[41];
  int dlcount;
  char contenttype[256];
  char encoding[256];

  int r = db_stream_row(0, q,
                        DB_RESULT_INT(id),
                        DB_RESULT_TIME(created),
                        DB_RESULT_STRING(name),
                        DB_RESULT_STRING(type),
                        DB_RESULT_INT(size),
                        DB_RESULT_STRING(md5),
                        DB_RESULT_STRING(sha1),
                        DB_RESULT_INT(dlcount),
                        DB_RESULT_STRING(contenttype),
                        DB_RESULT_STRING(encoding));
  if(r < 0)
    return NULL;

  if(r)
    return API_NO_DATA;

  htsmsg_t *m = htsmsg_create_map();
  htsmsg_add_u32(m, "id",            id);
  if(created)
    htsmsg_add_u32(m, "created",       created);
  htsmsg_add_str(m, "name",          name);
  htsmsg_add_str(m, "type",          type);
  htsmsg_add_u32(m, "size",          size);
  htsmsg_add_str(m, "md5",           md5);
  htsmsg_add_str(m, "sha1",          sha1);
  htsmsg_add_u32(m, "dlcount",       dlcount);
  htsmsg_add_str(m, "contenttype",   contenttype);
  htsmsg_add_str(m, "encoding",      encoding);

  if(artifact_prefix) {
    char url[1024];
    snprintf(url, sizeof(url), "%s/file/%s", artifact_prefix, sha1);
    htsmsg_add_str(m, "url", url);
  }

  return m;
}


/**
 *
 */
static int
restapi_builds(http_connection_t *hc, int qtype)
{
  const char *project = http_arg_get(&hc->hc_req_args, "project");
  int offset      = http_arg_get_int(&hc->hc_req_args, "offset", 0);
  int limit       = http_arg_get_int(&hc->hc_req_args, "limit", 10);
  char query[1024];
  MYSQL_BIND in[10] = {};

  if(project == NULL)
    return 400;

  conn_t *c = db_get_conn();
  if(c == NULL)
    return 500;

  if(qtype == 0) {
    snprintf(query, sizeof(query),
             "SELECT count(*) "
             "FROM build "
             "WHERE project = ? ");
  } else {

    snprintf(query, sizeof(query),
             "SELECT "BUILD_MSG_FIELDS" "
             "FROM build "
             "WHERE project = ? "
             "ORDER BY created DESC "
             "LIMIT %d "
             "OFFSET %d "
             , limit, offset);
  }

  scoped_db_stmt(q, query);
  if(q == NULL)
    return 500;

  in[0].buffer_type = MYSQL_TYPE_STRING;
  in[0].buffer = (char *)project;
  in[0].buffer_length = strlen(project);

  if(mysql_stmt_bind_param(q, in)) {
    trace(LOG_ERR,
          "Failed to bind parameters to prepared statement %s -- %s",
          mysql_stmt_sqlstate(q), mysql_stmt_error(q));
    return 500;
  }

  if(mysql_stmt_execute(q)) {
    trace(LOG_ERR, "Failed to execute statement %s -- %s",
          mysql_stmt_sqlstate(q), mysql_stmt_error(q));
    return 500;
  }

  if(qtype == 0) {
    int numrows;
    int r = db_stream_row(0, q,
                          DB_RESULT_INT(numrows),
                          NULL);
    if(r)
      return 500;

    htsbuf_qprintf(&hc->hc_reply, "%d", numrows);
    http_output_content(hc, "text/plain");
    return 0;
  }

  htsmsg_t *list = htsmsg_create_list();

  while(1) {
    htsmsg_t *m = build_to_htsmsg(q);
    if(m == NULL)
      return 500;
    if(m == API_NO_DATA)
       break;
    htsmsg_add_msg(list, NULL, m);
  }

  char *json = htsmsg_json_serialize_to_str(list, 1);
  htsmsg_destroy(list);

  htsbuf_append_prealloc(&hc->hc_reply, json, strlen(json));
  http_output_content(hc, "application/json");
  return 0;
}


/**
 *
 */
static int
restapi_builds_count(http_connection_t *hc, const char *remain,
                     void *opaque)
{
  return restapi_builds(hc, 0);
}


/**
 *
 */
static int
restapi_builds_list(http_connection_t *hc, const char *remain,
                    void *opaque)
{
  return restapi_builds(hc, 1);
}


/**
 *
 */
static int
restapi_builds_one(http_connection_t *hc, const char *remain,
                   void *opaque)
{
  cfg_root(root);
  const char *baseurl = cfg_get_str(root, CFG("artifactPrefix"), NULL);

  if(remain == NULL)
    return 404;

  int id = atoi(remain);

  conn_t *c = db_get_conn();
  if(c == NULL)
    return 500;

  htsmsg_t *m;
  {
    scoped_db_stmt(bq, "SELECT "BUILD_MSG_FIELDS" "
                   " FROM build WHERE id = ?");

    if(bq == NULL || db_stmt_exec(bq, "i", id))
      return 500;

    m = build_to_htsmsg(bq);
    if(m == NULL)
      return 500;
    if(m == API_NO_DATA)
      return 404;
  }

  scoped_db_stmt(aq, "SELECT "ARTIFACT_MSG_FIELDS" "
                 " FROM artifact WHERE build_id = ?");

  if(aq == NULL || db_stmt_exec(aq, "i", id))
    return 500;

  htsmsg_t *list = htsmsg_create_list();
  while(1) {
    htsmsg_t *a = artifact_to_htsmsg(aq, baseurl);
    if(a == NULL) {
      htsmsg_destroy(m);
      return 500;
    }
    if(a == API_NO_DATA)
      break;
    htsmsg_add_msg(list, NULL, a);
  }

  htsmsg_add_msg(m, "artifacts", list);

  char *json = htsmsg_json_serialize_to_str(m, 1);
  htsmsg_destroy(m);

  htsbuf_append_prealloc(&hc->hc_reply, json, strlen(json));
  http_output_content(hc, "application/json");
  return 0;
}


/**
 *
 */
void
restapi_init(void)
{
  http_path_add("/restapi/builds.json",  NULL, restapi_builds_list);
  http_path_add("/restapi/builds.count", NULL, restapi_builds_count);
  http_path_add("/restapi/builds",       NULL, restapi_builds_one);
}