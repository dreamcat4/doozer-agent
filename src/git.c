#include <unistd.h>
#include <stdio.h>
#include <limits.h>
#include <git2.h>

#include "libsvc/trace.h"

#include "agent.h"
#include "job.h"
#include "git.h"

/**
 *
 */
static const char *
giterr(void)
{
  const git_error *ge = giterr_last();
  if(ge == NULL)
    return "Unknown GIT error";
  return ge->message;
}

/**
 *
 */
static int
update_cb(const char *refname, const git_oid *a, const git_oid *b, void *data)
{
  char a_str[GIT_OID_HEXSZ+1], b_str[GIT_OID_HEXSZ+1];

  git_oid_fmt(b_str, b);
  b_str[GIT_OID_HEXSZ] = '\0';

  if(git_oid_iszero(a)) {
    printf("GIT: [new]     %.20s %s\n", b_str, refname);
  } else {
    git_oid_fmt(a_str, a);
    a_str[GIT_OID_HEXSZ] = '\0';
    printf("GIT: [updated] %.10s..%.10s %s\n",
         a_str, b_str, refname);
  }
  return 0;
}

/**
 *
 */
static int
progress_cb(const char *str, int len, void *data)
{
  printf("remote: %.*s", len, str);
  fflush(stdout); /* We don't have the \n to force the flush */

  if(!running)
    return 1;
  return 0;
}


/**
 *
 */
static int
cred_acquire_cb(git_cred **out,
		const char *url,
		const char *username_from_url,
		unsigned int allowed_types,
		void *payload)
{
  if(allowed_types & GIT_CREDTYPE_SSH_KEY) {
    return git_cred_ssh_key_new(out, username_from_url,
                                "/tmp/id_rsa.pub", "/tmp/id_rsa", "");
  }
  return -1;

#if 0
  project_t *p = payload;

  project_cfg(pc, p->p_id);
  if(pc == NULL)
    return -1;

  const char *username = cfg_get_str(pc, CFG("gitrepo", "username"),
				     username_from_url);

  if(allowed_types & GIT_CREDTYPE_USERPASS_PLAINTEXT) {
    const char *password = cfg_get_str(pc, CFG("gitrepo", "password"),
				       NULL);
    
    if(password != NULL) {
      plog(p, "git/repo", "Trying password authentication");
      return git_cred_userpass_plaintext_new(out, username, password);
    }
  }


  if(allowed_types & GIT_CREDTYPE_SSH_KEY) {

    const char *home = getenv("HOME");
    char buf_pub_path[PATH_MAX];
    char buf_priv_path[PATH_MAX];
    const char *priv_path = NULL;
    const char *pub_path = NULL;

    if(home != NULL) {
      snprintf(buf_pub_path, PATH_MAX, "%s/.ssh/id_rsa.pub", home);
      snprintf(buf_priv_path, PATH_MAX, "%s/.ssh/id_rsa", home);
      if(!access(buf_pub_path, R_OK) && !access(buf_priv_path, R_OK)) {
	pub_path  = buf_pub_path;
	priv_path = buf_priv_path;
      } else {
	snprintf(buf_pub_path, PATH_MAX, "%s/.ssh/id_dsa.pub", home);
	snprintf(buf_priv_path, PATH_MAX, "%s/.ssh/id_dsa", home);
	if(!access(buf_pub_path, R_OK) && !access(buf_priv_path, R_OK)) {
	  pub_path  = buf_pub_path;
	  priv_path = buf_priv_path;
	}
      }
    }

    pub_path  = cfg_get_str(pc, CFG("gitrepo", "ssh", "pubPath"),  pub_path);
    priv_path = cfg_get_str(pc, CFG("gitrepo", "ssh", "privPath"), priv_path);
    const char *pw = cfg_get_str(pc, CFG("gitrepo", "ssh", "password"), NULL);

    if(pub_path != NULL && priv_path != NULL) {
      plog(p, "git/repo", "Trying SSH key authentication");
      return git_cred_ssh_key_new(out, username, pub_path, priv_path, pw);
    }
  }
  plog(p, "git/repo", "No available authentication methods");
#endif
  return -1;
}


/**
 *
 */
static int
repo_fetch(git_repository *repo, job_t *j)
{
  const char *refspec = "+refs/*:refs/*";

  git_remote *r;
  if(git_remote_create_inmemory(&r, repo, refspec, j->repourl) < 0) {
    snprintf(j->errmsg, sizeof(j->errmsg),
             "GIT: Unable to create in-memory remote");
    return DOOZER_TEMPORARY_FAIL;
  }

  job_report_status(j, "building", "GIT: Fetch from %s", j->repourl);

  git_remote_callbacks callbacks = GIT_REMOTE_CALLBACKS_INIT;

  callbacks.update_tips = &update_cb;
  callbacks.payload = j;
  if(isatty(1))
    callbacks.progress = &progress_cb;

  callbacks.credentials = &cred_acquire_cb;

  git_remote_set_callbacks(r, &callbacks);
  git_remote_set_autotag(r, GIT_REMOTE_DOWNLOAD_TAGS_AUTO);

  if(git_remote_connect(r, GIT_DIRECTION_FETCH) < 0) {
    snprintf(j->errmsg, sizeof(j->errmsg),
             "GIT: Unable to connect to %s -- %s",
             j->repourl, giterr());
    git_remote_free(r);
    return DOOZER_TEMPORARY_FAIL;
  }

  if(git_remote_download(r) < 0) {
    snprintf(j->errmsg, sizeof(j->errmsg),
             "GIT: Unable to download from %s -- %s",
             j->repourl, giterr());
    git_remote_disconnect(r);
    git_remote_free(r);
    return DOOZER_TEMPORARY_FAIL;
  }

  int err = git_remote_update_tips(r);
  git_remote_disconnect(r);
  git_remote_free(r);
  if(err < 0) {
    snprintf(j->errmsg, sizeof(j->errmsg),
             "GIT: Unable to update tips from %s -- %s",
             j->repourl, giterr());
    return DOOZER_TEMPORARY_FAIL;
  }

  job_report_status(j, "building", "GIT: Fetched repo from %s", j->repourl);
  return 0;
}


/**
 *
 */
static int
repo_checkout(git_repository *repo, job_t *j, const git_oid *oid)
{
  git_checkout_opts opts = GIT_CHECKOUT_OPTS_INIT;
  git_object *obj;

  opts.checkout_strategy =
    GIT_CHECKOUT_FORCE |
    GIT_CHECKOUT_REMOVE_UNTRACKED |
    GIT_CHECKOUT_REMOVE_IGNORED;


  if(git_object_lookup(&obj, repo, oid, GIT_OBJ_COMMIT))
    return -1;

  int r = git_checkout_tree(repo, obj, &opts);
  git_object_free(obj);

  return r ? -1 : 0;
}


/**
 *
 */
int
git_checkout_repo(job_t *j)
{
  git_repository *repo;
  int err;
  char path[PATH_MAX];
  git_oid oid;

  if(git_oid_fromstr(&oid, j->revision)) {

    snprintf(j->errmsg, sizeof(j->errmsg),
             "GIT: Commit %s is invalid -- %s",
             j->revision, giterr());
    return DOOZER_PERMANENT_FAIL;
  }

  snprintf(path, sizeof(path), "%s/repo/checkout", j->projectdir_external);

  if((err = git_repository_open(&repo, path)) < 0) {
    if(err == GIT_ENOTFOUND) {
      trace(LOG_INFO, "Creating new GIT repo at %s", path);
      err = git_repository_init(&repo, path, 0);
    }
  }

  if(err) {
    snprintf(j->errmsg, sizeof(j->errmsg),
             "GIT: Unable to create GIT repo -- %s", giterr());
    return DOOZER_PERMANENT_FAIL;
  }

  // First try to checkout without doing a fetch, maybe it's possible
  // and in those cases it's faster

  if(repo_checkout(repo, j, &oid)) {

    if((err = repo_fetch(repo, j)) != 0) {
      git_repository_free(repo);
      return err;
    }

    if(repo_checkout(repo, j, &oid)) {

      snprintf(j->errmsg, sizeof(j->errmsg),
               "GIT: Failed to checkout %s -- %s",
               j->revision, giterr());
      git_repository_free(repo);
      return DOOZER_TEMPORARY_FAIL;
    }
  }
  git_repository_free(repo);

  job_report_status(j, "building", "GIT: Checked out %s",
                    j->revision);

  return 0;
}
