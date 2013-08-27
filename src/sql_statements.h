#pragma once

#define SQL_GET_ARTIFACT_BY_SHA1 "SELECT storage,payload,project,name,artifact.type,contenttype,encoding FROM artifact,build WHERE artifact.sha1=? AND build.id = artifact.build_id"

#define SQL_INCREASE_DLCOUNT_BY_SHA1 "UPDATE artifact SET dlcount = dlcount + 1 WHERE sha1 = ?"

#define SQL_INCREASE_PATCHCOUNT_BY_SHA1 "UPDATE artifact SET patchcount = patchcount + 1 WHERE sha1 = ?"

#define SQL_GET_TARGETS_FOR_BUILD "SELECT target,id,status FROM build WHERE revision = ? AND project = ? AND branch = ?"

#define SQL_INSERT_BUILD "INSERT INTO build (project,revision,target,type,status,branch,version,no_output) VALUES (?,?,?,?,?,?,?,?)"

#define SQL_ALLOC_BUILD "UPDATE build SET agent=?, status=?, status_change=NOW(), buildstart=NOW(), attempts = attempts + 1, jobsecret=? WHERE id=?"

#define SQL_GET_BUILD_BY_ID "SELECT project,revision,target,type,agent,jobsecret,status,version,branch FROM build WHERE id=?"

#define SQL_INSERT_ARTIFACT "INSERT INTO artifact (build_id, type, payload, storage, name, size, md5, sha1, contenttype, encoding) VALUES (?,?,?,?,?,?,?,?,?,?)"

#define SQL_BUILD_PROGRESS_UPDATE "UPDATE build SET progress_text=?,status_change=NOW() WHERE id=?"

#define SQL_BUILD_FINISHED "UPDATE build SET status=?, progress_text=?,status_change=NOW(),buildend=NOW() WHERE id=?"

#define SQL_GET_EXPIRED_BUILDS "SELECT id,project,revision,agent,attempts FROM build WHERE status='building' AND TIMESTAMPDIFF(MINUTE, status_change, now()) >= ?"

#define SQL_RESTART_BUILD "UPDATE build SET status=?, status_change=NOW(), jobsecret = NULL WHERE id=?"

#define SQL_GET_RELEASES "SELECT id,branch,target,version,revision FROM build INNER JOIN (SELECT max(id) AS id FROM build WHERE status='done' AND project=? GROUP BY target,branch) latest USING (id)"

#define SQL_GET_ARTIFACTS "SELECT id,type,sha1,size,name FROM artifact WHERE build_id = ?"