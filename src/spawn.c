#ifdef linux
#define _GNU_SOURCE
#include <sched.h>
#endif


#include <sys/mman.h>
#include <sys/param.h>
#include <sys/wait.h>
#include <assert.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <poll.h>
#include <signal.h>
#include <fcntl.h>
#include <pthread.h>

#include <string.h>
#include <errno.h>
#include <stdlib.h>
#include <limits.h>
#include <unistd.h>
#include <stdio.h>
#include <stdarg.h>

#include <sys/resource.h>

#include "libsvc/htsmsg.h"
#include "libsvc/misc.h"
#include "libsvc/trace.h"
#include "libsvc/htsbuf.h"
#include "libsvc/misc.h"

#include "spawn.h"
#include "agent.h"


#ifdef linux
#define SPAWN_NEW_USER
#endif


LIST_HEAD(args_list, args);

typedef struct args {
  void *opaque;
  int (*exec_cb)(void *opaque);
  LIST_ENTRY(args) link;

  int pipe_stdout[2];
  int pipe_stderr[2];

#ifdef SPAWN_NEW_USER
  int pipe_setup[2];
  int newuser;
#endif

  pid_t pid;

} args_t;

static pthread_mutex_t spawn_mutex = PTHREAD_MUTEX_INITIALIZER;
static struct args_list active_args;
static int stopped;

/**
 *
 */
static int
child(void *A)
{
  args_t *a = A;

#ifdef SPAWN_NEW_USER
  if(a->newuser) {
    char ch;
    close(a->pipe_setup[1]);
    if(read(a->pipe_setup[0], &ch, 1) != 0) {
      fprintf(stderr, "read from setup_pipe returned != 0\n");
      return 1;
    }
    close(a->pipe_setup[0]);
  }
#endif


  // Close read ends of pipe
  close(a->pipe_stdout[0]);
  close(a->pipe_stderr[0]);

  // Let stdin read from /dev/null
  int devnull = open("/dev/null", O_RDONLY);
  if(devnull != -1) {
    dup2(devnull, 0);
    close(devnull);
  }

  // Flush output buffered IO
  fflush(stdout);
  fflush(stderr);

  // Switch stdout/stderr to our pipes
  dup2(a->pipe_stdout[1], 1);
  dup2(a->pipe_stderr[1], 2);
  close(a->pipe_stdout[1]);
  close(a->pipe_stderr[1]);

  return a->exec_cb(a->opaque);
}


#ifdef SPAWN_NEW_USER
static int
update_map(const char *path, const char *mapping)
{
  linux_cap_change(1, CAP_SETUID, CAP_SETGID, CAP_DAC_OVERRIDE, -1);

  int rval = 0;

  int fd = open(path, O_RDWR);
  if(fd == -1) {
    rval = -1;
  } else {

    if(write(fd, mapping, strlen(mapping)) != strlen(mapping)) {
      trace(LOG_ERR, "Unable to update UIDGID mapping %s in %s -- %s",
            mapping, path, strerror(errno));
      rval = -1;
    }

    if(close(fd)) {
      trace(LOG_ERR, "Unable to update UIDGID mapping %s in %s -- %s",
            mapping, path, strerror(errno));
      rval = -1;
    }
  }

  linux_cap_change(0, CAP_SETUID, CAP_SETGID, CAP_DAC_OVERRIDE, -1);
  return rval;
}
#endif


/**
 *
 */
int
spawn(int (*exec_cb)(void *opaque),
      int (*line_cb)(void *opaque, const char *line,
                     char *errbuf, size_t errlen),
      void *opaque,
      htsbuf_queue_t *output, int timeout, int flags,
      char *errbuf, size_t errlen)
{
  int forkerr;

  pthread_mutex_lock(&spawn_mutex);
  if(stopped) {
    snprintf(errbuf, errlen, "Buildagent is stopping");
    pthread_mutex_unlock(&spawn_mutex);
    return DOOZER_TEMPORARY_FAIL;
  }

  args_t *a = malloc(sizeof(args_t));
  a->exec_cb = exec_cb;
  a->opaque = opaque;

  const int print_to_stdout = isatty(1);

  if(pipe(a->pipe_stdout)) {
    snprintf(errbuf, errlen, "Unable to create stdout pipe -- %s",
             strerror(errno));
    pthread_mutex_unlock(&spawn_mutex);
    free(a);
    return DOOZER_TEMPORARY_FAIL;
  }

  if(pipe(a->pipe_stderr)) {
    snprintf(errbuf, errlen, "Unable to create stderr pipe -- %s",
             strerror(errno));
    close(a->pipe_stdout[0]);
    close(a->pipe_stdout[1]);
    pthread_mutex_unlock(&spawn_mutex);
    free(a);
    return DOOZER_TEMPORARY_FAIL;
  }

#ifdef SPAWN_NEW_USER

  a->newuser = 1;

  int clone_flags = SIGCHLD;
  if(a->newuser)
    clone_flags |=
      CLONE_NEWUSER | CLONE_NEWIPC | CLONE_NEWUTS | CLONE_NEWNS | CLONE_NEWPID;

  if(a->newuser) {

    if(pipe(a->pipe_setup)) {
      snprintf(errbuf, errlen, "Unable to create setup pipe -- %s",
               strerror(errno));
      close(a->pipe_stdout[0]);
      close(a->pipe_stdout[1]);
      close(a->pipe_stderr[0]);
      close(a->pipe_stderr[1]);
      free(a);
      pthread_mutex_unlock(&spawn_mutex);
      return DOOZER_TEMPORARY_FAIL;
    }
  }

  size_t initial_stacksize = 1024 * 1024;
  void *stack = mmap(NULL, initial_stacksize, PROT_WRITE | PROT_READ,
                     MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);

  a->pid = clone(child, stack + initial_stacksize, clone_flags, a);

  forkerr = errno;
  munmap(stack, initial_stacksize);
#else
  pid = fork();
  forkerr = errno;

  if(pid == 0) {
    int r = child(a);
    exit(r);
  }
#endif

  if(a->pid == -1) {
    close(a->pipe_stdout[0]);
    close(a->pipe_stdout[1]);
    close(a->pipe_stderr[0]);
    close(a->pipe_stderr[1]);
#ifdef SPAWN_NEW_USER
    if(a->newuser) {
      close(a->pipe_setup[0]);
      close(a->pipe_setup[1]);
    }
#endif
    snprintf(errbuf, errlen, "Unable to fork -- %s",
             strerror(forkerr));
    free(a);
    pthread_mutex_unlock(&spawn_mutex);
    return DOOZER_TEMPORARY_FAIL;
  }

  // Close write ends of pipe
  close(a->pipe_stdout[1]);
  close(a->pipe_stderr[1]);

#ifdef SPAWN_NEW_USER

  if(a->newuser) {

    char map_path[PATH_MAX];
    char mapping[128];

    assert(build_uid != -1);
    assert(build_gid != -1);

    snprintf(mapping, sizeof(mapping), "%d %d %d\n%d %d %d\n",
             0, UIDGID_OFFSET, 1000,
             build_uid, build_uid, 1);
    snprintf(map_path, PATH_MAX, "/proc/%ld/uid_map", (long)a->pid);
    update_map(map_path, mapping);

    snprintf(mapping, sizeof(mapping), "%d %d %d\n%d %d %d\n",
             0, UIDGID_OFFSET, 1000,
             build_gid, build_gid, 1);
    snprintf(map_path, PATH_MAX, "/proc/%ld/gid_map", (long)a->pid);
    update_map(map_path, mapping);

    // Clone setup pipe to tell child it can continue with exec()
    close(a->pipe_setup[1]);
    close(a->pipe_setup[0]);
  }
#endif

  int err = 0;

  LIST_INSERT_HEAD(&active_args, a, link);

  struct pollfd fds[2] = {
    {
      .fd = a->pipe_stdout[0],
      .events = POLLIN | POLLHUP | POLLERR,
    }, {
      .fd = a->pipe_stderr[0],
      .events = POLLIN | POLLHUP | POLLERR,
    }
  };

  pthread_mutex_unlock(&spawn_mutex);

  int got_timeout = 0;

  char buf[10000];

  htsbuf_queue_t stdout_q, stderr_q, *q;

  htsbuf_queue_init(&stdout_q, 0);
  htsbuf_queue_init(&stderr_q, 0);

  while(!err) {

    int r = poll(fds, 2, timeout * 1000);
    if(r == 0) {
      got_timeout = 1;
      break;
    }

    if(fds[0].revents & POLLIN) {
      r = read(fds[0].fd, buf, sizeof(buf));
      q = &stdout_q;
    } else if(fds[1].revents & POLLIN) {
      r = read(fds[1].fd, buf, sizeof(buf));
      q = &stderr_q;
    } else if(fds[0].revents & (POLLHUP | POLLERR)) {
      break;
    } else if(fds[1].revents & (POLLHUP | POLLERR)) {
      break;
    } else {
      sleep(1);
      continue;
    }

    if(r == 0 || r == -1)
      break;

    htsbuf_append(q, buf, r);

    while(!err) {
      int len = htsbuf_find(q, 0xa);
      if(len == -1)
        break;

      if(q == &stderr_q)
        htsbuf_append(output, (const uint8_t []){0xef,0xbf,0xb9}, 3);

      char *line;
      if(len < sizeof(buf) - 1) {
        line = buf;
      } else {
        line = malloc(len + 1);
      }

      htsbuf_read(q, line, len);
      htsbuf_drop(q, 1); // Drop \n
      line[len] = 0;

      htsbuf_append(output, line, len);
      htsbuf_append(output, "\n", 1);

      if(print_to_stdout) {
        printf("%s: %s\033[0m\n",
               q == &stderr_q ? "\033[31mstderr" : "\033[33mstdout",
               line);
      }

      if(line_cb != NULL)
        err = line_cb(opaque, line, errbuf, errlen);

      if(line != buf)
        free(line);
    }
  }

  pthread_mutex_lock(&spawn_mutex);
  LIST_REMOVE(a, link);

  // Close read ends of pipe
  close(a->pipe_stdout[0]);
  close(a->pipe_stderr[0]);

  pthread_mutex_unlock(&spawn_mutex);

  free(a);

  if(got_timeout || err) {
    kill(a->pid, SIGKILL);
  }

  int status;
  struct rusage rr;
  if(wait4(a->pid, &status, 0, &rr) == -1) {
    snprintf(errbuf, errlen, "Unable to wait for child -- %s",
             strerror(errno));
    return DOOZER_TEMPORARY_FAIL;
  }

  if(print_to_stdout)
    printf("RESOURCE USAGE: user:%ld.%ld system:%ld.%ld\n",
           rr.ru_utime.tv_sec,
           rr.ru_utime.tv_usec,
           rr.ru_stime.tv_sec,
           rr.ru_stime.tv_usec);

  if(got_timeout) {
    snprintf(errbuf, errlen, "No output detected for %d seconds",
             timeout);
    return DOOZER_TEMPORARY_FAIL;
  }

  if(stopped) {
    snprintf(errbuf, errlen, "Job aborted");
    return DOOZER_TEMPORARY_FAIL;
  }

  if(err)
    return err;

  if(WIFEXITED(status)) {
    return WEXITSTATUS(status);
  } else if(WIFSIGNALED(status)) {
#ifdef WCOREDUMP
    if(WCOREDUMP(status)) {
      snprintf(errbuf, errlen, "Core dumped");
      return DOOZER_TEMPORARY_FAIL;
    }
#endif
    snprintf(errbuf, errlen,
             "Terminated by signal %d", WTERMSIG(status));
    return DOOZER_TEMPORARY_FAIL;
  }
  snprintf(errbuf, errlen,
           "Exited with status code %d", status);
  return DOOZER_TEMPORARY_FAIL;
}



void
spawn_stop_all(void)
{
  pthread_mutex_lock(&spawn_mutex);
  stopped = 1;

  args_t *a;
  LIST_FOREACH(a, &active_args, link)
    kill(a->pid, SIGTERM);

  pthread_mutex_unlock(&spawn_mutex);
}
