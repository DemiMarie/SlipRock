#include "sliprock_libuv.h"
#include <assert.h>
#include <sliprock.h>
#include <stdlib.h>
#include <string.h>
#include <uv.h>

struct myuv_work {
  uv_work_t work;
  char *name;
  sliprock_uv_pipe_t *pipe;
  sliprock_uv_pipe_cb cb;
  void *data;
  size_t length;
  int error_code;
  int dummy;
};

#ifndef _WIN32
#include <fcntl.h>
#include <unistd.h>
#define open_osfhandle(x) ((int)(x))
#else
#include <io.h>
#define close _close
#define open_osfhandle(x) (_open_osfhandle((HANDLE)(x)))
#endif

static void sliprock_uv_pipe_bind_loop_cb(uv_work_t *req) {
  struct myuv_work *work = (struct myuv_work *)req->data;
  assert(work->work.data == req &&
         "Bogus work passed to sliprock_uv_pipe_bind_loop_cb()!");
  work->pipe->con = sliprock_socket(work->name, work->length);
  if (NULL == work->pipe->con) {
#ifdef _WIN32
    work->error_code = GetLastError();
#else
    work->error_code = errno;
#endif
  }
}

static void sliprock_uv_pipe_bind_after_loop_cb(uv_work_t *req, int status) {
  struct myuv_work *work = (struct myuv_work *)req->data;
  assert(work->work.data == req &&
         "Bogus work passed to sliprock_uv_pipe_bind_loop_cb()!");
  if (status || NULL == work->pipe->con) {
    (work->cb)(work->pipe, work->error_code);
  } else {
    uv_file fhandle =
        open_osfhandle(sliprock_UNSAFEgetRawHandle(work->pipe->con, 1));
    int errorcode = uv_pipe_open(&work->pipe->pipe, fhandle);
    if (errorcode) {
      close(fhandle);
      sliprock_close(work->pipe->con);
      work->pipe->con = NULL;
      (work->cb)(work->pipe, errorcode);
    } else {
      (work->cb)(work->pipe, 0);
    }
  }
}

SLIPROCK_API int sliprock_uv_pipe_bind(uv_loop_t *loop, const char *name,
                                       size_t length, void *data,
                                       sliprock_uv_pipe_cb cb) {
  int nomem = UV_ENOMEM;
  struct myuv_work *req = calloc(sizeof(struct myuv_work), 1);
  if (NULL == req)
    return UV_ENOMEM;
  req->work.data = req;
  req->length = length;
  req->cb = cb;
  req->data = data;
  req->pipe = NULL;
  req->name = malloc(length);
  if (NULL == req->name)
    goto error_nomem;
  memcpy(req->name, name, length);
  req->pipe = malloc(sizeof(sliprock_uv_pipe_t));
  if (NULL == req->pipe)
    goto error_nomem;
  nomem = uv_pipe_init(loop, &req->pipe->pipe, 0);
  if (nomem)
    goto error_nomem;
  return uv_queue_work(loop, &req->work, &sliprock_uv_pipe_bind_loop_cb,
                       &sliprock_uv_pipe_bind_after_loop_cb);
error_nomem:
  free(req->name);
  free(req->pipe);
  free(req);
  return nomem;
}

static void sliprock_uv_listen_cb(uv_stream_t *stream) {
   sliprock_uv_pipe_t *pipe = (sliprock_uv_pipe_t*)stream->data;
   assert((uv_stream_t*)&pipe->pipe == stream);
   uv_accept(stream, 

SLIPROCK_API int sliprock_uv_pipe_listen(uv_loop_t *loop,
                                         sliprock_uv_pipe_t *pipe,
                                         sliprock_uv_accept_cb cb) {
   return uv_listen(pipe->pipe, &sliprock_uv_listen_cb);
}
