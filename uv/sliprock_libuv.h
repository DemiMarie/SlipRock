#include <sliprock.h>
#include <uv.h>
typedef struct {
  SliprockConnection *con;
  uv_pipe_t pipe;
  void *data;
} sliprock_uv_pipe_t;
typedef void (*sliprock_uv_pipe_cb)(sliprock_uv_pipe_t *pipe, int status);
typedef void (*sliprock_uv_accept_cb)(uv_stream_t *stream);
SLIPROCK_API int sliprock_uv_pipe_bind(uv_loop_t *loop, const char *name,
                                       size_t length, void *data,
                                       sliprock_uv_pipe_cb cb);
