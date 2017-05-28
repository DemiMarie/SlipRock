#include <sliprock.h>
#include <uv.h>
typedef void (*sliprock_uv_accept_cb)(uv_pipe_t stream, int status);
typedef struct sliprock_uv_receiver_t {
  SliprockReceiver *con;
  uv_pipe_t pipe;
} sliprock_uv_receiver_t;
typedef struct sliprock_uv_pipe_t {
  SliprockConnection *con;
  uv_pipe_t pipe;
  sliprock_uv_accept_cb cb;
  int ipc;
  int align_dummy;
} sliprock_uv_pipe_t;
typedef void (*sliprock_uv_pipe_cb)(sliprock_uv_pipe_t *pipe, int status);
typedef void (*sliprock_uv_receiver_cb)(sliprock_uv_receiver_t *pipe,
                                        int status);
SLIPROCK_API int sliprock_uv_pipe_bind(uv_loop_t *const loop,
                                       const char *const name,
                                       const size_t length, void *const data,
                                       sliprock_uv_pipe_cb const cb);
SLIPROCK_API int sliprock_uv_pipe_connect(uv_loop_t *loop, uint32_t pid,
                                          const char *name, size_t length,
                                          int ipc, void *data,
                                          sliprock_uv_receiver_cb cb);
SLIPROCK_API int sliprock_uv_pipe_listen(sliprock_uv_pipe_t *pipe,
                                         sliprock_uv_accept_cb cb);
