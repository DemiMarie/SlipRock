#include "../state_machine.h"
#include <assert.h>
#include <ntsecapi.h>
#include <windows.h>
#include <winsock2.h>

int mac_nonce_and_data(struct CConnection *const con,
                       const SOCKADDR_STORAGE *addr, const size_t addr_len,
                       const unsigned char nonce[static SIZEOF_NONCE],
                       unsigned char hash[static SIZEOF_HASH]) {
  BOOL succeeded = FALSE;
  BCRYPT_HASH_HANDLE hash_handle;
  PUCHAR hasher = malloc(con->init->sizeOfHasher);
  if (!hasher) {
    goto fail;
  }
  if (BCryptCreateHash(con->init->sha256provider, &hash_handle, hasher,
                       con->init->sizeOfHasher, (PUCHAR)con->key,
                       sizeof con->key, 0) != 0) {
    goto fail;
  }
  if (BCryptHashData(hash_handle, (PUCHAR)nonce, SIZEOF_NONCE, 0) != 0)
    goto fail;
  if (BCryptHashData(hash_handle, (PUCHAR)connection_info, 6, 0) != 0) {
    goto fail;
  }
  if (BCryptFinishHash(hash_handle, hash, SIZEOF_HASH, 0) != 0) {
    goto fail;
  }
  if (BCryptDestroyHash(hash_handle) != 0) {
    goto fail;
  }
  succeeded = TRUE;
fail:
  if (hasher) {
    SecureZeroMemory(hasher, con->init->sizeOfHasher);
    SecureZeroMemory(hash, SIZEOF_HASH);
    free(hasher);
  }
  return succeeded;
}

int init_server_con(SConnection *con, SOCKET socket) {
  memset(con, 0, sizeof *con);
  if ((con->init = state_machine_init()) == NULL)
    return 0;
  con->state = CLIENT_HELLO;
  con->fd = socket;
  con->next_step = &get_client_hello;
}

int add_read_client(struct SConnection *connection, const char *buf,
                    size_t length, const void *out_buf,
                    const size_t *out_length) {
  return (connection->next_step_fn)(connection);
}
const InitState *state_machine_init(void) {
  INIT_ONCE initOnce;
  static InitState state;
  BOOLEAN pending;
  PVOID res;
  ULONG object_length, size, hash_length;
  if (!InitOnceBeginInitialize(&initOnce, 0, &pending, &res))
    return NULL;
  if (!pending)
    return (InitState *)res;
  struct WSAData data;
  if (WSAStartup(MAKEWORD(2, 2), &data) != 0)
    goto fail;
  if (data.wVersion != MAKEWORD(2, 2)) {
    WSACleanup();
    goto fail;
  }
  if (!BCryptOpenAlgorithmProvider(&state.sha256provider, L"SHA256",
                                   L"Microsoft Primitive Provider",
                                   BCRYPT_ALG_HANDLE_HMAC_FLAG))
    goto fail;
  if (!BCryptGetProperty(state.sha256provider, BCRYPT_OBJECT_LENGTH,
                         (PUCHAR)&object_length, sizeof object_length, &size,
                         0))
    goto fail;
  assert(size == sizeof(DWORD) &&
         "ObjectLength property of SHA256 algorithm was not a DWORD!");
  if (!BCryptGetProperty(state.sha256provider, L"HashDigestLength",
                         (PUCHAR)&hash_length, sizeof hash_length, &size, 0))
    goto fail;
  assert(size == sizeof(DWORD) &&
         "HashDigestLength property of SHA256 algorithm was not a DWORD!");
  assert(hash_length == 32 && "SHA256 hash algorithm produces 32-byte digest!");
  if (!BCryptOpenAlgorithmProvider(&state.rngProvider, L"RNG",
                                   L"Microsoft Primitive Provider", 0))
    goto fail;
  state.processHeap = GetProcessHeap();
  InitOnceEndInitialize(&initOnce, 0, &state);
  return &state;
fail:
  if (state.rngProvider != NULL)
    BCryptCloseAlgorithmProvider(state.rngProvider);
  if (state.sha256provider != NULL)
    BCryptCloseAlgorithmProvider(state.sha256provider);
  InitOnceEndInitialize(&initOnce, INIT_ONCE_INIT_FAILED, NULL);
  return NULL;
}
