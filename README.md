# Secure Local Interprocess Communication

This is the official repository of SlipRock.  Sliprock stands for “Secure Local Interprocess Communication” and is a foundational library that makes it easy for two processes running under the same user account to communicate with each other, in such a way that other users on the same machine are unable to either read the contents of messages or tamper with messages.  Furthermore, it allows for those processes to share handles (not yet implemented).

SlipRock is also designed to be robust.  It is designed to not crash or misbehave under *any* circumstances – including running out of memory.  Although it is written in C, SlipRock is so small that auditing it for violations of memory safety should be relatively easy.

SlipRock provides a blocking API.  This is by design.  SlipRock involves many file system operations that cannot be performed asynchronously on any major operating system.  Furthermore, a blocking API makes SlipRock much less difficult to misuse in insecure ways.  SlipRock also provides handles (Windows) or file descriptors (everywhere else) that can always be set to non-blocking.  Therefore, once a connection has been established, fully non-blocking communication is possible.  Finally, SlipRock generally assumes that one can do I/O multiplexing in user mode.  As a result, SlipRock assumes that most processes will not need to manage thousands of concurrent connections.  One can always make the SlipRock calls from a worker thread.

In the future, a lower-level API will be provided that requires the user to perform all IPC themselves.  This allows for fully non-blocking APIs to be implemented and will provide better integration with external I/O libraries, which often insist that they perform all IPC internally.

The library is in its infancy.  The only test so far establishes that a simple message can be sent.  The plan is to heavily test SlipRock.  This is essential to achieving its robustness goals.

SlipRock is fully thread-safe, provided that there is a happens-before relationship between the `sliprock_bind` call on a connection and all calls to `sliprock_accept` on the same connection.  It has no dependencies on Windows.  On other systems, SlipRock currently relies on libsodium for random-number generation and binary-to-hex conversion.  This is only a tiny fraction of the overall code in libsodium.  Other than random-number generation, SlipRock does not use cryptography in any way.  All security is provided by OS access controls.

Current Status:

- [X] Compiles on Linux
- [X] Can send simple message on Linux
- [X] Basic test case
- [ ] Low-level API
- [ ] Compiles on Windows
- [ ] Basic testing on Windows
- [ ] Comprehensive testing
- [ ] Extensive tests of error conditions
