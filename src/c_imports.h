/* Single header consumed by build.zig's translate-c step.
 *
 * BORINGSSL_PREFIX is also passed via build.zig defineCMacro; we set it here
 * defensively in case anyone runs translate-c manually for inspection. The
 * value MUST match the prefix used when libcrypto.a/libssl.a were built. */

#ifndef BORINGSSL_PREFIX
#define BORINGSSL_PREFIX zbssl
#endif

#include <openssl/base.h>

/* Zig's translate-c parses the post-preprocessor token stream and chokes on
 * _Pragma(...) emitted inside macro expansions (e.g. DEFINE_STACK_OF). Make
 * BoringSSL's pragma helper macros no-ops for translation only; the static
 * library itself was built with the real pragmas in effect. */
#undef OPENSSL_GNUC_CLANG_PRAGMA
#define OPENSSL_GNUC_CLANG_PRAGMA(arg)
#undef OPENSSL_CLANG_PRAGMA
#define OPENSSL_CLANG_PRAGMA(arg)
#undef OPENSSL_MSVC_PRAGMA
#define OPENSSL_MSVC_PRAGMA(arg)
#undef OPENSSL_BEGIN_ALLOW_DEPRECATED
#define OPENSSL_BEGIN_ALLOW_DEPRECATED
#undef OPENSSL_END_ALLOW_DEPRECATED
#define OPENSSL_END_ALLOW_DEPRECATED

#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/sha.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>
#include <openssl/ssl.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/bio.h>
#include <openssl/aead.h>
#include <openssl/hkdf.h>
#include <openssl/aes.h>
