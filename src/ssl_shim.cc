#include <openssl/ssl.h>

extern "C" void boringssl_zig_SSL_CTX_set_aes_hw_override_for_testing(
    SSL_CTX *ctx, int override_value) {
  bssl::SSL_CTX_set_aes_hw_override_for_testing(ctx, override_value != 0);
}
