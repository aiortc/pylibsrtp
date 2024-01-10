import sys

from cffi import FFI

libraries = ["srtp2"]
if sys.platform == "win32":
    libraries += ["libcrypto", "advapi32", "crypt32", "gdi32", "user32", "ws2_32"]
else:
    libraries += ["crypto"]

ffibuilder = FFI()
ffibuilder.set_source(
    "pylibsrtp._binding", "#include <srtp2/srtp.h>", libraries=libraries
)

ffibuilder.cdef(
    """
typedef enum {
  srtp_err_status_ok = 0,
  ...
} srtp_err_status_t;

typedef enum {
  srtp_profile_aes128_cm_sha1_80 = 1,
  srtp_profile_aes128_cm_sha1_32 = 2,
  srtp_profile_aead_aes_128_gcm = 7,
  srtp_profile_aead_aes_256_gcm = 8,
  ...
} srtp_profile_t;

typedef enum {
  ssrc_undefined = 0,
  ssrc_specific = 1,
  ssrc_any_inbound = 2,
  ssrc_any_outbound = 3
} srtp_ssrc_type_t;

typedef struct srtp_crypto_policy_t {
  ...;
} srtp_crypto_policy_t;

typedef struct {
  srtp_ssrc_type_t type;
  unsigned int value;
} srtp_ssrc_t;

typedef struct srtp_ctx_t_ srtp_ctx_t;
typedef srtp_ctx_t *srtp_t;

typedef struct srtp_policy_t {
  srtp_ssrc_t ssrc;
  srtp_crypto_policy_t rtp;
  srtp_crypto_policy_t rtcp;
  unsigned char *key;
  unsigned long window_size;
  int allow_repeat_tx;
  ...;
} srtp_policy_t;

srtp_err_status_t srtp_init(void);

srtp_err_status_t srtp_create(srtp_t *session, const srtp_policy_t *policy);
srtp_err_status_t srtp_dealloc(srtp_t s);

void srtp_crypto_policy_set_rtp_default(srtp_crypto_policy_t *p);
void srtp_crypto_policy_set_rtcp_default(srtp_crypto_policy_t *p);

srtp_err_status_t srtp_crypto_policy_set_from_profile_for_rtp(
    srtp_crypto_policy_t *policy, srtp_profile_t profile);
srtp_err_status_t srtp_crypto_policy_set_from_profile_for_rtcp(
    srtp_crypto_policy_t *policy, srtp_profile_t profile);

unsigned int srtp_profile_get_master_key_length(srtp_profile_t profile);
unsigned int srtp_profile_get_master_salt_length(srtp_profile_t profile);

srtp_err_status_t srtp_add_stream(srtp_t session, const srtp_policy_t *policy);
srtp_err_status_t srtp_remove_stream(srtp_t session, unsigned int ssrc);

srtp_err_status_t srtp_protect(srtp_t ctx, void *rtp_hdr, int *len_ptr);
srtp_err_status_t srtp_protect_rtcp(srtp_t ctx, void *rtcp_hdr, int *pkt_octet_len);

srtp_err_status_t srtp_unprotect(srtp_t ctx, void *srtp_hdr, int *len_ptr);
srtp_err_status_t srtp_unprotect_rtcp(srtp_t ctx, void *srtcp_hdr, int *pkt_octet_len);
"""
)

if __name__ == "__main__":
    ffibuilder.compile(verbose=True)
