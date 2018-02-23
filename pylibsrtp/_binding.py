import ctypes.util
import platform

import cffi

ffi = cffi.FFI()
ffi.cdef("""
typedef uint32_t srtp_auth_type_id_t;
typedef uint32_t srtp_cipher_type_id_t;

typedef enum {
  srtp_err_status_ok = 0,
  srtp_err_status_fail = 1,
  srtp_err_status_bad_param = 2,
  srtp_err_status_alloc_fail = 3,
  srtp_err_status_dealloc_fail = 4,
  srtp_err_status_init_fail = 5,
  srtp_err_status_terminus = 6,
  srtp_err_status_auth_fail = 7,
  srtp_err_status_cipher_fail = 8,
  srtp_err_status_replay_fail = 9,
  srtp_err_status_replay_old = 10,
  srtp_err_status_algo_fail = 11,
  srtp_err_status_no_such_op = 12,
  srtp_err_status_no_ctx = 13,
  srtp_err_status_cant_check = 14,
  srtp_err_status_key_expired = 15,
  srtp_err_status_socket_err = 16,
  srtp_err_status_signal_err = 17,
  srtp_err_status_nonce_bad = 18,
  srtp_err_status_read_fail = 19,
  srtp_err_status_write_fail = 20,
  srtp_err_status_parse_err = 21,
  srtp_err_status_encode_err = 22,
  srtp_err_status_semaphore_err = 23,
  srtp_err_status_pfkey_err = 24,
  srtp_err_status_bad_mki = 25,
  srtp_err_status_pkt_idx_old = 26,
  srtp_err_status_pkt_idx_adv = 27
} srtp_err_status_t;

typedef enum {
  sec_serv_none = 0,
  sec_serv_conf = 1,
  sec_serv_auth = 2,
  sec_serv_conf_and_auth = 3
} srtp_sec_serv_t;

typedef enum {
  ssrc_undefined = 0,
  ssrc_specific = 1,
  ssrc_any_inbound = 2,
  ssrc_any_outbound = 3
} srtp_ssrc_type_t;

typedef enum {
  srtp_profile_reserved           = 0,
  srtp_profile_aes128_cm_sha1_80  = 1,
  srtp_profile_aes128_cm_sha1_32  = 2,
  srtp_profile_null_sha1_80       = 5,
  srtp_profile_null_sha1_32       = 6,
  srtp_profile_aead_aes_128_gcm   = 7,
  srtp_profile_aead_aes_256_gcm   = 8,
} srtp_profile_t;

typedef struct srtp_crypto_policy_t {
  srtp_cipher_type_id_t cipher_type;
  int cipher_key_len;
  srtp_auth_type_id_t auth_type;
  int auth_key_len;
  int auth_tag_len;
  srtp_sec_serv_t sec_serv;
} srtp_crypto_policy_t;

typedef struct {
  srtp_ssrc_type_t type;
  unsigned int value;
} srtp_ssrc_t;

typedef struct srtp_ekt_policy_ctx_t *srtp_ekt_policy_t;
typedef struct srtp_ekt_stream_ctx_t *srtp_ekt_stream_t;

typedef struct srtp_master_key_t {
  unsigned char *key;
  unsigned char *mki_id;
  unsigned int mki_size;
} srtp_master_key_t;

typedef struct srtp_ctx_t_ srtp_ctx_t;
typedef srtp_ctx_t *srtp_t;

typedef struct srtp_policy_t {
  srtp_ssrc_t ssrc;
  srtp_crypto_policy_t rtp;
  srtp_crypto_policy_t rtcp;
  unsigned char *key;
  srtp_master_key_t **keys;
  unsigned long num_master_keys;
  srtp_ekt_policy_t ekt;
  unsigned long window_size;
  int allow_repeat_tx;
  int *enc_xtn_hdr;
  int enc_xtn_hdr_count;
  struct srtp_policy_t *next;
} srtp_policy_t;

srtp_err_status_t srtp_init(void);

srtp_err_status_t srtp_create(srtp_t *session, const srtp_policy_t *policy);
srtp_err_status_t srtp_dealloc(srtp_t s);

void srtp_crypto_policy_set_rtp_default(srtp_crypto_policy_t *p);
void srtp_crypto_policy_set_rtcp_default(srtp_crypto_policy_t *p);

srtp_err_status_t srtp_add_stream(srtp_t session, const srtp_policy_t *policy);
srtp_err_status_t srtp_remove_stream(srtp_t session, unsigned int ssrc);

srtp_err_status_t srtp_protect(srtp_t ctx, void *rtp_hdr, int *len_ptr);
srtp_err_status_t srtp_protect_rtcp(srtp_t ctx, void *rtcp_hdr, int *pkt_octet_len);

srtp_err_status_t srtp_unprotect(srtp_t ctx, void *srtp_hdr, int *len_ptr);
srtp_err_status_t srtp_unprotect_rtcp(srtp_t ctx, void *srtcp_hdr, int *pkt_octet_len);
""")
_libname = ctypes.util.find_library('srtp2')
# find_library does not respect LD_LIBRARY_PATH on python < 3.6
if _libname is None and platform.python_version_tuple() < ('3', '6', '0'):
    _libname = 'libsrtp2.so.1'
_lib = ffi.dlopen(_libname)
