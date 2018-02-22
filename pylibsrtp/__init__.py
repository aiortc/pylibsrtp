from ._binding import ffi, _lib

ERRORS = [
    "nothing to report",
    "unspecified failure",
    "unsupported parameter",
    "couldn't allocate memory",
    "couldn't deallocate properly",
    "couldn't initialize",
    "can't process as much data as requested",
    "authentication failure",
    "cipher failure",
    "replay check failed (bad index)",
    "replay check failed (index too old)",
    "algorithm failed test routine",
    "unsupported operation",
    "no appropriate context found",
    "unable to perform desired validation",
    "can't use key any more",
    "error in use of socket",
    "error in use POSIX signals",
    "nonce check failed",
    "couldn't read data",
    "couldn't write data",
    "error parsing data",
    "error encoding data",
    "error while using semaphores",
    "error while using pfkey",
    "error MKI present in packet is invalid",
    "packet index is too old to consider",
    "packet index advanced, reset needed",
]


SRTP_MAX_TRAILER_LEN = 16 + 128


class Error(Exception):
    pass


def _srtp_assert(rc):
    if rc != _lib.srtp_err_status_ok:
        raise Error(ERRORS[rc])


class Policy:
    SSRC_UNDEFINED = _lib.ssrc_undefined
    SSRC_SPECIFIC = _lib.ssrc_specific
    SSRC_ANY_INBOUND = _lib.ssrc_any_inbound
    SSRC_ANY_OUTBOUND = _lib.ssrc_any_outbound

    def __init__(self, key=None, ssrc_type=SSRC_UNDEFINED, ssrc_value=0):
        self._policy = ffi.new('srtp_policy_t *')
        _lib.srtp_crypto_policy_set_rtp_default(
            ffi.addressof(self._policy.rtp))
        _lib.srtp_crypto_policy_set_rtcp_default(
            ffi.addressof(self._policy.rtcp))

        self.key = key
        self.ssrc_type = ssrc_type
        self.ssrc_value = ssrc_value

    @property
    def key(self):
        if self.__cdata is None:
            return None
        return ffi.buffer(self.__cdata)

    @key.setter
    def key(self, key):
        if key is None:
            self.__cdata = None
            self._policy.key = ffi.NULL
            return

        if not isinstance(key, bytes):
            raise TypeError('key must be bytes')
        self.__cdata = ffi.new('char[]', len(key))
        self.__cdata[0:len(key)] = key
        self._policy.key = self.__cdata

    @property
    def ssrc_type(self):
        return self._policy.ssrc.type

    @ssrc_type.setter
    def ssrc_type(self, ssrc_type):
        self._policy.ssrc.type = ssrc_type

    @property
    def ssrc_value(self):
        return self._policy.ssrc.value

    @ssrc_value.setter
    def ssrc_value(self, ssrc_value):
        self._policy.ssrc.value = ssrc_value


class Session:
    def __init__(self, policy):
        srtp = ffi.new('srtp_t *')
        _srtp_assert(_lib.srtp_create(srtp, policy._policy))

        self._cdata = ffi.new('char[]', 1500)
        self._buffer = ffi.buffer(self._cdata)
        self._srtp = ffi.gc(srtp, lambda x: _lib.srtp_dealloc(x[0]))

    def protect(self, data):
        return self.__process(data, _lib.srtp_protect, SRTP_MAX_TRAILER_LEN)

    def protect_rtcp(self, data):
        return self.__process(data, _lib.srtp_protect_rtcp, SRTP_MAX_TRAILER_LEN)

    def unprotect(self, data):
        return self.__process(data, _lib.srtp_unprotect)

    def unprotect_rtcp(self, data):
        return self.__process(data, _lib.srtp_unprotect_rtcp)

    def __process(self, data, func, trailer=0):
        if not isinstance(data, bytes):
            raise TypeError('data must be bytes')
        if len(data) > len(self._cdata) - trailer:
            raise ValueError('data is too long')

        len_p = ffi.new('int *')
        len_p[0] = len(data)
        self._buffer[0:len(data)] = data
        _srtp_assert(func(self._srtp[0], self._cdata, len_p))
        return self._buffer[0:len_p[0]]


_lib.srtp_init()
