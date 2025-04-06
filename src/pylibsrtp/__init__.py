from socket import htonl
from typing import Optional

from ._binding import ffi, lib

__all__ = ["Error", "Policy", "Session", "__version__"]
__version__ = "0.12.0"


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


# SRTP_MAX_TAG_LEN + SRTP_MAX_MKI_LEN
SRTP_MAX_TRAILER_LEN = 16 + 128

# SRTP_SRCTP_INDEX_LEN + SRTP_MAX_TAG_LEN + SRTP_MAX_MKI_LEN
SRTP_MAX_SRTCP_TRAILER_LEN = 4 + 16 + 128


class Error(Exception):
    """
    Error that occurred making a `libsrtp` API call.
    """

    pass


def _srtp_assert(rc):
    if rc != lib.srtp_err_status_ok:
        raise Error(ERRORS[rc])


class Policy:
    """
    Policy for single SRTP stream.
    """

    #: AES-128 CM mode with 80-bit authentication tag (default)
    SRTP_PROFILE_AES128_CM_SHA1_80 = lib.srtp_profile_aes128_cm_sha1_80
    #: AES-128 CM mode with 32-bit authentication tag
    SRTP_PROFILE_AES128_CM_SHA1_32 = lib.srtp_profile_aes128_cm_sha1_32
    #: AES-128 GCM mode
    SRTP_PROFILE_AEAD_AES_128_GCM = lib.srtp_profile_aead_aes_128_gcm
    #: AES-256 GCM mode
    SRTP_PROFILE_AEAD_AES_256_GCM = lib.srtp_profile_aead_aes_256_gcm

    #: Indicates an undefined SSRC type
    SSRC_UNDEFINED = lib.ssrc_undefined
    #: Indicates a specific SSRC value
    SSRC_SPECIFIC = lib.ssrc_specific
    #: Indicates any inbound SSRC value
    SSRC_ANY_INBOUND = lib.ssrc_any_inbound
    #: Indicates any inbound SSRC value
    SSRC_ANY_OUTBOUND = lib.ssrc_any_outbound

    def __init__(
        self,
        key: Optional[bytes] = None,
        ssrc_type: int = SSRC_UNDEFINED,
        ssrc_value: int = 0,
        srtp_profile: int = SRTP_PROFILE_AES128_CM_SHA1_80,
    ) -> None:
        self._policy = ffi.new("srtp_policy_t *")
        self._srtp_profile = srtp_profile

        _srtp_assert(
            lib.srtp_crypto_policy_set_from_profile_for_rtp(
                ffi.addressof(self._policy.rtp), srtp_profile
            )
        )
        _srtp_assert(
            lib.srtp_crypto_policy_set_from_profile_for_rtcp(
                ffi.addressof(self._policy.rtcp), srtp_profile
            )
        )

        self.key = key
        self.ssrc_type = ssrc_type
        self.ssrc_value = ssrc_value

    @property
    def allow_repeat_tx(self) -> bool:
        """
        Whether retransmissions of packets with the same sequence number are allowed.
        """
        return self._policy.allow_repeat_tx == 1

    @allow_repeat_tx.setter
    def allow_repeat_tx(self, allow_repeat_tx: bool) -> None:
        self._policy.allow_repeat_tx = 1 if allow_repeat_tx else 0

    @property
    def key(self) -> Optional[bytes]:
        """
        The SRTP master key + master salt.
        """
        if self.__cdata is None:
            return None
        return ffi.buffer(self.__cdata)

    @key.setter
    def key(self, key: Optional[bytes]) -> None:
        if key is None:
            # Clear the key.
            self.__cdata = None
            self._policy.key = ffi.NULL
            return

        # Check the key is acceptable then assign it.
        expected_length = lib.srtp_profile_get_master_key_length(
            self._srtp_profile
        ) + lib.srtp_profile_get_master_salt_length(self._srtp_profile)
        if not isinstance(key, bytes):
            raise TypeError("key must be bytes")
        if len(key) < expected_length:
            raise ValueError("key must contain at least %d bytes" % expected_length)
        self.__cdata = ffi.new("unsigned char[]", len(key))
        self.__cdata[0 : len(key)] = key
        self._policy.key = self.__cdata

    @property
    def srtp_profile(self) -> int:
        """
        The SRTP profile.
        """
        return self._srtp_profile

    @property
    def ssrc_type(self) -> int:
        """
        The SSRC type.
        """
        return self._policy.ssrc.type

    @ssrc_type.setter
    def ssrc_type(self, ssrc_type: int) -> None:
        self._policy.ssrc.type = ssrc_type

    @property
    def ssrc_value(self) -> int:
        """
        The SSRC value, if it is not a wildcard.
        """
        return self._policy.ssrc.value

    @ssrc_value.setter
    def ssrc_value(self, ssrc_value: int) -> None:
        self._policy.ssrc.value = ssrc_value

    @property
    def window_size(self) -> int:
        """
        The window size to use for replay protection.
        """
        return self._policy.window_size

    @window_size.setter
    def window_size(self, window_size: int) -> None:
        self._policy.window_size = window_size


class Session:
    """
    SRTP session, which may comprise several streams.

    If `policy` is not specified, streams should be added later using the
    :func:`add_stream` method.
    """

    def __init__(self, policy: Optional[Policy] = None) -> None:
        srtp = ffi.new("srtp_t *")

        if policy is None:
            _policy = ffi.NULL
        else:
            _policy = policy._policy
        _srtp_assert(lib.srtp_create(srtp, _policy))

        self._cdata = ffi.new("char[]", 1500)
        self._buffer = ffi.buffer(self._cdata)
        self._srtp = ffi.gc(srtp, lambda x: lib.srtp_dealloc(x[0]))

    def add_stream(self, policy: Policy) -> None:
        """
        Add a stream to the SRTP session, applying the given `policy`
        to the stream.

        :param policy: :class:`Policy`
        """
        _srtp_assert(lib.srtp_add_stream(self._srtp[0], policy._policy))

    def remove_stream(self, ssrc: int) -> None:
        """
        Remove the stream with the given `ssrc` from the SRTP session.

        :param ssrc: :class:`int`
        """
        _srtp_assert(lib.srtp_remove_stream(self._srtp[0], htonl(ssrc)))

    def protect(self, packet: bytes) -> bytes:
        """
        Apply SRTP protection to the RTP `packet`.

        :param packet: :class:`bytes`
        :rtype: :class:`bytes`
        """
        return self.__process(packet, lib.srtp_protect, SRTP_MAX_TRAILER_LEN)

    def protect_rtcp(self, packet: bytes) -> bytes:
        """
        Apply SRTCP protection to the RTCP `packet`.

        :param packet: :class:`bytes`
        :rtype: :class:`bytes`
        """
        return self.__process(packet, lib.srtp_protect_rtcp, SRTP_MAX_SRTCP_TRAILER_LEN)

    def unprotect(self, packet: bytes) -> bytes:
        """
        Verify SRTP protection of the SRTP packet.

        :param packet: :class:`bytes`
        :rtype: :class:`bytes`
        """
        return self.__process(packet, lib.srtp_unprotect)

    def unprotect_rtcp(self, packet: bytes) -> bytes:
        """
        Verify SRTCP protection of the SRTCP packet.

        :param packet: :class:`bytes`
        :rtype: :class:`bytes`
        """
        return self.__process(packet, lib.srtp_unprotect_rtcp)

    def __process(self, data, func, trailer=0):
        if not isinstance(data, bytes):
            raise TypeError("packet must be bytes")
        if len(data) > len(self._cdata) - trailer:
            raise ValueError("packet is too long")

        len_p = ffi.new("int *")
        len_p[0] = len(data)
        self._buffer[0 : len(data)] = data
        _srtp_assert(func(self._srtp[0], self._cdata, len_p))
        return self._buffer[0 : len_p[0]]


lib.srtp_init()
