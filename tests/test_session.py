import dataclasses
import secrets
from unittest import TestCase

import pylibsrtp
from pylibsrtp import Error, Policy, Session

RTP = (
    b"\x80\x08\x00\x00"  # version, packet type, sequence number
    b"\x00\x00\x00\x00"  # timestamp
    b"\x00\x00\x30\x39"  # ssrc: 12345
) + (b"\xd4" * 160)
RTCP = (
    b"\x80\xc8\x00\x06\xf3\xcb\x20\x01\x83\xab\x03\xa1\xeb\x02\x0b\x3a"
    b"\x00\x00\x94\x20\x00\x00\x00\x9e\x00\x00\x9b\x88"
)


@dataclasses.dataclass
class Profile:
    key_length: int
    protected_rtp_length: int
    protected_rtcp_length: int
    srtp_profile: int


# AES-GCM may not be supported depending on how libsrtp2 was built.
SRTP_PROFILES = [
    Profile(
        key_length=30,
        protected_rtp_length=182,
        protected_rtcp_length=42,
        srtp_profile=Policy.SRTP_PROFILE_AES128_CM_SHA1_80,
    ),
    Profile(
        key_length=30,
        protected_rtp_length=176,
        protected_rtcp_length=42,
        srtp_profile=Policy.SRTP_PROFILE_AES128_CM_SHA1_32,
    ),
]
try:
    Policy(srtp_profile=Policy.SRTP_PROFILE_AEAD_AES_128_GCM)
except Error:
    pass
else:
    SRTP_PROFILES += [
        Profile(
            key_length=28,
            protected_rtp_length=188,
            protected_rtcp_length=48,
            srtp_profile=Policy.SRTP_PROFILE_AEAD_AES_128_GCM,
        ),
        Profile(
            key_length=44,
            protected_rtp_length=188,
            protected_rtcp_length=48,
            srtp_profile=Policy.SRTP_PROFILE_AEAD_AES_256_GCM,
        ),
    ]


class PolicyTest(TestCase):
    def test_allow_repeat_tx(self):
        policy = Policy()
        self.assertEqual(policy.allow_repeat_tx, False)

        policy.allow_repeat_tx = True
        self.assertEqual(policy.allow_repeat_tx, True)

        policy.allow_repeat_tx = False
        self.assertEqual(policy.allow_repeat_tx, False)

        policy.allow_repeat_tx = 1
        self.assertEqual(policy.allow_repeat_tx, True)

        policy.allow_repeat_tx = 0
        self.assertEqual(policy.allow_repeat_tx, False)

    def test_key(self):
        key = secrets.token_bytes(30)

        policy = Policy()
        self.assertEqual(policy.key, None)

        policy.key = key
        self.assertEqual(policy.key, key)

        policy.key = None
        self.assertEqual(policy.key, None)

        # Key is not bytes.
        with self.assertRaises(TypeError) as cm:
            policy.key = 1234
        self.assertEqual(policy.key, None)
        self.assertEqual(str(cm.exception), "key must be bytes")

        # Key is too short.
        with self.assertRaises(ValueError) as cm:
            policy.key = b"0"
        self.assertEqual(policy.key, None)
        self.assertEqual(str(cm.exception), "key must contain at least 30 bytes")

    def test_srtp_policy(self):
        # Default profile.
        policy = Policy()
        self.assertEqual(policy.srtp_profile, Policy.SRTP_PROFILE_AES128_CM_SHA1_80)

        # Valid user-specified profiles.
        for profile in SRTP_PROFILES:
            with self.subTest(profile=profile):
                policy = Policy(srtp_profile=profile.srtp_profile)
                self.assertEqual(policy.srtp_profile, profile.srtp_profile)

        # Invalid profile.
        with self.assertRaises(Error) as cm:
            Policy(srtp_profile=0)
        self.assertEqual(str(cm.exception), "unsupported parameter")

    def test_ssrc_type(self):
        policy = Policy()
        self.assertEqual(policy.ssrc_type, Policy.SSRC_UNDEFINED)

        policy.ssrc_type = Policy.SSRC_ANY_INBOUND
        self.assertEqual(policy.ssrc_type, Policy.SSRC_ANY_INBOUND)

    def test_ssrc_value(self):
        policy = Policy()
        self.assertEqual(policy.ssrc_value, 0)

        policy.ssrc_value = 12345
        self.assertEqual(policy.ssrc_value, 12345)

    def test_window_size(self):
        policy = Policy()
        self.assertEqual(policy.window_size, 0)

        policy.window_size = 1024
        self.assertEqual(policy.window_size, 1024)


class SessionTest(TestCase):
    def test_no_key(self):
        policy = Policy(ssrc_type=Policy.SSRC_ANY_OUTBOUND)

        with self.assertRaises(Error) as cm:
            Session(policy=policy)
        self.assertEqual(str(cm.exception), "unsupported parameter")

    def test_add_remove_stream(self):
        for profile in SRTP_PROFILES:
            with self.subTest(profile=profile):
                key = secrets.token_bytes(profile.key_length)

                # protect RTP
                tx_session = Session(
                    policy=Policy(
                        key=key,
                        srtp_profile=profile.srtp_profile,
                        ssrc_type=Policy.SSRC_SPECIFIC,
                        ssrc_value=12345,
                    )
                )
                protected = tx_session.protect(RTP)
                self.assertEqual(len(protected), profile.protected_rtp_length)

                # add stream and unprotect RTP
                rx_session = Session()
                rx_session.add_stream(
                    Policy(
                        key=key,
                        srtp_profile=profile.srtp_profile,
                        ssrc_type=Policy.SSRC_SPECIFIC,
                        ssrc_value=12345,
                    )
                )
                unprotected = rx_session.unprotect(protected)
                self.assertEqual(unprotected, RTP)

                # remove stream
                rx_session.remove_stream(12345)

                # try removing stream again
                with self.assertRaises(Error) as cm:
                    rx_session.remove_stream(12345)
                self.assertEqual(str(cm.exception), "no appropriate context found")

    def test_rtp_any_ssrc(self):
        for profile in SRTP_PROFILES:
            with self.subTest(profile=profile):
                key = secrets.token_bytes(profile.key_length)

                # protect RTP
                tx_session = Session(
                    policy=Policy(
                        key=key,
                        srtp_profile=profile.srtp_profile,
                        ssrc_type=Policy.SSRC_ANY_OUTBOUND,
                    )
                )
                protected = tx_session.protect(RTP)
                self.assertEqual(len(protected), profile.protected_rtp_length)

                # bad type
                with self.assertRaises(TypeError) as cm:
                    tx_session.protect(4567)
                self.assertEqual(str(cm.exception), "packet must be bytes")

                # bad length
                with self.assertRaises(ValueError) as cm:
                    tx_session.protect(b"0" * (1501 - pylibsrtp.SRTP_MAX_TRAILER_LEN))
                self.assertEqual(str(cm.exception), "packet is too long")

                # unprotect RTP
                rx_session = Session(
                    policy=Policy(
                        key=key,
                        srtp_profile=profile.srtp_profile,
                        ssrc_type=Policy.SSRC_ANY_INBOUND,
                    )
                )
                unprotected = rx_session.unprotect(protected)
                self.assertEqual(unprotected, RTP)

    def test_rtcp_any_ssrc(self):
        for profile in SRTP_PROFILES:
            with self.subTest(profile=profile):
                key = secrets.token_bytes(profile.key_length)

                # protect RCTP
                tx_session = Session(
                    policy=Policy(
                        key=key,
                        srtp_profile=profile.srtp_profile,
                        ssrc_type=Policy.SSRC_ANY_OUTBOUND,
                    )
                )
                protected = tx_session.protect_rtcp(RTCP)
                self.assertEqual(len(protected), profile.protected_rtcp_length)

                # bad type
                with self.assertRaises(TypeError) as cm:
                    tx_session.protect_rtcp(4567)
                self.assertEqual(str(cm.exception), "packet must be bytes")

                # bad length
                with self.assertRaises(ValueError) as cm:
                    tx_session.protect_rtcp(
                        b"0" * (1501 - pylibsrtp.SRTP_MAX_SRTCP_TRAILER_LEN)
                    )
                self.assertEqual(str(cm.exception), "packet is too long")

                # unprotect RTCP
                rx_session = Session(
                    policy=Policy(
                        key=key,
                        srtp_profile=profile.srtp_profile,
                        ssrc_type=Policy.SSRC_ANY_INBOUND,
                    )
                )
                unprotected = rx_session.unprotect_rtcp(protected)
                self.assertEqual(unprotected, RTCP)

    def test_rtp_specific_ssrc(self):
        for profile in SRTP_PROFILES:
            with self.subTest(profile=profile):
                key = secrets.token_bytes(profile.key_length)

                # protect RTP
                tx_session = Session(
                    policy=Policy(
                        key=key,
                        srtp_profile=profile.srtp_profile,
                        ssrc_type=Policy.SSRC_SPECIFIC,
                        ssrc_value=12345,
                    )
                )
                protected = tx_session.protect(RTP)
                self.assertEqual(len(protected), profile.protected_rtp_length)

                # unprotect RTP
                rx_session = Session(
                    policy=Policy(
                        key=key,
                        srtp_profile=profile.srtp_profile,
                        ssrc_type=Policy.SSRC_SPECIFIC,
                        ssrc_value=12345,
                    )
                )
                unprotected = rx_session.unprotect(protected)
                self.assertEqual(unprotected, RTP)
