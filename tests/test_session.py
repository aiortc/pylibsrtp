import dataclasses
import secrets
from unittest import TestCase, skipUnless

import pylibsrtp
from pylibsrtp import Error, Policy, Session

RTP = (
    b"\x80\x08\x00\x00"  # version, packet type, sequence number
    b"\x00\x00\x00\x00"  # timestamp
    b"\x00\x00\x30\x39"  # ssrc: 12345
) + (b"\xd4" * 160)
RTP_WITH_EXTENSION = (
    b"\x90\x08\x00\x00"  # version, extension, packet type, sequence number
    b"\x00\x00\x00\x00"  # timestamp
    b"\x00\x00\x30\x39"  # ssrc: 12345
    b"\xbe\xde\x00\x01"  # one-byte header extensions, length: 1
    b"\x10\xff\x00\x00"  # id: 1, value: 0xff, padding
) + (b"\xd4" * 160)
RTP_WITH_CSRC = (
    b"\x81\x08\x00\x00"  # version, CSRC count: 1, packet type, sequence number
    b"\x00\x00\x00\x00"  # timestamp
    b"\x00\x00\x30\x39"  # ssrc: 12345
    b"\x00\x00\xd4\x31"  # csrc: 54321
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
    def test_allow_repeat_tx(self) -> None:
        policy = Policy()
        self.assertEqual(policy.allow_repeat_tx, False)

        policy.allow_repeat_tx = True
        self.assertEqual(policy.allow_repeat_tx, True)

        policy.allow_repeat_tx = False
        self.assertEqual(policy.allow_repeat_tx, False)

        policy.allow_repeat_tx = 1  # type: ignore[assignment]
        self.assertEqual(policy.allow_repeat_tx, True)

        policy.allow_repeat_tx = 0  # type: ignore[assignment]
        self.assertEqual(policy.allow_repeat_tx, False)

    def test_key(self) -> None:
        key = secrets.token_bytes(30)

        policy = Policy()
        self.assertEqual(policy.key, None)

        policy.key = key
        self.assertEqual(policy.key, key)

        policy.key = None
        self.assertEqual(policy.key, None)

        # Key is not bytes.
        with self.assertRaises(TypeError) as cm:
            policy.key = 1234  # type: ignore[assignment]
        self.assertEqual(policy.key, None)
        self.assertEqual(str(cm.exception), "key must be bytes")

        # Key is too short.
        with self.assertRaises(ValueError) as cm2:
            policy.key = b"0"
        self.assertEqual(policy.key, None)
        self.assertEqual(str(cm2.exception), "key must contain at least 30 bytes")

    def test_srtp_policy(self) -> None:
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

    def test_ssrc_type(self) -> None:
        policy = Policy()
        self.assertEqual(policy.ssrc_type, Policy.SSRC_UNDEFINED)

        policy.ssrc_type = Policy.SSRC_ANY_INBOUND
        self.assertEqual(policy.ssrc_type, Policy.SSRC_ANY_INBOUND)

    def test_ssrc_value(self) -> None:
        policy = Policy()
        self.assertEqual(policy.ssrc_value, 0)

        policy.ssrc_value = 12345
        self.assertEqual(policy.ssrc_value, 12345)

    def test_use_cryptex(self) -> None:
        policy = Policy()
        self.assertEqual(policy.use_cryptex, False)

        if Policy.CRYPTEX_SUPPORTED:
            policy.use_cryptex = True
            self.assertEqual(policy.use_cryptex, True)
        else:
            with self.assertRaises(Error) as cm:
                policy.use_cryptex = True
            self.assertEqual(str(cm.exception), "unsupported operation")
            self.assertEqual(policy.use_cryptex, False)

        # Disabling cryptex is always allowed.
        policy.use_cryptex = False
        self.assertEqual(policy.use_cryptex, False)

    def test_window_size(self) -> None:
        policy = Policy()
        self.assertEqual(policy.window_size, 0)

        policy.window_size = 1024
        self.assertEqual(policy.window_size, 1024)


class SessionTest(TestCase):
    def test_no_key(self) -> None:
        policy = Policy(ssrc_type=Policy.SSRC_ANY_OUTBOUND)

        with self.assertRaises(Error) as cm:
            Session(policy=policy)
        self.assertEqual(str(cm.exception), "unsupported parameter")

    def test_add_remove_stream(self) -> None:
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

    def test_rtp_any_ssrc(self) -> None:
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
                    tx_session.protect(4567)  # type: ignore[arg-type]
                self.assertEqual(str(cm.exception), "packet must be bytes")

                # bad length
                with self.assertRaises(ValueError) as cm2:
                    tx_session.protect(b"0" * (1501 - pylibsrtp.SRTP_MAX_TRAILER_LEN))
                self.assertEqual(str(cm2.exception), "packet is too long")

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

    def test_rtcp_any_ssrc(self) -> None:
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
                    tx_session.protect_rtcp(4567)  # type: ignore[arg-type]
                self.assertEqual(str(cm.exception), "packet must be bytes")

                # bad length
                with self.assertRaises(ValueError) as cm2:
                    tx_session.protect_rtcp(
                        b"0" * (1501 - pylibsrtp.SRTP_MAX_SRTCP_TRAILER_LEN)
                    )
                self.assertEqual(str(cm2.exception), "packet is too long")

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

    def test_rtp_specific_ssrc(self) -> None:
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


@dataclasses.dataclass
class CryptexVector:
    section: str
    plain: bytes
    protected: bytes


# Test vectors from RFC 9335 appendix A: A.1 uses AES-CTR, A.2 uses AES-GCM.
CRYPTEX_KEYS = {
    "A.1": (
        Policy.SRTP_PROFILE_AES128_CM_SHA1_80,
        bytes.fromhex("e1f97a0d3e018be0d64fa32c06de4139 0ec675ad498afeebb6960b3aabe6"),
    ),
    "A.2": (
        Policy.SRTP_PROFILE_AEAD_AES_128_GCM,
        bytes.fromhex("000102030405060708090a0b0c0d0e0f a0a1a2a3a4a5a6a7a8a9aaab"),
    ),
}
CRYPTEX_VECTORS = [
    CryptexVector(
        section="A.1.1",
        plain=bytes.fromhex(
            "900f1235 decafbad cafebabe bede0001"
            "51000200 abababab abababab abababab"
            "abababab"
        ),
        protected=bytes.fromhex(
            "900f1235 decafbad cafebabe c0de0001"
            "eb923652 51c3e036 f8de27e9 c27ee3e0"
            "b4651d9f bc4218a7 0244522f 34a5"
        ),
    ),
    CryptexVector(
        section="A.1.2",
        plain=bytes.fromhex(
            "900f1236 decafbad cafebabe 10000001"
            "05020002 abababab abababab abababab"
            "abababab"
        ),
        protected=bytes.fromhex(
            "900f1236 decafbad cafebabe c2de0001"
            "4ed9cc4e 6a712b30 96c5ca77 339d4204"
            "ce0d7739 6cab6958 5fbce381 94a5"
        ),
    ),
    CryptexVector(
        section="A.1.3",
        plain=bytes.fromhex(
            "920f1238 decafbad cafebabe 0001e240"
            "0000b26e bede0001 51000200 abababab"
            "abababab abababab abababab"
        ),
        protected=bytes.fromhex(
            "920f1238 decafbad cafebabe 8bb6e12b"
            "5cff16dd c0de0001 92838c8c 09e58393"
            "e1de3a9a 74734d67 45671338 c3acf11d"
            "a2df8423 bee0"
        ),
    ),
    CryptexVector(
        section="A.1.4",
        plain=bytes.fromhex(
            "920f1239 decafbad cafebabe 0001e240"
            "0000b26e 10000001 05020002 abababab"
            "abababab abababab abababab"
        ),
        protected=bytes.fromhex(
            "920f1239 decafbad cafebabe f70e513e"
            "b90b9b25 c2de0001 bbed4848 faa64466"
            "5f3d7f34 125914e9 f4d0ae92 3c6f479b"
            "95a0f7b5 3133"
        ),
    ),
    CryptexVector(
        section="A.1.5",
        plain=bytes.fromhex(
            "920f123a decafbad cafebabe 0001e240"
            "0000b26e bede0000 abababab abababab"
            "abababab abababab"
        ),
        protected=bytes.fromhex(
            "920f123a decafbad cafebabe 7130b6ab"
            "fe2ab0e3 c0de0000 e3d9f64b 25c9e74c"
            "b4cf8e43 fb92e378 1c2c0cea b6b3a499"
            "a14c"
        ),
    ),
    CryptexVector(
        section="A.1.6",
        plain=bytes.fromhex(
            "920f123b decafbad cafebabe 0001e240"
            "0000b26e 10000000 abababab abababab"
            "abababab abababab"
        ),
        protected=bytes.fromhex(
            "920f123b decafbad cafebabe cbf24c12"
            "4330e1c8 c2de0000 599dd45b c9d687b6"
            "03e8b59d 771fd38e 88b170e0 cd31e125"
            "eabe"
        ),
    ),
    CryptexVector(
        section="A.2.1",
        plain=bytes.fromhex(
            "900f1235 decafbad cafebabe bede0001"
            "51000200 abababab abababab abababab"
            "abababab"
        ),
        protected=bytes.fromhex(
            "900f1235 decafbad cafebabe c0de0001"
            "39972dc9 572c4d99 e8fc355d e743fb2e"
            "94f9d8ff 54e72f41 93bbc5c7 4ffab0fa"
            "9fa0fbeb"
        ),
    ),
    CryptexVector(
        section="A.2.2",
        plain=bytes.fromhex(
            "900f1236 decafbad cafebabe 10000001"
            "05020002 abababab abababab abababab"
            "abababab"
        ),
        protected=bytes.fromhex(
            "900f1236 decafbad cafebabe c2de0001"
            "bb75a4c5 45cd1f41 3bdb7daa 2b1e3263"
            "de313667 c9632490 81b35a65 f5cb6c88"
            "b394235f"
        ),
    ),
    CryptexVector(
        section="A.2.3",
        plain=bytes.fromhex(
            "920f1238 decafbad cafebabe 0001e240"
            "0000b26e bede0001 51000200 abababab"
            "abababab abababab abababab"
        ),
        protected=bytes.fromhex(
            "920f1238 decafbad cafebabe 63bbccc4"
            "a7f695c4 c0de0001 8ad7c71f ac70a80c"
            "92866b4c 6ba98546 ef913586 e95ffaaf"
            "fe956885 bb0647a8 bc094ac8"
        ),
    ),
    CryptexVector(
        section="A.2.4",
        plain=bytes.fromhex(
            "920f1239 decafbad cafebabe 0001e240"
            "0000b26e 10000001 05020002 abababab"
            "abababab abababab abababab"
        ),
        protected=bytes.fromhex(
            "920f1239 decafbad cafebabe 3680524f"
            "8d312b00 c2de0001 c78d1200 38422bc1"
            "11a7187a 18246f98 0c059cc6 bc9df8b6"
            "26394eca 344e4b05 d80fea83"
        ),
    ),
    CryptexVector(
        section="A.2.5",
        plain=bytes.fromhex(
            "920f123a decafbad cafebabe 0001e240"
            "0000b26e bede0000 abababab abababab"
            "abababab abababab"
        ),
        protected=bytes.fromhex(
            "920f123a decafbad cafebabe 15b6bb43"
            "37906fff c0de0000 b7b96453 7a2b03ab"
            "7ba5389c e9331712 6b5d974d f30c6884"
            "dcb651c5 e120c1da"
        ),
    ),
    CryptexVector(
        section="A.2.6",
        plain=bytes.fromhex(
            "920f123b decafbad cafebabe 0001e240"
            "0000b26e 10000000 abababab abababab"
            "abababab abababab"
        ),
        protected=bytes.fromhex(
            "920f123b decafbad cafebabe dcb38c9e"
            "48bf95f4 c2de0000 61ee432c f9203170"
            "76613258 d3ce4236 c06ac429 681ad084"
            "13512dc9 8b5207d8"
        ),
    ),
]


@skipUnless(Policy.CRYPTEX_SUPPORTED, "cryptex is not supported")
class CryptexTest(TestCase):
    def create_policy(
        self,
        key: bytes,
        *,
        ssrc_type: int,
        ssrc_value: int = 0,
        srtp_profile: int = Policy.SRTP_PROFILE_AES128_CM_SHA1_80,
        use_cryptex: bool = True,
    ) -> Policy:
        policy = Policy(
            key=key,
            ssrc_type=ssrc_type,
            ssrc_value=ssrc_value,
            srtp_profile=srtp_profile,
        )
        policy.use_cryptex = use_cryptex
        return policy

    def create_sessions(
        self,
        *,
        key: bytes | None = None,
        srtp_profile: int = Policy.SRTP_PROFILE_AES128_CM_SHA1_80,
        tx_cryptex: bool = True,
        rx_cryptex: bool = True,
    ) -> tuple[Session, Session]:
        if key is None:
            key = secrets.token_bytes(30)
        tx_session = Session(
            policy=self.create_policy(
                key,
                ssrc_type=Policy.SSRC_ANY_OUTBOUND,
                srtp_profile=srtp_profile,
                use_cryptex=tx_cryptex,
            )
        )
        rx_session = Session(
            policy=self.create_policy(
                key,
                ssrc_type=Policy.SSRC_ANY_INBOUND,
                srtp_profile=srtp_profile,
                use_cryptex=rx_cryptex,
            )
        )
        return tx_session, rx_session

    def test_rfc9335_vectors(self) -> None:
        for vector in CRYPTEX_VECTORS:
            with self.subTest(section=vector.section):
                srtp_profile, key = CRYPTEX_KEYS[vector.section[:3]]
                tx_session, rx_session = self.create_sessions(
                    key=key, srtp_profile=srtp_profile
                )
                self.assertEqual(tx_session.protect(vector.plain), vector.protected)
                self.assertEqual(rx_session.unprotect(vector.protected), vector.plain)

    def test_rtp_with_extension(self) -> None:
        for profile in SRTP_PROFILES:
            with self.subTest(profile=profile):
                tx_session, rx_session = self.create_sessions(
                    key=secrets.token_bytes(profile.key_length),
                    srtp_profile=profile.srtp_profile,
                )

                protected = tx_session.protect(RTP_WITH_EXTENSION)
                self.assertEqual(len(protected), profile.protected_rtp_length + 8)
                # The header extension profile is replaced and its contents
                # encrypted.
                self.assertEqual(protected[12:16], b"\xc0\xde\x00\x01")
                self.assertNotEqual(protected[16:20], RTP_WITH_EXTENSION[16:20])

                self.assertEqual(rx_session.unprotect(protected), RTP_WITH_EXTENSION)

    def test_rtp_with_extension_without_cryptex(self) -> None:
        tx_session, rx_session = self.create_sessions(tx_cryptex=False)

        protected = tx_session.protect(RTP_WITH_EXTENSION)
        # The header extension is sent in the clear.
        self.assertEqual(protected[12:20], RTP_WITH_EXTENSION[12:20])

        self.assertEqual(rx_session.unprotect(protected), RTP_WITH_EXTENSION)

    def test_rtp_without_extension(self) -> None:
        tx_session, rx_session = self.create_sessions()

        protected = tx_session.protect(RTP)
        self.assertEqual(len(protected), len(RTP) + 10)
        self.assertEqual(rx_session.unprotect(protected), RTP)

    def test_rtp_with_csrc_without_extension(self) -> None:
        tx_session, _ = self.create_sessions()

        # libsrtp does not add the empty header extension required by RFC 9335.
        with self.assertRaises(Error) as cm:
            tx_session.protect(RTP_WITH_CSRC)
        self.assertEqual(str(cm.exception), "cryptex error")

    def test_specific_ssrc(self) -> None:
        key = secrets.token_bytes(30)
        tx_session = Session(
            policy=self.create_policy(
                key, ssrc_type=Policy.SSRC_SPECIFIC, ssrc_value=12345
            )
        )
        rx_session = Session(
            policy=self.create_policy(
                key, ssrc_type=Policy.SSRC_SPECIFIC, ssrc_value=12345
            )
        )

        protected = tx_session.protect(RTP_WITH_EXTENSION)
        self.assertEqual(protected[12:16], b"\xc0\xde\x00\x01")
        self.assertEqual(rx_session.unprotect(protected), RTP_WITH_EXTENSION)

    def test_add_stream(self) -> None:
        key = secrets.token_bytes(30)
        tx_session = Session()
        tx_session.add_stream(
            self.create_policy(key, ssrc_type=Policy.SSRC_SPECIFIC, ssrc_value=12345)
        )
        rx_session = Session()
        rx_session.add_stream(
            self.create_policy(key, ssrc_type=Policy.SSRC_ANY_INBOUND)
        )

        protected = tx_session.protect(RTP_WITH_EXTENSION)
        self.assertEqual(protected[12:16], b"\xc0\xde\x00\x01")
        self.assertEqual(rx_session.unprotect(protected), RTP_WITH_EXTENSION)
