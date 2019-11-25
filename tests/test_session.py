from unittest import TestCase

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

# Set key to predetermined value
KEY = (
    b"\x00\x01\x02\x03\x04\x05\x06\x07"
    b"\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f"
    b"\x10\x11\x12\x13\x14\x15\x16\x17"
    b"\x18\x19\x1a\x1b\x1c\x1d"
)


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
        policy = Policy()
        self.assertEqual(policy.key, None)

        policy.key = KEY
        self.assertEqual(policy.key, KEY)

        policy.key = None
        self.assertEqual(policy.key, None)

        with self.assertRaises(TypeError) as cm:
            policy.key = 1234
        self.assertEqual(policy.key, None)
        self.assertEqual(str(cm.exception), "key must be bytes")

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
        # protect RTP
        tx_session = Session(
            policy=Policy(key=KEY, ssrc_type=Policy.SSRC_SPECIFIC, ssrc_value=12345)
        )
        protected = tx_session.protect(RTP)
        self.assertEqual(len(protected), 182)

        # add stream and unprotect RTP
        rx_session = Session()
        rx_session.add_stream(
            Policy(key=KEY, ssrc_type=Policy.SSRC_SPECIFIC, ssrc_value=12345)
        )
        unprotected = rx_session.unprotect(protected)
        self.assertEqual(len(unprotected), 172)
        self.assertEqual(unprotected, RTP)

        # remove stream
        rx_session.remove_stream(12345)

        # try removing stream again
        with self.assertRaises(Error) as cm:
            rx_session.remove_stream(12345)
        self.assertEqual(str(cm.exception), "no appropriate context found")

    def test_rtp_any_ssrc(self):
        # protect RTP
        tx_session = Session(policy=Policy(key=KEY, ssrc_type=Policy.SSRC_ANY_OUTBOUND))
        protected = tx_session.protect(RTP)
        self.assertEqual(len(protected), 182)

        # bad type
        with self.assertRaises(TypeError) as cm:
            tx_session.protect(4567)
        self.assertEqual(str(cm.exception), "packet must be bytes")

        # bad length
        with self.assertRaises(ValueError) as cm:
            tx_session.protect(b"0" * 1500)
        self.assertEqual(str(cm.exception), "packet is too long")

        # unprotect RTP
        rx_session = Session(policy=Policy(key=KEY, ssrc_type=Policy.SSRC_ANY_INBOUND))
        unprotected = rx_session.unprotect(protected)
        self.assertEqual(len(unprotected), 172)
        self.assertEqual(unprotected, RTP)

    def test_rtcp_any_ssrc(self):
        # protect RCTP
        tx_session = Session(policy=Policy(key=KEY, ssrc_type=Policy.SSRC_ANY_OUTBOUND))
        protected = tx_session.protect_rtcp(RTCP)
        self.assertEqual(len(protected), 42)

        # bad type
        with self.assertRaises(TypeError) as cm:
            tx_session.protect_rtcp(4567)
        self.assertEqual(str(cm.exception), "packet must be bytes")

        # bad length
        with self.assertRaises(ValueError) as cm:
            tx_session.protect_rtcp(b"0" * 1500)
        self.assertEqual(str(cm.exception), "packet is too long")

        # unprotect RTCP
        rx_session = Session(policy=Policy(key=KEY, ssrc_type=Policy.SSRC_ANY_INBOUND))
        unprotected = rx_session.unprotect_rtcp(protected)
        self.assertEqual(len(unprotected), 28)
        self.assertEqual(unprotected, RTCP)

    def test_rtp_specific_ssrc(self):
        # protect RTP
        tx_session = Session(
            policy=Policy(key=KEY, ssrc_type=Policy.SSRC_SPECIFIC, ssrc_value=12345)
        )
        protected = tx_session.protect(RTP)
        self.assertEqual(len(protected), 182)

        # unprotect RTP
        rx_session = Session(
            policy=Policy(key=KEY, ssrc_type=Policy.SSRC_SPECIFIC, ssrc_value=12345)
        )
        unprotected = rx_session.unprotect(protected)
        self.assertEqual(len(unprotected), 172)
        self.assertEqual(unprotected, RTP)
