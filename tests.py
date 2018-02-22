from unittest import TestCase

from libsrtp import Policy, Session

RTP = (
    b'\x80\x08\x00\x00'  # version, packet type, sequence number
    b'\x00\x00\x00\x00'  # timestamp
    b'\x00\x00\x00\x00'  # ssrc
) + (b'\xd4' * 160)


# Set key to predetermined value
KEY = (
    b'\x00\x01\x02\x03\x04\x05\x06\x07'
    b'\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f'
    b'\x10\x11\x12\x13\x14\x15\x16\x17'
    b'\x18\x19\x1a\x1b\x1c\x1d'
)


class PolicyTest(TestCase):
    def test_key(self):
        policy = Policy(inbound=True)
        self.assertEqual(policy.key, b'')

        policy.key = KEY
        self.assertEqual(policy.key, KEY)


class SessionTest(TestCase):
    def test_rtp(self):
        # protect RTP
        tx_session = Session(policy=Policy(inbound=False, key=KEY))
        protected = tx_session.protect(RTP)
        self.assertEqual(len(protected), 182)

        # unprotect RTP
        rx_session = Session(policy=Policy(inbound=True, key=KEY))
        unprotected = rx_session.unprotect(protected)
        self.assertEqual(len(unprotected), 172)
        self.assertEqual(unprotected, RTP)
