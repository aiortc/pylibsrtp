pylibsrtp
=========

A Python wrapper around libsrtp >= 2.0.

Example:

.. code:: python

    #!/usr/bin/env python

    from pylibsrtp import Policy, Session

    key = (b'\x00' * 30)
    rtp = b'\x80\x08\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00' + (b'\xd4' * 160)

    # protect RTP
    tx_policy = Policy(key=key, ssrc_type=Policy.SSRC_ANY_OUTBOUND)
    tx_session = Session(policy=tx_policy)
    srtp = tx_session.protect(rtp)

    # unprotect RTP
    rx_policy = Policy(key=key, ssrc_type=Policy.SSRC_ANY_INBOUND)
    rx_session = Session(policy=rx_policy)
    rtp2 = rx_session.unprotect(srtp)

    # check roundtrip worked!
    assert rtp2 == rtp

License
-------

``pylibsrtp`` is released under the BSD license.
