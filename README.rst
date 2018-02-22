pylibsrtp
=========

A Python wrapper around libsrtp.

Example:

.. code:: python

    #!/usr/bin/env python

    key = (b'\x00' * 30)
    rtp = b'\x80\x08\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00' + (b'\xd4' * 160)

    tx_session = Session(policy=Policy(inbound=False, key=key))
    srtp = tx_session.protect(rtp)

    rx_session = Session(policy=Policy(inbound=True, key=key))
    rtp2 = rx_session.unprotect(srtp)

License
-------

``pylibsrtp`` is released under the BSD license.
