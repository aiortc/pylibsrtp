pylibsrtp
=========

|rtd| |pypi-v| |pypi-pyversions| |pypi-l| |pypi-wheel|

.. |rtd| image:: https://readthedocs.org/projects/pylibsrtp/badge/?version=latest
   :target: https://pylibsrtp.readthedocs.io/

.. |pypi-v| image:: https://img.shields.io/pypi/v/pylibsrtp.svg
    :target: https://pypi.python.org/pypi/pylibsrtp

.. |pypi-pyversions| image:: https://img.shields.io/pypi/pyversions/pylibsrtp.svg
    :target: https://pypi.python.org/pypi/pylibsrtp

.. |pypi-l| image:: https://img.shields.io/pypi/l/pylibsrtp.svg
    :target: https://pypi.python.org/pypi/pylibsrtp

.. |pypi-wheel| image:: https://img.shields.io/pypi/wheel/pylibsrtp.svg
    :target: https://pypi.python.org/pypi/pylibsrtp

A Python wrapper around libsrtp >= 2.0.

Example
-------

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

.. _BSD license: https://pylibsrtp.readthedocs.io/en/stable/license.html
