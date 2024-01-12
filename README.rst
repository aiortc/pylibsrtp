pylibsrtp
=========

.. image:: https://img.shields.io/pypi/l/pylibsrtp.svg
   :target: https://pypi.python.org/pypi/pylibsrtp
   :alt: License

.. image:: https://img.shields.io/pypi/v/pylibsrtp.svg
   :target: https://pypi.python.org/pypi/pylibsrtp
   :alt: Version

.. image:: https://img.shields.io/pypi/pyversions/pylibsrtp.svg
   :target: https://pypi.python.org/pypi/pylibsrtp
   :alt: Python versions

.. image:: https://github.com/aiortc/pylibsrtp/workflows/tests/badge.svg
   :target: https://github.com/aiortc/pylibsrtp/actions
   :alt: Tests

.. image:: https://img.shields.io/codecov/c/github/aiortc/pylibsrtp.svg
   :target: https://codecov.io/gh/aiortc/pylibsrtp
   :alt: Coverage

.. image:: https://readthedocs.org/projects/pylibsrtp/badge/?version=latest
   :target: https://pylibsrtp.readthedocs.io/
   :alt: Documentation

What is ``pylibsrtp``?
----------------------

``pylibsrtp`` is a Python wrapper around `libsrtp`_, making it possible to
encrypt and decrypt Secure Real-time Transport Protocol (SRTP) packets from
Python code.

SRTP is a profile of the Real-time Transport Protocol (RTP) which provides
confidentiality, message authentication, and replay protection. It is defined
by `RFC 3711`_.

You can install ``pylibsrtp`` with ``pip``:

.. code-block:: console

    $ pip install pylibsrtp

To learn more about ``pylibsrtp`` please `read the documentation`_.

.. _libsrtp: https://github.com/cisco/libsrtp

.. _RFC 3711: https://tools.ietf.org/html/rfc3711

.. _read the documentation: https://pylibsrtp.readthedocs.io/en/stable/

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

Building pylibsrtp
------------------

If you wish to build pylibsrtp yourself, you will need libsrtp version 2.0 or better.

On Debian/Ubuntu run:

.. code-block:: console

    $ apt install libsrtp2-dev

On Fedora/CentOS run:

.. code-block:: console

    $ dnf install libsrtp-devel

On OS X run:

.. code-block:: console

    $ brew install srtp

License
-------

``pylibsrtp`` is released under the `BSD license`_.

.. _BSD license: https://pylibsrtp.readthedocs.io/en/stable/license.html
