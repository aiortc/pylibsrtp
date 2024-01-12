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

``pylibsrtp`` is a Python wrapper around `libsrtp`_, making it possible to
encrypt and decrypt Secure Real-time Transport Protocol (SRTP) packets from
Python code.

SRTP is a profile of the Real-time Transport Protocol (RTP) which provides
confidentiality, message authentication, and replay protection. It is defined
by `RFC 3711`_.

You can install ``pylibsrtp`` with ``pip``:

.. code-block:: console

    $ pip install pylibsrtp

.. _libsrtp: https://github.com/cisco/libsrtp

.. _RFC 3711: https://tools.ietf.org/html/rfc3711

.. toctree::
   :maxdepth: 2

   api
   license
