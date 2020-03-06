pylibsrtp
=========

|pypi-v| |pypi-pyversions| |pypi-l| |pypi-wheel| |tests| |codecov|

.. |pypi-v| image:: https://img.shields.io/pypi/v/pylibsrtp.svg
    :target: https://pypi.python.org/pypi/pylibsrtp

.. |pypi-pyversions| image:: https://img.shields.io/pypi/pyversions/pylibsrtp.svg
    :target: https://pypi.python.org/pypi/pylibsrtp

.. |pypi-l| image:: https://img.shields.io/pypi/l/pylibsrtp.svg
    :target: https://pypi.python.org/pypi/pylibsrtp

.. |pypi-wheel| image:: https://img.shields.io/pypi/wheel/pylibsrtp.svg
    :target: https://pypi.python.org/pypi/pylibsrtp

.. |tests| image:: https://github.com/aiortc/pylibsrtp/workflows/tests/badge.svg
    :target: https://github.com/aiortc/pylibsrtp/actions

.. |codecov| image:: https://img.shields.io/codecov/c/github/aiortc/pylibsrtp.svg
    :target: https://codecov.io/gh/aiortc/pylibsrtp

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
