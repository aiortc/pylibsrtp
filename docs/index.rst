pylibsrtp
=========

|pypi-v| |pypi-pyversions| |pypi-l| |pypi-wheel| |travis| |coveralls|

.. |pypi-v| image:: https://img.shields.io/pypi/v/pylibsrtp.svg
    :target: https://pypi.python.org/pypi/pylibsrtp

.. |pypi-pyversions| image:: https://img.shields.io/pypi/pyversions/pylibsrtp.svg
    :target: https://pypi.python.org/pypi/pylibsrtp

.. |pypi-l| image:: https://img.shields.io/pypi/l/pylibsrtp.svg
    :target: https://pypi.python.org/pypi/pylibsrtp

.. |pypi-wheel| image:: https://img.shields.io/pypi/wheel/pylibsrtp.svg
    :target: https://pypi.python.org/pypi/pylibsrtp

.. |travis| image:: https://img.shields.io/travis/jlaine/pylibsrtp.svg
    :target: https://travis-ci.org/jlaine/pylibsrtp

.. |coveralls| image:: https://img.shields.io/coveralls/jlaine/pylibsrtp.svg
    :target: https://coveralls.io/github/jlaine/pylibsrtp

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
