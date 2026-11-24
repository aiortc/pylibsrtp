Changelog
=========

.. currentmodule:: pylibsrtp

1.1.0
-----

* Add support for cryptex (:rfc:`9335`), which encrypts RTP header extensions
  and CSRCs, using :attr:`Policy.use_cryptex`. It requires `libsrtp`_ 2.8.0 or
  later, which :attr:`Policy.CRYPTEX_SUPPORTED` tells. The binary wheels
  support it.
* Require Python 3.11, and support Python 3.15. Binary wheels target the stable
  ABI of Python 3.11 and newer.
* Return :class:`bytes` from :attr:`Policy.key`, as documented, instead of a
  cffi buffer.
* Build the binary wheels against `libsrtp`_ 2.8.2 (was 2.7.0) and OpenSSL
  3.5.9 (was 3.5.4), both built from source. The OpenSSL features which
  libsrtp does not use are left out, which halves the size of the extension
  module.
* Publish releases using PyPI trusted publishing, with attestations.

1.0.0
-----

* Support Python 3.14, and drop Python 3.9.
* Build binary wheels for Windows on ARM64.
* Stop building binary wheels for free-threaded Python.

.. _libsrtp: https://github.com/cisco/libsrtp
