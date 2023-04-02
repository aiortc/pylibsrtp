import os

import setuptools

if os.environ.get("READTHEDOCS") == "True":
    cffi_modules = []
else:
    cffi_modules = ["src/_cffi_src/build_srtp.py:ffibuilder"]

setuptools.setup(cffi_modules=cffi_modules)
