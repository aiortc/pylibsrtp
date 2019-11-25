import os.path
import sys

import setuptools

root_dir = os.path.abspath(os.path.dirname(__file__))
readme_file = os.path.join(root_dir, "README.rst")
with open(readme_file, encoding="utf-8") as f:
    long_description = f.read()

if os.environ.get("READTHEDOCS") == "True":
    cffi_modules = []
else:
    cffi_modules = ["src/_cffi_src/build_srtp.py:ffibuilder"]

setuptools.setup(
    name="pylibsrtp",
    version="0.6.4",
    description="Python wrapper around the libsrtp library",
    long_description=long_description,
    url="https://github.com/aiortc/pylibsrtp",
    author="Jeremy Lainé",
    author_email="jeremy.laine@m4x.org",
    license="BSD",
    classifiers=[
        "Development Status :: 5 - Production/Stable",
        "Intended Audience :: Developers",
        "License :: OSI Approved :: BSD License",
        "Operating System :: OS Independent",
        "Programming Language :: Python",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.5",
        "Programming Language :: Python :: 3.6",
        "Programming Language :: Python :: 3.7",
        "Programming Language :: Python :: 3.8",
        "Topic :: Communications :: Telephony",
        "Topic :: Security :: Cryptography",
    ],
    cffi_modules=cffi_modules,
    package_dir={"": "src"},
    package_data={"pylibsrtp": ["py.typed"]},
    packages=["pylibsrtp"],
    install_requires=["cffi>=1.0.0"],
    setup_requires=["cffi>=1.0.0"],
)
