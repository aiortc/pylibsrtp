import setuptools

setuptools.setup(
    cffi_modules=["src/_cffi_src/build_srtp.py:ffibuilder"],
    options={"bdist_wheel": {"py_limited_api": "cp311"}},
)
