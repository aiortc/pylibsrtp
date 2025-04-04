import setuptools
from wheel.bdist_wheel import bdist_wheel


class bdist_wheel_abi3(bdist_wheel):
    def get_tag(self):
        python, abi, plat = super().get_tag()

        if python.startswith("cp"):
            return "cp39", "abi3", plat

        return python, abi, plat


setuptools.setup(
    cffi_modules=["src/_cffi_src/build_srtp.py:ffibuilder"],
    cmdclass={"bdist_wheel": bdist_wheel_abi3},
)
