"""
Build the native libraries bundled into pylibsrtp wheels.

OpenSSL and libsrtp are built as static libraries and installed into PREFIX,
which the wheel build then compiles and links against.
"""

import argparse
import hashlib
import os
import pathlib
import platform
import shutil
import subprocess
import sys
import sysconfig
import tarfile

OPENSSL_VERSION = "3.5.9"
OPENSSL_URL = (
    "https://github.com/openssl/openssl/releases/download/"
    f"openssl-{OPENSSL_VERSION}/openssl-{OPENSSL_VERSION}.tar.gz"
)
OPENSSL_SHA256 = "603f5602e2eef00d77fbd429d34dcd5822bb301757a1bc9cdb24c670f1eb859a"

# libcrypto is linked statically, and its default provider pulls in every
# algorithm it registers, so disable everything libsrtp does not use. libsrtp
# needs AES-CTR, AES-GCM and HMAC-SHA1. libssl is not used at all.
OPENSSL_OPTIONS = [
    # Build only the static libraries.
    "no-apps",
    "no-dso",
    "no-module",
    "no-shared",
    "no-tests",
    # Algorithms.
    "no-argon2",
    "no-aria",
    "no-bf",
    "no-blake2",
    "no-camellia",
    "no-cast",
    "no-chacha",
    "no-cmac",
    "no-des",
    "no-dh",
    "no-dsa",
    "no-ec",
    "no-gost",
    "no-idea",
    "no-legacy",
    "no-md4",
    "no-mdc2",
    "no-ml-dsa",
    "no-ml-kem",
    "no-multiblock",
    "no-ocb",
    "no-poly1305",
    "no-rc2",
    "no-rc4",
    "no-rmd160",
    "no-scrypt",
    "no-seed",
    "no-siphash",
    "no-siv",
    "no-slh-dsa",
    "no-sm2",
    "no-sm3",
    "no-sm4",
    "no-whirlpool",
    # PKI and protocols.
    "no-cmp",
    "no-cms",
    "no-comp",
    "no-ct",
    "no-dtls",
    "no-http",
    "no-integrity-only-ciphers",
    "no-nextprotoneg",
    "no-ocsp",
    "no-psk",
    "no-quic",
    "no-rfc3779",
    "no-sock",
    "no-srp",
    "no-srtp",
    "no-ssl",
    "no-ssl-trace",
    "no-tls",
    "no-ts",
    # Miscellaneous.
    "no-async",
    # Do not load the system's openssl.cnf into our embedded copy.
    "no-autoload-config",
    "no-default-thread-pool",
    "no-deprecated",
    "no-engine",
    "no-err",
    "no-filenames",
    "no-thread-pool",
    "no-ui-console",
]

LIBSRTP_VERSION = "2.8.2"
LIBSRTP_URL = (
    f"https://github.com/cisco/libsrtp/archive/refs/tags/v{LIBSRTP_VERSION}.tar.gz"
)
LIBSRTP_SHA256 = "02e8326e12381e27a205ded888a803c6ff55ec7be170cd5e5506251f731fee92"

BUILD_DIR = pathlib.Path("vendor.build").absolute()
TARBALL_DIR = pathlib.Path("vendor.tarballs").absolute()

# Per Python platform: vcvarsall architecture, OpenSSL target, CMake platform.
WINDOWS_TARGETS = {
    "win-amd64": ("x64", "VC-WIN64A", "x64"),
    "win-arm64": ("arm64", "VC-WIN64-ARM", "ARM64"),
    "win32": ("x86", "VC-WIN32", "Win32"),
}


def run(cmd, **kwargs):
    print(f"- Running: {cmd}", flush=True)
    subprocess.run(cmd, check=True, **kwargs)


def sha256sum(path):
    with open(path, "rb") as fp:
        return hashlib.sha256(fp.read()).hexdigest()


def fetch(name, url, sha256):
    """
    Download a source tarball, check its digest and extract it.

    Returns the directory it was extracted to.
    """
    TARBALL_DIR.mkdir(exist_ok=True)
    tarball = TARBALL_DIR / f"{name}.tar.gz"
    if not tarball.exists() or sha256sum(tarball) != sha256:
        run(
            ["curl", "--fail", "--location", "--silent", "--show-error"]
            + ["--output", str(tarball), url]
        )

    digest = sha256sum(tarball)
    if digest != sha256:
        tarball.unlink()
        sys.exit(f"Checksum mismatch for {url}: expected {sha256}, got {digest}")

    with tarfile.open(tarball) as tar:
        if hasattr(tarfile, "data_filter"):
            tar.extractall(BUILD_DIR, filter="data")
        else:
            tar.extractall(BUILD_DIR)
    return BUILD_DIR / name


def install_system_packages():
    if os.environ.get("CIBUILDWHEEL") != "1" or not shutil.which("yum"):
        # Only install packages inside manylinux containers, Alpine has no yum.
        return

    # Required by OpenSSL's Configure.
    packages = ["perl-IPC-Cmd", "perl-Time-Piece"]
    if platform.machine() == "i686":
        # There are no binary wheels for cffi on i686 anymore.
        packages.append("libffi-devel")
    run(["yum", "-y", "install", *packages])


def setup_msvc_environment(vcvars_arch):
    """
    Load the Visual C++ build environment into os.environ.
    """
    vswhere = (
        pathlib.Path(os.environ["ProgramFiles(x86)"])
        / "Microsoft Visual Studio"
        / "Installer"
        / "vswhere.exe"
    )
    install_dir = subprocess.check_output(
        [str(vswhere), "-latest", "-products", "*", "-property", "installationPath"],
        text=True,
    ).strip()
    vcvarsall = (
        pathlib.Path(install_dir) / "VC" / "Auxiliary" / "Build" / "vcvarsall.bat"
    )
    output = subprocess.check_output(
        f'cmd /s /c ""{vcvarsall}" {vcvars_arch} >nul && set"',
        text=True,
        errors="replace",
    )
    for line in output.splitlines():
        key, sep, value = line.partition("=")
        if sep:
            os.environ[key] = value

    # OpenSSL's assembly code needs NASM on x86 and x64. Use ProgramW6432, as
    # ProgramFiles points to "Program Files (x86)" in a 32-bit Python.
    program_files = os.environ.get("ProgramW6432", os.environ["ProgramFiles"])
    nasm_dir = pathlib.Path(program_files) / "NASM"
    if nasm_dir.exists():
        os.environ["PATH"] += os.pathsep + str(nasm_dir)


def find_windows_perl():
    """
    Find a native Windows perl, as OpenSSL's Configure rejects MSYS perl.
    """
    for directory in os.environ["PATH"].split(os.pathsep):
        perl = pathlib.Path(directory) / "perl.exe"
        if perl.exists():
            result = subprocess.run(
                [str(perl), "-e", "print $^O"], capture_output=True, text=True
            )
            if result.stdout == "MSWin32":
                return str(perl)
    sys.exit("Could not find a native Windows perl, such as Strawberry Perl")


def build_openssl(prefix):
    source_dir = fetch(f"openssl-{OPENSSL_VERSION}", OPENSSL_URL, OPENSSL_SHA256)
    options = [*OPENSSL_OPTIONS, f"--prefix={prefix}", "--libdir=lib"]

    # CIBW_ENVIRONMENT sets CFLAGS and LDFLAGS for the wheel build. If they are
    # in the environment, OpenSSL's Configure uses them *instead* of its own
    # flags, which would drop optimizations such as -O3.
    env = os.environ.copy()
    for var in ["CFLAGS", "CPPFLAGS", "LDFLAGS"]:
        env.pop(var, None)

    if platform.system() == "Windows":
        _, target, _ = WINDOWS_TARGETS[sysconfig.get_platform()]
        run(
            [find_windows_perl(), "Configure", target, *options],
            cwd=source_dir,
            env=env,
        )
        run(["nmake"], cwd=source_dir)
        run(["nmake", "install_sw"], cwd=source_dir)
    else:
        configure = ["./config"]
        if platform.system() == "Darwin" and "ARCHFLAGS" in os.environ:
            # cibuildwheel sets ARCHFLAGS to the architecture being built.
            archs = [x for x in os.environ["ARCHFLAGS"].split() if x != "-arch"]
            if len(archs) != 1:
                sys.exit(f"Cannot build OpenSSL for multiple architectures: {archs}")
            configure = ["./Configure", f"darwin64-{archs[0]}-cc"]
        run([*configure, *options], cwd=source_dir, env=env)
        run(["make", f"-j{os.cpu_count()}"], cwd=source_dir)
        run(["make", "install_sw"], cwd=source_dir)


def check_openssl_paths(build_dir, prefix):
    """
    Fail if CMake found an OpenSSL other than the one we built.
    """
    prefix = prefix.resolve()
    with open(build_dir / "CMakeCache.txt") as fp:
        for line in fp:
            entry, sep, value = line.rstrip("\n").partition("=")
            name, _, entry_type = entry.partition(":")
            if (
                sep
                and entry_type in ("FILEPATH", "PATH")
                and name.startswith(("OPENSSL_", "LIB_EAY_", "SSL_EAY_"))
                and value
                and not value.endswith("-NOTFOUND")
                and not pathlib.Path(value).resolve().is_relative_to(prefix)
            ):
                sys.exit(f"CMake found OpenSSL outside {prefix}: {name}={value}")


def build_libsrtp(prefix):
    source_dir = fetch(f"libsrtp-{LIBSRTP_VERSION}", LIBSRTP_URL, LIBSRTP_SHA256)
    build_dir = BUILD_DIR / "libsrtp.build"
    cmake_args = [
        "-DCMAKE_BUILD_TYPE=Release",
        f"-DCMAKE_INSTALL_PREFIX={prefix}",
        "-DCMAKE_POSITION_INDEPENDENT_CODE=ON",
        "-DENABLE_OPENSSL=ON",
        "-DLIBSRTP_TEST_APPS=OFF",
        f"-DOPENSSL_ROOT_DIR={prefix}",
    ]

    if platform.system() == "Windows":
        _, _, cmake_platform = WINDOWS_TARGETS[sysconfig.get_platform()]
        cmake_args += ["-A", cmake_platform]
    else:
        cmake_args.append("-DOPENSSL_USE_STATIC_LIBS=ON")
        if platform.system() == "Darwin" and "ARCHFLAGS" in os.environ:
            archs = [x for x in os.environ["ARCHFLAGS"].split() if x != "-arch"]
            cmake_args.append("-DCMAKE_OSX_ARCHITECTURES=" + ";".join(archs))

    # FindOpenSSL asks pkg-config for the static dependencies of OpenSSL, make
    # sure it reads our openssl.pc and not the system's.
    env = os.environ.copy()
    env["PKG_CONFIG_PATH"] = str(prefix / "lib" / "pkgconfig")
    run(["cmake", "-S", str(source_dir), "-B", str(build_dir), *cmake_args], env=env)
    check_openssl_paths(build_dir, prefix)
    run(["cmake", "--build", str(build_dir), "--config", "Release", "--parallel"])
    run(["cmake", "--install", str(build_dir), "--config", "Release"])


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("prefix", help="directory to install the libraries into")
    args = parser.parse_args()
    prefix = pathlib.Path(args.prefix).absolute()

    for d in [BUILD_DIR, prefix]:
        if d.exists():
            shutil.rmtree(d)
    BUILD_DIR.mkdir()

    install_system_packages()
    if platform.system() == "Windows":
        vcvars_arch, _, _ = WINDOWS_TARGETS[sysconfig.get_platform()]
        setup_msvc_environment(vcvars_arch)

    build_openssl(prefix)
    build_libsrtp(prefix)


if __name__ == "__main__":
    main()
