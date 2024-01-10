import os
import platform
import shutil
import subprocess
import sys

if len(sys.argv) < 2:
    sys.stderr.write("Usage: build-libsrtp.py <prefix>\n")
    sys.exit(1)

dest_dir = sys.argv[1]
build_dir = os.path.abspath("build")

for d in [build_dir]:
    if os.path.exists(d):
        shutil.rmtree(d)


def run(cmd):
    sys.stdout.write(f"- Running: {cmd}\n")
    subprocess.run(cmd, check=True, stderr=sys.stderr.buffer, stdout=sys.stdout.buffer)


cmake_args = [
    "-DCMAKE_INSTALL_PREFIX=" + dest_dir,
    "-DCMAKE_POSITION_INDEPENDENT_CODE=ON",
    "-DCMAKE_VERBOSE_MAKEFILE:BOOL=ON",
    "-DENABLE_OPENSSL=ON",
]
if platform.system() == "Darwin" and "ARCHFLAGS" in os.environ:
    archs = [x for x in os.environ["ARCHFLAGS"].split() if x != "-arch"]
    cmake_args.append("-DCMAKE_OSX_ARCHITECTURES=" + ";".join(archs))

run(["python", "scripts/fetch-vendor.py", dest_dir])

run(["git", "clone", "https://github.com/cisco/libsrtp/", build_dir])
os.chdir(build_dir)
run(["git", "checkout", "-qf", "v2.5.0"])

run(["cmake", "."] + cmake_args)
run(["make"])
run(["make", "install"])
