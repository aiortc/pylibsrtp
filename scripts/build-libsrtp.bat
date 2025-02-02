set dest_dir=%1
set build_dir=libsrtp.build
set source_dir=libsrtp.source

python scripts\fetch-vendor.py %dest_dir%

for %%d in (libsrtp) do (
    if exist %%d (
        rmdir /s /q %%d
    )
)

git clone https://github.com/cisco/libsrtp/ %source_dir%
cd %source_dir%
git checkout -qf v2.6.0
cd ..

if "%PYTHON_ARCH%" == "64" (
    set CMAKE_OPTIONS=-A x64
) else (
    set CMAKE_OPTIONS=-A Win32
)
mkdir %build_dir%
cd %build_dir%
cmake ..\%source_dir% -G "Visual Studio 17 2022" %CMAKE_OPTIONS% -DENABLE_OPENSSL=ON
cmake --build . --config Release
cd ..

mkdir %dest_dir%
mkdir %dest_dir%\include
mkdir %dest_dir%\include\srtp2
mkdir %dest_dir%\lib

for %%d in (include\srtp.h crypto\include\auth.h crypto\include\cipher.h crypto\include\crypto_types.h) do (
	 copy %source_dir%\%%d %dest_dir%\include\srtp2
)
copy %build_dir%\Release\srtp2.lib %dest_dir%\lib\srtp2.lib
