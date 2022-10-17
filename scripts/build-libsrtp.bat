set destdir=%1

for %%d in (libsrtp %destdir%) do (
    if exist %%d (
        rmdir /s /q %%d
    )
)

git clone https://github.com/cisco/libsrtp/
cd libsrtp
git checkout -qf v2.4.2

if "%PYTHON_ARCH%" == "64" (
    set CMAKE_OPTIONS=-A x64
) else (
    set CMAKE_OPTIONS=-A Win32
)
cmake . -G "Visual Studio 17 2022" %CMAKE_OPTIONS%
cmake --build . --config Release

mkdir %destdir%
mkdir %destdir%\include
mkdir %destdir%\include\srtp2
mkdir %destdir%\lib

for %%d in (include\srtp.h crypto\include\auth.h crypto\include\cipher.h crypto\include\crypto_types.h) do (
	 copy %%d %destdir%\include\srtp2
)
copy Release\srtp2.lib %destdir%\lib\srtp2.lib
