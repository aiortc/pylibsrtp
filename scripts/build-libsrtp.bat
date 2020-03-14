set destdir=%1

for %%d in (libsrtp %destdir%) do (
    if exist %%d (
        rmdir /s /q %%d
    )
)

git clone https://github.com/cisco/libsrtp/
cd libsrtp
git checkout -qf v2.2.0

set MSBUILD_OPTIONS=/p:Configuration=Release
if "%GITHUB_ACTIONS%" == "true" (
    set MSBUILD_OPTIONS=%MSBUILD_OPTIONS% /p:PlatformToolset=v142
)
if "%PYTHON_ARCH%" == "64" (
    set MSBUILD_OPTIONS=%MSBUILD_OPTIONS% /p:Platform=x64
)
msbuild srtp2.vcxproj %MSBUILD_OPTIONS%

mkdir %destdir%
mkdir %destdir%\include
mkdir %destdir%\include\srtp2
mkdir %destdir%\lib

for %%d in (include\srtp.h include\ekt.h crypto\include\cipher.h crypto\include\auth.h crypto\include\crypto_types.h) do (
	 copy %%d %destdir%\include\srtp2
)

if "%PYTHON_ARCH%" == "64" (
    copy x64\Release\srtp2.lib %destdir%\lib\srtp2.lib
) else (
    copy Release\srtp2.lib %destdir%\lib\srtp2.lib
)
