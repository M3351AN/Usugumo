@echo off
setlocal

set INCDIR=..\includes
set DRIVERDIR=..\client\backends\driver\target\release
set NATIVEDIR=..\client\backends\native\target\release
set CXXFLAGS=-static -O2 -std=c++23 -Wall -Wextra

echo [backends] building usugumo_driver and usugumo_native
pushd ..\client\backends\driver
call cargo build --release || (popd & exit /b 1)
popd
pushd ..\client\backends\native
call cargo build --release || (popd & exit /b 1)
popd

if not exist "%DRIVERDIR%\usugumo_driver.lib" (
  echo [error] %DRIVERDIR%\usugumo_driver.lib was not produced & exit /b 1
)
if not exist "%NATIVEDIR%\usugumo_native.lib" (
  echo [error] %NATIVEDIR%\usugumo_native.lib was not produced & exit /b 1
)

echo [examples] linking from example.cc
call g++ %CXXFLAGS% target.cc -o target.exe || exit /b 1
call g++ %CXXFLAGS% -DUSING_USUGUMO -I%INCDIR% example.cc %DRIVERDIR%\usugumo_driver.lib -o driver.exe -lwinmm -lgdi32 -luser32 -lws2_32 -lntdll -luserenv || exit /b 1
call g++ %CXXFLAGS% -I%INCDIR% example.cc %NATIVEDIR%\usugumo_native.lib -o native.exe -lwinmm -lgdi32 -luser32 -lntdll -luserenv || exit /b 1

copy /y %DRIVERDIR%\usugumo_driver.dll . >nul
copy /y %NATIVEDIR%\usugumo_native.dll . >nul
call g++ %CXXFLAGS% -DDYNAMIC -I%INCDIR% example.cc -o dynamic.exe -lgdi32 -luser32 || exit /b 1

echo done