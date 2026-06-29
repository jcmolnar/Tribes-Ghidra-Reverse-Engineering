@echo off
REM Build getFreeIdNative.dll — a 32-bit Tribes 1.40.655 plugin (no TribesXT framework needed).
REM 32-bit is REQUIRED: the target Tribes.exe is x86, and an injected DLL must match its bitness.
call "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvarsall.bat" x86
if errorlevel 1 ( echo vcvarsall failed & exit /b 1 )
cd /d "%~dp0"
cl /nologo /LD /EHsc /O2 getFreeIdNative.cpp dllmain.cpp /Fe:getFreeIdNative.dll
if errorlevel 1 ( echo BUILD FAILED & exit /b 1 )
echo BUILD OK: getFreeIdNative.dll
