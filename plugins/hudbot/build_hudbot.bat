@echo off
REM Build hudbot.dll (ScriptGL for Tribes 1.40.655). x86 REQUIRED (32-bit target).
REM Run from an "x86 Native Tools Command Prompt for VS 2022", or this resolves vcvars.
if "%VSCMD_ARG_TGT_ARCH%"=="x86" goto build
call "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvarsall.bat" x86
:build
cd /d "%~dp0"
cl /nologo /LD /EHsc /O2 /MT hudbot.cpp hudbot_img.cpp /Fe:hudbot.dll
echo.
echo Built hudbot.dll  (deploy next to Tribes.exe, inject with xtloader.exe)
